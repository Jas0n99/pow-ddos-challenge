--[[
    NOTE: This file gets placed in /etc/nginx/snippets

    SHA256 Proof-of-Work Anti-DDoS Challenge
    Cryptographic PoW protection for Nginx/OpenResty
    
    Originally created by: Andrey Prokopenko
    https://github.com/terem42/pow-ddos-challenge

    Custom fork by: Jas0n99
    https://github.com/Jas0n99/pow-ddos-challenge

    Version: 1.1.2
    Last Updated: 2026-01-19

    Security Features:
    - SHA256 proof-of-work with configurable difficulty (1-7)
    - HMAC-signed challenges with embedded difficulty (tamper-proof)
    - Server-side bot fingerprinting from HTTP headers
    - Client-side bot fingerprinting (defense in depth, can increase difficulty)
    - Two-phase challenge: client suspicion score calculated and sent back first before recieving final difficulty and challenge
    - JavaScript timing delay with server-side verification / notification
    - Difficulty 7 "honeypot" - only fake engines trigger this, then get rejected after wasting their time
    - Nonce replay prevention (each solution valid only once)
    - Challenge expiry (5-minute window)
    - Per-IP rate limiting on challenge requests
    - Secure proxy mode configuration (prevents IP spoofing)
    - Suspiciously fast solve detection with rechallenge mechanism
    - ACME challenge bypass for SSL certificate renewal
    
    Browser Requirements:
    - Web Crypto API (blocks Node.js and simple HTTP clients)
    - ES6 modules (blocks legacy scrapers)
    - JavaScript execution required
    
    Debian/Ubuntu Requirements:
    - libnginx-mod-http-lua (For basic lua)
    - lua-nginx-string (For sha256)
    - Shared memory zone (See sample config 'pow_gatekeeper.conf')
    
    Challenge Format:
        signature-timestamp-difficulty
        The signature covers IP + timestamp + difficulty + secret, preventing tampering.
    
    Log Events:
        [PoW] ISSUED            - New challenge generated
        [PoW] VERIFIED          - Valid solution accepted
        [PoW] EXPIRED           - Challenge too old (>5 min)
        [PoW] INVALID_CHALLENGE - Forged/tampered challenge
        [PoW] INVALID           - Wrong PoW solution
        [PoW] NONCE_REPLAY      - Attempted nonce reuse
        [PoW] RATE_LIMITED      - Too many requests from IP
        [PoW] FAKE_ENGINE       - Difficulty 7 trap triggered (bot detected)
        [PoW] RECHALLENGE       - Solution too fast, issuing new challenge
        [PoW] TIMING_VIOLATION  - Client suspicion score submitted too quickly
    
    License: MIT
]]

-- Initialize module
local _M = {}

-- Configuration
local config = require("pow_gatekeeper_config")

-- Shared memory for rate limiting
local rate_limit_dict = ngx.shared[config.shared_zone]

-- These create "shortcuts" to the Nginx internal tables, which is faster for the LuaJIT compiler to process.
local ngx_var = ngx.var
local ngx_header = ngx.header
local ngx_time = ngx.time   -- UNIX timestamp (integer)
local ngx_now = ngx.now     -- UNIX timestamp (float)
local ngx_log = ngx.log
local ngx_say = ngx.say
local ngx_req = ngx.req
local ngx_exit = ngx.exit
local INFO = ngx.INFO
local WARN = ngx.WARN
local ERR = ngx.ERR
local encode_base64 = ngx.encode_base64
local hmac_sha1 = ngx.hmac_sha1
local string_rep = string.rep
local math_floor = math.floor
local math_max = math.max
local math_min = math.min
local tonumber = tonumber

-- Utility: Generate HMAC signature
local function signature(str)
    local hash = encode_base64(hmac_sha1(config.secret, str))
    return hash:gsub("[+]", "-"):gsub("[/]", "_"):gsub("[=]", "")
end

-- Log challenge metrics
local function log_challenge(event, remote_addr, data)
    local msg = string.format("[PoW] %s remote_addr=%s", event, remote_addr)
    for k, v in pairs(data or {}) do
        msg = msg .. string.format(" %s=%s", k, tostring(v))
    end
--    ngx_log(INFO, msg)
    ngx_log(WARN, msg)
end

-- Get client IP (secure proxy handling)
local function get_client_ip()
    if config.proxy_mode == "cloudflare" then
        -- Only trust CF header when behind Cloudflare
        return ngx_var.http_cf_connecting_ip or ngx_var.remote_addr
    elseif config.proxy_mode == "proxy" then
        -- Trust X-Forwarded-For only when behind trusted proxy
        local xff = ngx_var.http_x_forwarded_for
        if xff then
            -- Take first IP (original client) from comma-separated list
            return xff:match("^%s*([^,]+)")
        end
        return ngx_var.remote_addr
    else
        -- Direct mode: only trust actual remote address
        -- Log warning if forwarded headers are present (potential spoofing attempt)
        if ngx_var.http_x_forwarded_for or ngx_var.http_cf_connecting_ip then
            ngx_log(WARN, "[PoW] Forwarded headers present but proxy_mode=direct, ignoring")
        end
        return ngx_var.remote_addr
    end
end

-- Server-side bot detection from HTTP headers
local function detect_server_suspicion(headers)
    local score = 0
    
    -- Missing Accept-Language (all real browsers send this)
    if not headers["accept-language"] then
        score = score + 2
    end
    
    -- Missing Accept-Encoding (all real browsers send this)
    if not headers["accept-encoding"] then
        score = score + 1
    end
    
    -- Missing or suspicious User-Agent
    local ua = headers["user-agent"]
    if type(ua) == "string" then
        if ua == "" then
            score = score + 3
        elseif ua:match("^curl") or ua:match("^wget") or ua:match("^python") 
               or ua:match("^Go%-http") or ua:match("^Java") or ua:match("^Ruby")
               or ua:match("bot") or ua:match("Bot") or ua:match("crawler") 
               or ua:match("spider") or ua:match("scraper") then
            score = score + 2
        end
    else
        -- Not a string (nil, table, etc) - missing UA is very suspicious
        score = score + 2

        -- Missing UA and Referer is even more suspicious
        if not headers["referer"] then
            score = score + 2
        end
    end
    
    -- Missing Sec-Fetch headers (modern browsers always send these)
    if not headers["sec-fetch-mode"] and not headers["sec-fetch-site"] then
        -- Could be older browser, minor penalty
        score = score + 1
    end

    -- Missing Accept header
    if not headers["accept"] then
        score = score + 1
    end
    
    -- Connection header anomalies
    local conn = headers["connection"]
    if type(conn) == "string" and conn:lower() == "close" then
        -- Scrapers often use Connection: close
        score = score + 1
    end

    -- HTTP/1.0 in 2026 (very old or bot)
    if ngx_var.server_protocol == "HTTP/1.0" then
        score = score + 2
    end

    return math_min(score, 6)  -- Cap at 6
end

-- Rate limiting check / increment
local function check_rate_limit(remote_addr)
    local key = "pow:" .. remote_addr
    local count, err = rate_limit_dict:incr(key, 1, 0, 60)  -- 60 second window, does not update TTL on existing key
    
    if not count then
        ngx_log(ERR, "[PoW] Rate limit error: ", err)
        return 0  -- On error, don't block them (fail open)
    end
    
    if count > config.rate_limit then
        -- reset TTL to full window from now
        local ok, err = rate_limit_dict:expire(key, 60)
        if not ok then
            ngx_log(ERR, "[PoW] Failed to reset TTL: ", err)
        end

        log_challenge("RATE_LIMITED", remote_addr, {
            rate_count = count,
            rate_limit = config.rate_limit
        })
        ngx.status = 429
        ngx_header["Retry-After"] = "60"
        ngx_header["Content-Type"] = "text/plain"
        ngx_say("Too many requests. Please wait a minute.")
        return ngx_exit(429)
    end
    
    return count  -- Return count for logging
end

-- Generate challenge string with embedded difficulty (tamper-proof)
local function generate_challenge(remote_addr, host, difficulty, current_time)
    -- Include host and difficulty in signature to prevent tampering and cross site reuse
    local data = remote_addr .. ":" .. host .. ":" .. current_time .. ":" .. difficulty .. ":" .. config.secret
    return signature(data) .. "-" .. current_time .. "-" .. difficulty
end

-- Verify challenge signature and extract difficulty
-- Returns: is_valid, extracted_difficulty, timestamp
local function verify_challenge(challenge, remote_addr, host)
    local sig, tstamp, difficulty = challenge:match("^(.+)-(%d+)-(%d+)$")
    if not sig or not tstamp or not difficulty then
        return false, nil, nil
    end
    
    tstamp = tonumber(tstamp)
    difficulty = tonumber(difficulty)
    
    -- Recreate expected signature
    local data = remote_addr .. ":" .. host .. ":" .. tstamp .. ":" .. difficulty .. ":" .. config.secret
    local expected_sig = signature(data)
    
    if sig ~= expected_sig then
        return false, nil, nil
    end
    
    return true, difficulty, tstamp
end

-- Verify SHA256 solution (check leading zeros on server)
local function verify_solution(challenge, nonce, difficulty)
    -- These locations are possibly different for non-Debian/Ubuntu distros
    local resty_sha256 = require "nginx.sha256"
    local str = require "nginx.string"
    
    local sha = resty_sha256:new()
    sha:update(challenge .. nonce)
    local digest = sha:final()
    local hex = str.to_hex(digest)
    
    local target = string_rep("0", difficulty)
    return hex:sub(1, difficulty) == target, hex
end

-- Check if solve time is suspiciously fast for given difficulty, preventing SHA256 acceleration
local function is_suspiciously_fast(test_difficulty, solve_time_ms)
    if test_difficulty < 6 then
        return false  -- Don't check lower difficulties
    end
    
    -- Base thresholds (very conservative - allows 10-100x faster than expected)
    local thresholds = {
        [5] = 1000,    -- 1 second (expected ~8s at 135k hash/s)
        [6] = 10000,   -- 10 seconds (expected ~2min)
        [7] = 120000   -- 2 minutes (expected ~33min)
    }
    
    local base_threshold = thresholds[test_difficulty]
    if not base_threshold then
        return false
    end
    
    -- Add random jitter: ±20%
    -- This prevents bots from learning exact timing thresholds
    math.randomseed(ngx_time() + test_difficulty)
    local jitter = math.random(80, 120) / 100  -- 0.8 to 1.2
    local threshold = base_threshold * jitter
    
    return solve_time_ms < threshold
end

-- Main logic is a function that either returns to continue the lua_block in nginx or returns an error response
function _M.check(custom_difficulty)
    -- ACME Challenge Bypass - Always allow Let's Encrypt certificate renewal
    if ngx_var.uri:match("^/.well%-known/acme%-challenge/") then
        return
    end

    -- Require the shared dict due to numerous dependencies
    if not rate_limit_dict then
        ngx_log(WARN, "[PoW] CRITICAL: Shared dict 'pow_rate_limit' not configured!")
        return ngx_exit(500)
    end

    -- Start Main Logic
    local pow_difficulty = math_max(1, math_min(6, custom_difficulty or 3))  -- Clamp configured difficulty to safe range (1-6)
    local remote_addr = get_client_ip()
    local current_time = ngx_time()
    local time_bucket = math_floor(tonumber(current_time) / tonumber(config.expire_time))
    local host = ngx_var.host

    -- Cookie check (unique per client, per hostname). Removed cookie_exp, the token is either valid within the time bucket, or it's not.
    local cookie_token = "_pow_" .. signature(remote_addr .. host .. "token"):sub(1, 8)
    local token = ngx_var["cookie_" .. cookie_token] or ""
    local expected_token = signature(remote_addr .. host .. config.secret .. time_bucket)
    if token == expected_token then
        return  -- Valid session, allow request
    end

    -- 3 Phase test below: Greet, Challenge, Verify
    local headers = ngx_req.get_headers()

    -- Phase 3: Check for PoW solution submission
    if headers["x-pow-challenge"] and headers["x-pow-nonce"] then
        -- Phase 3: Receive and verify PoW solution
        local challenge = headers["x-pow-challenge"]
        local nonce = headers["x-pow-nonce"]
        local solve_time = tonumber(headers["x-pow-time"]) or 0  -- Client processing time, just used for logging

        -- Rate limiting check
        local rate_count = check_rate_limit(remote_addr)

        -- Verify challenge signature and extract server-signed difficulty
        local challenge_valid, server_difficulty, tstamp = verify_challenge(challenge, remote_addr, host)
        
        if not challenge_valid then
            log_challenge("INVALID_CHALLENGE", remote_addr, {
                challenge = challenge:sub(1, 20),
                rate_count = rate_count
            })
            ngx.status = 403
            ngx_say("Invalid challenge")
            return ngx_exit(403)
        end
        
        -- Verify timestamp (prevent replay after expiry)
        if current_time - tstamp > 300 then  -- 5 minute expiry
            log_challenge("EXPIRED", remote_addr, {
                age = current_time - tstamp,
                rate_count = rate_count
            })
            ngx.status = 403
            ngx_say("Challenge expired")
            return ngx_exit(403)
        end
        
        -- Check dict to prevent nonce replay (same challenge+nonce can only be used once)
        local nonce_key = "nonce:" .. challenge .. ":" .. nonce
        local exists = rate_limit_dict:get(nonce_key)
        if exists then
            log_challenge("NONCE_REPLAY", remote_addr, {
                nonce = nonce,
                rate_count = rate_count
            })
            ngx.status = 403
            ngx_say("Nonce already used")
            return ngx_exit(403)
        end
        
        -- Verify PoW solution with SERVER-SIGNED difficulty
        local valid, hash = verify_solution(challenge, nonce, server_difficulty)
        
        if valid then
            -- Store nonce to prevent replay attack (TTL = challenge expiry)
            local nonce_key = "nonce:" .. challenge .. ":" .. nonce
            rate_limit_dict:set(nonce_key, true, 300)  -- 5 min TTL

            -- Check for suspiciously fast high-difficulty solves
            if is_suspiciously_fast(server_difficulty, solve_time) then
                log_challenge("RECHALLENGE", remote_addr, {
                    nonce = nonce,
                    hash_prefix = hash:sub(1, 8),
                    solve_time_ms = solve_time,
                    server_difficulty = server_difficulty,
                    rate_count = rate_count
                })

                -- Client will reload and get a new challenge
                -- Note: Nonce is already burned above, so they can't replay this solution
                ngx.status = 403
                ngx_say("Verification required")
                return ngx_exit(403)
            end

            -- Difficulty 7 honeypot trap: reject if CLIENT intentionally pushed to 7
            -- This catches fake engines that failed client-side detection tests
            if server_difficulty >= 7 then
                log_challenge("FAKE_ENGINE", remote_addr, {
                    nonce = nonce,
                    hash_prefix = hash:sub(1, 8),
                    solve_time_ms = solve_time,
                    server_difficulty = server_difficulty,
                    rate_count = rate_count
                })
                ngx.status = 403
                ngx_say("Verification required")
                return ngx_exit(403)
            end

            -- Issue new session token
            local expire_ts = current_time + config.expire_time
            local new_token = signature(remote_addr .. host .. config.secret .. time_bucket)
            
            log_challenge("VERIFIED", remote_addr, {
                nonce = nonce,
                hash_prefix = hash:sub(1, 8),
                solve_time_ms = solve_time,
                server_difficulty = server_difficulty,
                rate_count = rate_count
            })

            ngx_header["Set-Cookie"] = {
                cookie_token .. "=" .. new_token .. "; path=/; Max-Age=" .. config.expire_time .. "; SameSite=Lax; HttpOnly",
            }
            ngx.status = 204
            return ngx_exit(204)
        else
            log_challenge("INVALID", remote_addr, {
                nonce = nonce,
                difficulty = server_difficulty,
                rate_count = rate_count
            })
            ngx.status = 403
            ngx_say("Invalid solution")
            return ngx_exit(403)
        end
    elseif headers["x-pow-client-suspicion"] then
        -- Phase 2: Receive client suspicion score and send back PoW challenge
        local client_suspicion = tonumber(headers["x-pow-client-suspicion"]) or 0
        client_suspicion = math_max(0, math_min(client_suspicion, 14))

        -- Rate limiting check
        local rate_count = check_rate_limit(remote_addr)

        -- Verify client timing (prevent immediate replies)
        local ts_key = "pow_ts:" .. remote_addr
        local ts_start = rate_limit_dict:get(ts_key)

        if ts_start then
            local ts_elapsed = ngx_now() - ts_start
            if ts_elapsed < 1 then
                -- Penalize by adding to their suspicion score
                log_challenge("TIMING_VIOLATION", remote_addr, {
                    ts_elapsed = ts_elapsed,
                    client_suspicion = client_suspicion,
                    rate_count = rate_count
                })
                -- We need to create some unique token to tie the timer to the check before penalizing.
                -- Issue is when browser requests multiple pages at once we don't know which is which.
                -- client_suspicion = client_suspicion + 2
            end
        else
            -- Challenge expired or never started
            log_challenge("EXPIRED", remote_addr, {
                reason = "no start timestamp",
                rate_count = rate_count
            })
            ngx.status = 403
            ngx_say("Challenge expired")
            return ngx_exit(403)
        end

        -- Calculate difficulty based on server-side detection
        local server_suspicion = detect_server_suspicion(headers)
        local effective_difficulty = math_min(pow_difficulty + math_floor((server_suspicion + client_suspicion) / 2), 7)

        -- Generate new challenge with embedded difficulty
        local challenge = generate_challenge(remote_addr, host, effective_difficulty, current_time)
        log_challenge("ISSUED", remote_addr, { 
            base_difficulty = pow_difficulty, 
            server_suspicion = server_suspicion,
            client_suspicion = client_suspicion,
            effective_difficulty = effective_difficulty,
            rate_count = rate_count
        })

        ngx.status = 204
        ngx_header["X-PoW-Challenge"] = challenge
        ngx_exit(204)
    else
        -- Phase 1: Initial request - Greet with challenge page

        -- Generate initial low TTL simple session token for tracking reply timing
        rate_limit_dict:set("pow_ts:" .. remote_addr, ngx_now(), 15)  -- reset TTL each new challenge

        -- NOTE: Cloudflare uses 403 on their anti-bot page as they found 503 could confuse legitimate clients and some browsers. So that's what we use.
        -- Comments in JavaScript will get stripped out before sending to the browser.
        -- Maybe eventually move HTML to separate file and use ngx.exec() since it is all static now?
        ngx.status = 403
        ngx_header["Content-Type"] = "text/html; charset=utf-8"
        ngx_header["Cache-Control"] = "no-store, no-cache, must-revalidate"

        local html = [[<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#0f0f0f">
    <title>Security Check</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body { height: 100%; -webkit-text-size-adjust: 100%; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex; 
            flex-direction: column;
            justify-content: center; 
            align-items: center;
            min-height: 100vh; 
            min-height: 100dvh;
            padding: 1rem;
            padding: max(1rem, env(safe-area-inset-top)) max(1rem, env(safe-area-inset-right)) max(1rem, env(safe-area-inset-bottom)) max(1rem, env(safe-area-inset-left));
            background: linear-gradient(135deg, #0f0f0f 0%, #1a1a2e 50%, #16213e 100%);
            color: #fff;
        }
        .container {
            text-align: center;
            margin: auto;
            padding: clamp(1.5rem, 5vw, 3rem) clamp(1.25rem, 4vw, 2rem);
            background: rgba(255,255,255,0.03);
            border-radius: clamp(16px, 4vw, 24px);
            border: 1px solid rgba(255,255,255,0.1);
            backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
            max-width: 420px; 
            width: 100%;
        }
        .spinner-box { position: relative; width: 100px; height: 100px; margin: 0 auto 1.5rem; }
        .spinner { width: 100%; height: 100%; border: 4px solid rgba(255,129,0,0.2); border-top-color: #ff8100; border-radius: 50%; animation: spin 1s linear infinite; }
        .checkmark { display: none; position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); width: 150px; height: 150px; color: #22c55e; }
        .xmark { display: none; position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); width: 150px; height: 150px; color: #ef4444; }
        .success .spinner { display: none; }
        .success .checkmark { display: block; }
        .failure .spinner { display: none; }
        .failure .xmark { display: block; }
        @keyframes spin { to { transform: rotate(360deg); } }
        h1 { font-size: 1.4rem; font-weight: 600; margin-bottom: 0.75rem; background: linear-gradient(90deg,#ff8100,#ffb366); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        p { color: rgba(255,255,255,0.7); font-size: 0.9rem; line-height: 1.5; }
        .status { margin-top: 1.5rem; padding: 0.75rem 1.25rem; background: rgba(255,129,0,0.1); border-radius: 12px; font-size: 0.85rem; color: #ff8100; }
        .stats { margin-top: 1rem; font-size: 0.75rem; color: rgba(255,255,255,0.4); font-family: monospace; }
        noscript .container { border-color: #ef4444; }
        noscript h1 { background: linear-gradient(90deg,#ef4444,#f87171); -webkit-background-clip: text; background-clip: text; }
    </style>
</head>
<body>
    <noscript>
        <div class="container">
            <h1>JavaScript Required</h1>
            <p>Please enable JavaScript to access this site.</p>
        </div>
    </noscript>
    <div class="container" id="main">
        <div class="spinner-box">
            <div class="spinner"></div>
            <svg class="checkmark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
            <svg class="xmark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="6" y1="6" x2="18" y2="18"></line>
            <line x1="18" y1="6" x2="6" y2="18"></line>
            </svg>
        </div>
        <h1>Verifying you are human...</h1>
        <p>Completing a quick security challenge to protect against bots, scrapers, and automated attacks.</p>
        <div class="status" id="status">Initializing...</div>
        <div class="stats" id="stats"></div>
    </div>
    <script type="module">
        // Challenge will be received from server after suspicion score submission
        const $ = id => document.getElementById(id);
        const status = msg => $('status').textContent = msg;
        const stats = msg => $('stats').textContent = msg;

        // Mouse movement tracking
        let mouseMovements = 0;
        let lastMouseTime = 0;
        let mouseVelocities = [];
        let mouseTeleports = 0;  // Detect instant jumps

        // Track mouse/touch during page load
        document.addEventListener('mousemove', (e) => {
            mouseMovements++;
            const now = performance.now();
            
            // Calculate velocity
            if (lastMouseTime > 0) {
                const timeDelta = now - lastMouseTime;
                if (timeDelta > 0) {
                    const distance = Math.sqrt(e.movementX**2 + e.movementY**2);
                    const velocity = distance / timeDelta;
                    mouseVelocities.push(velocity);
                    
                    // Detect teleports (>500px instant jump is suspicious)
                    if (distance > 500 && timeDelta < 16) {
                        mouseTeleports++;
                        // console.log('Teleport detected!', { distance, timeDelta });
                    }
                }
            }
            lastMouseTime = now;
        });

        // Track touch for mobile devices
        document.addEventListener('touchmove', () => {
            mouseMovements++;  // Count touch as movement
        });

        // === Bot detection flags ===
        // These tests run immediately at module load (before detectClientSuspicion is called)
        // They set flags that detectClientSuspicion() will read to calculate suspicion score

        let failedSemanticTests = false;
        let failedEventLoopTest = false;

        // Semantic correctness tests - detect fake JavaScript engines
        // Real browsers must handle bitwise ops, integer math, and Unicode correctly
        (function semanticChecks(){
            let ok = true;
            
            // Bitwise shift test - engines must handle 32-bit integers correctly
            ok = ok && ((1 << 31) === -2147483648);
            
            // Integer multiplication test
            ok = ok && (Math.imul(0xffffffff, 5) === -5);
            
            // Unicode surrogate pair handling (emoji is 2 length in JS)
            ok = ok && (String.fromCodePoint(0x1F600).length === 2);
            
            failedSemanticTests = !ok;
        })();
        
        // Event loop ordering test
        // Real browsers process Promises (microtasks) before setTimeout (macrotasks)
        await (async function eventLoopTest(){
            let seq = [];
            Promise.resolve().then(() => seq.push(1));
            setTimeout(() => seq.push(2), 0);
            await new Promise(r => setTimeout(r, 10));
            
            // If Promise didn't run first, engine is fake
            failedEventLoopTest = (seq[0] !== 1);
        })();

        // Cross-browser bot fingerprinting (defense in depth)
        // NOTE: This can only INCREASE difficulty, never decrease below server minimum
        function detectClientSuspicion() {
            let score = 0;
            const reasons = [];

            // Engine correctness tests (serious red flags)
            if (failedSemanticTests) { score += 3; reasons.push(`${score} (Semantic tests)`); }
            if (failedEventLoopTest) { score += 3; reasons.push(`${score} (Event loop)`); }

            // Browser inconsistency checks (bots often get these wrong)
            const ua = navigator.userAgent;
            if (ua.includes('Chrome') && !window.chrome) { score += 1; reasons.push(`${score} (Chrome mismatch)`); }  // Claims Chrome (or Edg) but no chrome object
            if (ua.includes('Firefox') && typeof InstallTrigger === 'undefined') { score += 1; reasons.push(`${score} (Firefox mismatch)`); }  // Claims Firefox but missing
            if ( (/\bIntel Mac OS X\b|\bCPU (?:iPhone |iPad )?OS\b/.test(ua)) && ua.includes('Safari') && !/Chrome|Edg|Firefox/.test(ua) && !window.safari ) { score += 1; reasons.push(`${score} (Safari mismatch)`); }  // Claims Safari but missing

            // Bots fake 1-2 cores, humans 4-16+
            if(navigator.hardwareConcurrency <= 1) { score += 1; reasons.push(`${score} (Low cores)`); }

            // Webdriver flag (Selenium, Puppeteer, Playwright)
            if (navigator.webdriver === true) { score += 1; reasons.push(`${score} (Webdriver)`); }
            
            // Missing language preferences
            if (!navigator.languages || navigator.languages.length === 0) { score += 2; reasons.push(`${score} (No languages)`); }

            // Known automation frameworks
            if (window._phantom || window.__nightmare || window.callPhantom) { score += 3; reasons.push(`${score} (Phantom)`); }
            if (window.Cypress || window.__puppeteer__) { score += 3; reasons.push(`${score} (Cypress/Puppeteer)`); }
            if (window.Buffer || window.emit || window.spawn) { score += 2; reasons.push(`${score} (Node.js)`); }  // Node.js indicators
            
            // Webdriver attribute on document
            if (document.documentElement.getAttribute('webdriver') !== null) { score += 3; reasons.push(`${score} (Webdriver attr)`); }
            if (document.documentElement.getAttribute('selenium') !== null) { score += 3; reasons.push(`${score} (Selenium attr)`); }
            
            // Zero screen dimensions (headless default)
            if (screen.width === 0 || screen.height === 0) { score += 1; reasons.push(`${score} (Zero screen)`); }

            // Virtual viewport
            if(window.outerWidth === 0 || screen.availWidth === 0) { score += 1; reasons.push(`${score} (Virtual viewport)`); }

            // Missing standard browser features
            if (typeof window.onmousemove === 'undefined' && typeof window.ontouchstart === 'undefined') { score += 1; reasons.push(`${score} (No mouse/touch)`); }

            // Permission state (headless + missing API)
            // intentionally ignore "denied"
            if (navigator.permissions && navigator.permissions.query) {
                navigator.permissions
                    .query({ name: 'notifications' })
                    .then(result => {
                        if (!result || !result.state) { score += 1; reasons.push(`${score} (Permissions query returned nothing)`); }
                    })
                    .catch(() => {
                        reasons.push(`${score} (Permissions query failed)`);  // Firefox/other browsers
                    });
            } else {
                score += 1;
                reasons.push(`${score} (Permissions API missing)`);
            }
            
            // Media devices (often missing in headless)
            if (!navigator.mediaDevices) { score += 1; reasons.push(`${score} (No media)`); }

            // Notification API (often missing in headless)
            if (!window.Notification) { score += 1; reasons.push(`${score} (No notifications)`); }

            // Broken Error.stack format (bots often have wrong stack traces)
            try {
                null.f();
            } catch(e) {
                if (!e.stack || e.stack.split('\n').length < 2) { score += 1; reasons.push(`${score} (Bad stack)`); }
            }

            // Canvas fingerprinting anomaly
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('🤖', 0, 0);
            const sum = Array.from(ctx.getImageData(0,0,10,10).data).reduce((a,b)=>a+b,0);
            // const pixels = ctx.getImageData(0, 0, 10, 10).data;
            // const sum = Array.from(pixels).reduce((a, b) => a + b, 0);
            if (sum === 0 || sum === 2550) { score += 1; reasons.push(`${score} (Canvas anomaly ${sum})`); }  // Suspiciously uniform

            // WebGL vendor detection (VMs have telltale signatures)
            const gl = document.createElement('canvas').getContext('webgl');
            if (gl) {
                const vendor = gl.getParameter(gl.VENDOR);
                const renderer = gl.getParameter(gl.RENDERER);
                // Headless Chrome often uses SwiftShader
                if (renderer && renderer.includes('SwiftShader')) { score += 4; reasons.push(`${score} (SwiftShader)`); }
                // VMware/VirtualBox fingerprints
                if (vendor && (vendor.includes('VMware') || renderer.includes('llvmpipe'))) { score += 4; reasons.push(`${score} (VM detected)`); }
            }

            // Mouse/touch interaction checks (only penalize suspicious patterns, not absence)
            // console.log('Mouse tracking:', { movements: mouseMovements, velocities: mouseVelocities.length, teleports: mouseTeleports });
            // Check for robotic/scripted mouse patterns (only if there WAS movement)
            if (mouseVelocities.length > 10) {
                const avgVelocity = mouseVelocities.reduce((a,b) => a+b, 0) / mouseVelocities.length;
                const variance = mouseVelocities.reduce((sum, v) => sum + Math.pow(v - avgVelocity, 2), 0) / mouseVelocities.length;
                // console.log('Mouse variance analysis:', { avgVelocity: avgVelocity.toFixed(4), variance: variance.toFixed(6), threshold: 0.0001 });
                // Real humans have high variance (natural jitter), bots are too smooth
                if (variance < 0.0001) { score += 1; reasons.push(`${score} (Robotic mouse, variance: ${variance.toFixed(4)})`); }
            }
            
            // Teleporting mouse (instant jumps - clear bot indicator)
            if (mouseTeleports > 2) { score += 1; reasons.push(`${score} (Mouse teleports: ${mouseTeleports})`); }

            // Debug output
            // console.log('Detection reasons:', reasons);
            // document.body.innerHTML += `<pre>${JSON.stringify(reasons)}</pre>`;

            // Don't cap - let it go high for extreme bots
            return score;
        }

        // Parse server-signed minimum difficulty from challenge
        // Format: signature-timestamp-difficulty
        function parseServerDifficulty(challenge) {
            const parts = challenge.split('-');
            const diff = parseInt(parts[parts.length - 1], 10);
            return isNaN(diff) ? 3 : Math.max(1, Math.min(7, diff));
        }

        async function sha256(message) {
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }

        // Final difficulty will be determined by server after client suspicion score submission        
        async function solve(challenge) {
            const DIFFICULTY = parseServerDifficulty(challenge);
            const TARGET = '0'.repeat(DIFFICULTY);
            status(`Computing proof-of-work (Difficulty: ${DIFFICULTY})...`);

            const startTime = performance.now();
            let nonce = 0;
            let hash = '';
            const CHUNK_SIZE = 5000;

            while (true) {
                for (let i = 0; i < CHUNK_SIZE; i++) {
                    hash = await sha256(challenge + nonce);
                    if (hash.startsWith(TARGET)) {
                        const elapsed = performance.now() - startTime;
                        stats(`${nonce.toLocaleString()} hashes in ${(elapsed/1000).toFixed(2)}s`);
                        return { nonce: nonce.toString(), elapsed: Math.round(elapsed) };
                    }
                    nonce++;
                }
                stats(`Checked ${nonce.toLocaleString()} hashes...`);
                await new Promise(r => setTimeout(r, 0));
            }
        }

        // Send the PoW solution back to the server for verification        
        async function submit(challenge, nonce, elapsed) {
            status('Verifying...');
            const res = await fetch(location.href, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'X-PoW-Challenge': challenge,
                    'X-PoW-Nonce': nonce,
                    'X-PoW-Time': elapsed.toString()
                }
            });
            
            if (res.status === 204 || res.ok) {
                status('Verification successful! Redirecting...');
                stats('Waiting for server to respond...');
                document.querySelector('.spinner-box').classList.add('success');
                setTimeout(() => location.reload(), 1000);
            } else if (res.status === 429) {
                status('Too many attempts! Please wait...');
                document.querySelector('.spinner-box').classList.add('failure');
                setTimeout(() => location.reload(), 60000);
            } else {
                status('Verification failed! Retrying...');
                document.querySelector('.spinner-box').classList.add('failure');
                setTimeout(() => location.reload(), 3000);
            }
        }

        async function submitSuspicionScore() {
            // Create minimum 1 second combined delay before submitting score.
            // Otherwise adjust time in Phase 2 to prevent a TIMING_VIOLATION.

            status('Loading tests and analyzing browser...');
            await new Promise(resolve => setTimeout(resolve, 1000));

            status('Just hang on. We are almost there...');
            await new Promise(resolve => setTimeout(resolve, 500));

            status('Fetching challenge...');
            await new Promise(resolve => setTimeout(resolve, 200));

            // Run client tests and get suspicion score
            const clientSuspicion = detectClientSuspicion();

            const res = await fetch(location.href, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'X-PoW-Client-Suspicion': clientSuspicion.toString()
                }
            });
            if (!res.ok) {
                if (res.status === 429) {
                    status('Too many attempts! Please wait...');
                    document.querySelector('.spinner-box').classList.add('failure');
                    const retryAfter = res.headers.get('Retry-After') || '60';
                    stats(`Page will auto-refresh after ${retryAfter} seconds.`);
                    setTimeout(() => location.reload(), parseInt(retryAfter) * 1000);
                    // Prevent further execution
                    await new Promise(() => {});
                }
                throw new Error('Suspicion score rejected!');
            }

            const challenge = res.headers.get('X-PoW-Challenge');
            if (!challenge) { throw new Error('No challenge received from server'); }
            return challenge;
        }

        async function main() {
            try {
                if (!crypto.subtle) throw new Error('Web Crypto not available');
                // Phase 2: Submit suspicion score, receive challenge + difficulty
                const challenge = await submitSuspicionScore();
                // Phase 3: Solve & submit PoW solution with server-assigned challenge and difficulty
                const { nonce, elapsed } = await solve(challenge);
                await submit(challenge, nonce, elapsed);
            } catch (e) {
                status('Error: ' + e.message);
                console.error(e);
            }
        }

        main();
    </script>
</body>
</html>]]

        -- Some very basic minification stripping comments, newlines, and excessive spaces
        html = html:gsub("([^:])//[^\n]*", "%1")
        html = html:gsub("\n+", " ")
        html = html:gsub("  +", " ")
        html = html:gsub(">%s+<", "><")

        ngx_say(html)
        ngx_exit(403)
    end -- Client suspicion test, PoW challenge, and solution submission
end  -- _M.check

return _M
