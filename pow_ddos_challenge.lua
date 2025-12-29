--[[
    SHA256 Proof-of-Work Anti-DDoS Challenge
    Cryptographic PoW protection for Nginx/OpenResty
    
    Security Features:
    - SHA256 proof-of-work with configurable difficulty (1-6)
    - HMAC-signed challenges with embedded difficulty (tamper-proof)
    - Server-side bot fingerprinting from HTTP headers
    - Client-side bot fingerprinting (defense in depth, can only increase difficulty)
    - Nonce replay prevention (each solution valid only once)
    - Challenge expiry (5-minute window)
    - Per-IP rate limiting on challenge requests
    - Secure proxy mode configuration (prevents IP spoofing)
    
    Browser Requirements:
    - Web Crypto API (blocks Node.js and simple HTTP clients)
    - ES6 modules (blocks legacy scrapers)
    - JavaScript execution required
    
    Requirements:
    - OpenResty with lua-resty-string
    - Shared memory zone in nginx.conf:
        lua_shared_dict pow_rate_limit 10m;
    
    Usage in nginx.conf:
        lua_shared_dict pow_rate_limit 10m;
        access_by_lua_file /path/to/pow_ddos_challenge.lua;
    
    Environment variables:
        POW_SECRET      - HMAC secret key (REQUIRED for production)
        POW_DIFFICULTY  - Base difficulty, 1-6 (default: 3, each level ~16x harder)
        POW_EXPIRE      - Session duration in seconds (default: 86400 = 1 day)
        POW_RATE_LIMIT  - Max challenge requests per IP per minute (default: 10)
        POW_PROXY_MODE  - IP detection: "direct", "cloudflare", or "proxy" (default: direct)
    
    Challenge Format:
        signature-timestamp-difficulty
        The signature covers IP + timestamp + difficulty + secret, preventing tampering.
    
    Log Events:
        [PoW] ISSUED           - New challenge generated
        [PoW] VERIFIED         - Valid solution accepted
        [PoW] EXPIRED          - Challenge too old (>5 min)
        [PoW] INVALID_CHALLENGE - Forged/tampered challenge
        [PoW] INVALID          - Wrong PoW solution
        [PoW] NONCE_REPLAY     - Attempted nonce reuse
        [PoW] RATE_LIMITED     - Too many requests from IP
    
    License: MIT
]]

-- Configuration
local config = {
    secret = os.getenv("POW_SECRET") or "put-here-your-own-large-secret",
    difficulty = tonumber(os.getenv("POW_DIFFICULTY")) or 3,
    expire_time = tonumber(os.getenv("POW_EXPIRE")) or 86400,
    rate_limit = tonumber(os.getenv("POW_RATE_LIMIT")) or 10,
    -- Proxy mode: "cloudflare", "proxy", or "direct"
    -- Only trust forwarded headers when explicitly configured
    proxy_mode = os.getenv("POW_PROXY_MODE") or "direct",
}

-- Clamp difficulty to safe range (1-6)
config.difficulty = math.max(1, math.min(6, config.difficulty))

-- Shared memory for rate limiting
local rate_limit_dict = ngx.shared.pow_rate_limit

-- Utility: Generate HMAC signature
local function signature(str)
    local hash = ngx.encode_base64(ngx.hmac_sha1(config.secret, str))
    return hash:gsub("[+]", "-"):gsub("[/]", "_"):gsub("[=]", "")
end

-- Get client IP (secure proxy handling)
local function get_client_ip()
    if config.proxy_mode == "cloudflare" then
        -- Only trust CF header when behind Cloudflare
        return ngx.var.http_cf_connecting_ip or ngx.var.remote_addr
    elseif config.proxy_mode == "proxy" then
        -- Trust X-Forwarded-For only when behind trusted proxy
        local xff = ngx.var.http_x_forwarded_for
        if xff then
            -- Take first IP (original client) from comma-separated list
            return xff:match("^%s*([^,]+)")
        end
        return ngx.var.remote_addr
    else
        -- Direct mode: only trust actual remote address
        -- Log warning if forwarded headers are present (potential spoofing attempt)
        if ngx.var.http_x_forwarded_for or ngx.var.http_cf_connecting_ip then
            ngx.log(ngx.WARN, "[PoW] Forwarded headers present but proxy_mode=direct, ignoring")
        end
        return ngx.var.remote_addr
    end
end

-- Server-side bot detection from HTTP headers
local function detect_server_suspicion()
    local headers = ngx.req.get_headers()
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
    local ua = headers["user-agent"] or ""
    if ua == "" then
        score = score + 3
    elseif ua:match("^curl") or ua:match("^wget") or ua:match("^python") 
           or ua:match("^Go%-http") or ua:match("^Java") or ua:match("^Ruby")
           or ua:match("bot") or ua:match("Bot") or ua:match("crawler") 
           or ua:match("spider") or ua:match("scraper") then
        score = score + 2
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
    local conn = headers["connection"] or ""
    if conn:lower() == "close" then
        -- Scrapers often use Connection: close
        score = score + 1
    end
    
    return math.min(score, 6)  -- Cap at 6
end

-- Rate limiting check
local function check_rate_limit(ip)
    if not rate_limit_dict then
        ngx.log(ngx.WARN, "[PoW] Shared dict 'pow_rate_limit' not configured - rate limiting disabled")
        return true, 0
    end
    
    local key = "pow:" .. ip
    local count, err = rate_limit_dict:incr(key, 1, 0, 60)  -- 60 second window
    
    if not count then
        ngx.log(ngx.ERR, "[PoW] Rate limit error: ", err)
        return true, 0
    end
    
    return count <= config.rate_limit, count
end

-- Generate challenge string with embedded difficulty (tamper-proof)
local function generate_challenge(ip, difficulty)
    local timestamp = ngx.time()
    -- Include difficulty in signature to prevent tampering
    local data = ip .. ":" .. timestamp .. ":" .. difficulty .. ":" .. config.secret
    return signature(data) .. "-" .. timestamp .. "-" .. difficulty
end

-- Verify challenge signature and extract difficulty
-- Returns: is_valid, extracted_difficulty, timestamp
local function verify_challenge(challenge, ip)
    local sig, ts, diff = challenge:match("^(.+)-(%d+)-(%d+)$")
    if not sig or not ts or not diff then
        return false, nil, nil
    end
    
    ts = tonumber(ts)
    diff = tonumber(diff)
    
    -- Recreate expected signature
    local data = ip .. ":" .. ts .. ":" .. diff .. ":" .. config.secret
    local expected_sig = signature(data)
    
    if sig ~= expected_sig then
        return false, nil, nil
    end
    
    return true, diff, ts
end

-- Verify SHA256 solution (check leading zeros on server)
local function verify_solution(challenge, nonce, difficulty)
    local resty_sha256 = require "resty.sha256"
    local str = require "resty.string"
    
    local sha = resty_sha256:new()
    sha:update(challenge .. nonce)
    local digest = sha:final()
    local hex = str.to_hex(digest)
    
    local target = string.rep("0", difficulty)
    return hex:sub(1, difficulty) == target, hex
end

-- Log challenge metrics
local function log_challenge(event, ip, data)
    local msg = string.format("[PoW] %s ip=%s", event, ip)
    for k, v in pairs(data or {}) do
        msg = msg .. string.format(" %s=%s", k, tostring(v))
    end
    ngx.log(ngx.INFO, msg)
end

-- Main logic
local remote_addr = get_client_ip()
local currenttime = ngx.time()

-- Cookie names (unique per client)
local cookie_token = "_pow_" .. signature(remote_addr .. "token"):sub(1, 8)
local cookie_exp = "_pow_" .. signature(remote_addr .. "exp"):sub(1, 8)

-- Check existing valid session
local token = ngx.var["cookie_" .. cookie_token] or ""
local exp = tonumber(ngx.var["cookie_" .. cookie_exp] or "0")
local expected_token = signature(remote_addr .. config.secret .. math.floor(currenttime / config.expire_time))

if token == expected_token and exp > currenttime then
    return ngx.exit(ngx.OK)  -- Valid session
end

-- Rate limiting check
local rate_ok, rate_count = check_rate_limit(remote_addr)
if not rate_ok then
    log_challenge("RATE_LIMITED", remote_addr, { count = rate_count, limit = config.rate_limit })
    ngx.status = 429
    ngx.header["Retry-After"] = "60"
    ngx.header["Content-Type"] = "text/plain"
    ngx.say("Too many requests. Please wait a minute.")
    return ngx.exit(429)
end

-- Handle PoW solution submission
local headers = ngx.req.get_headers()
if headers["x-pow-challenge"] and headers["x-pow-nonce"] then
    local challenge = headers["x-pow-challenge"]
    local nonce = headers["x-pow-nonce"]
    local solve_time = tonumber(headers["x-pow-time"]) or 0
    
    -- Verify challenge signature and extract server-signed difficulty
    local challenge_valid, server_difficulty, ts = verify_challenge(challenge, remote_addr)
    
    if not challenge_valid then
        log_challenge("INVALID_CHALLENGE", remote_addr, { challenge = challenge:sub(1, 20) })
        ngx.status = 403
        ngx.say("Invalid challenge")
        return ngx.exit(403)
    end
    
    -- Verify timestamp (prevent replay after expiry)
    if currenttime - ts > 300 then  -- 5 minute expiry
        log_challenge("EXPIRED", remote_addr, { age = currenttime - ts })
        ngx.status = 403
        ngx.say("Challenge expired")
        return ngx.exit(403)
    end
    
    -- Prevent nonce replay (same challenge+nonce can only be used once)
    if rate_limit_dict then
        local nonce_key = "nonce:" .. challenge .. ":" .. nonce
        local exists = rate_limit_dict:get(nonce_key)
        if exists then
            log_challenge("NONCE_REPLAY", remote_addr, { nonce = nonce })
            ngx.status = 403
            ngx.say("Nonce already used")
            return ngx.exit(403)
        end
    end
    
    -- Verify PoW solution with SERVER-SIGNED difficulty (not client-supplied!)
    local valid, hash = verify_solution(challenge, nonce, server_difficulty)
    
    if valid then
        -- Store nonce to prevent replay (TTL = challenge expiry)
        if rate_limit_dict then
            local nonce_key = "nonce:" .. challenge .. ":" .. nonce
            rate_limit_dict:set(nonce_key, true, 300)  -- 5 min TTL
        end
        
        local expire_ts = currenttime + config.expire_time
        local new_token = signature(remote_addr .. config.secret .. math.floor(currenttime / config.expire_time))
        
        log_challenge("VERIFIED", remote_addr, {
            nonce = nonce,
            difficulty = server_difficulty,
            solve_time_ms = solve_time,
            hash_prefix = hash:sub(1, 8)
        })
        
        ngx.header["Set-Cookie"] = {
            cookie_token .. "=" .. new_token .. "; path=/; Max-Age=" .. config.expire_time .. "; SameSite=Lax; HttpOnly",
            cookie_exp .. "=" .. expire_ts .. "; path=/; Max-Age=" .. config.expire_time .. "; SameSite=Lax"
        }
        ngx.status = 204
        return ngx.exit(204)
    else
        log_challenge("INVALID", remote_addr, { nonce = nonce, difficulty = server_difficulty })
        ngx.status = 403
        ngx.say("Invalid solution")
        return ngx.exit(403)
    end
end

-- Calculate difficulty based on server-side detection
local server_suspicion = detect_server_suspicion()
local effective_difficulty = math.min(config.difficulty + math.floor(server_suspicion / 2), 6)

-- Generate new challenge with embedded difficulty
local challenge = generate_challenge(remote_addr, effective_difficulty)
log_challenge("ISSUED", remote_addr, { 
    base_difficulty = config.difficulty, 
    server_suspicion = server_suspicion,
    effective_difficulty = effective_difficulty,
    rate_count = rate_count 
})

-- Serve challenge page
ngx.status = 503
ngx.header["Content-Type"] = "text/html; charset=utf-8"
ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate"

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
        .logo { width: 60px; height: auto; margin-bottom: 1.5rem; filter: drop-shadow(0 4px 6px rgba(255,129,0,0.3)); }
        .spinner-box { position: relative; width: 60px; height: 60px; margin: 0 auto 1.5rem; }
        .spinner { width: 100%; height: 100%; border: 3px solid rgba(255,129,0,0.2); border-top-color: #ff8100; border-radius: 50%; animation: spin 1s linear infinite; }
        .checkmark { display: none; position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); width: 30px; height: 30px; color: #22c55e; }
        .success .spinner { display: none; }
        .success .checkmark { display: block; }
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
        <svg class="logo" viewBox="0 0 75.946663 87.348663" xmlns="http://www.w3.org/2000/svg">
            <g transform="matrix(1.3333333,0,0,-1.3333333,-156.02933,329.57066)">
                <g style="fill:#ff8100" transform="translate(124.022,201.5)">
                    <path d="M 0,0 H 42.96 V 21.321 L 21.48,37.01 0,21.321 Z M 49.96,-7 H -7 V 24.877 L 21.48,45.678 49.96,24.877 Z"/>
                </g>
                <g style="fill:#ff8100" transform="translate(159.3359,181.6665)">
                    <path d="M 0,0 H -7 V 29.167 H -20.5 V 0 h -7 V 36.167 H 0 Z"/>
                </g>
            </g>
        </svg>
        <div class="spinner-box">
            <div class="spinner"></div>
            <svg class="checkmark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
        </div>
        <h1>Verifying your connection</h1>
        <p>Completing a quick security challenge to protect against automated attacks.</p>
        <div class="status" id="status">Initializing...</div>
        <div class="stats" id="stats"></div>
    </div>

    <script type="module">
        const CHALLENGE = ']] .. challenge .. [[';
        
        const $ = id => document.getElementById(id);
        const status = msg => $('status').textContent = msg;
        const stats = msg => $('stats').textContent = msg;
        
        // Parse server-signed minimum difficulty from challenge
        // Format: signature-timestamp-difficulty
        function parseServerDifficulty(challenge) {
            const parts = challenge.split('-');
            const diff = parseInt(parts[parts.length - 1], 10);
            return isNaN(diff) ? 3 : Math.max(1, Math.min(6, diff));
        }
        
        const SERVER_MIN_DIFFICULTY = parseServerDifficulty(CHALLENGE);
        
        // Cross-browser bot fingerprinting (defense in depth)
        // NOTE: This can only INCREASE difficulty, never decrease below server minimum
        function detectClientSuspicion() {
            let score = 0;
            
            // Webdriver flag (Selenium, Puppeteer, Playwright)
            if (navigator.webdriver === true) score += 3;
            
            // Missing language preferences
            if (!navigator.languages || navigator.languages.length === 0) score += 2;
            
            // Known automation frameworks
            if (window._phantom || window.__nightmare || window.callPhantom) score += 3;
            if (window.Cypress || window.__puppeteer__) score += 3;
            if (window.Buffer || window.emit || window.spawn) score += 2;  // Node.js indicators
            
            // Webdriver attribute on document
            if (document.documentElement.getAttribute('webdriver') !== null) score += 3;
            if (document.documentElement.getAttribute('selenium') !== null) score += 3;
            
            // Zero screen dimensions (headless default)
            if (screen.width === 0 || screen.height === 0) score += 2;
            
            // Missing standard browser features
            if (typeof window.onmousemove === 'undefined' && typeof window.ontouchstart === 'undefined') score += 1;
            
            // Permissions API check (often missing in headless)
            if (!navigator.permissions) score += 1;
            
            // Media devices (often missing in headless)
            if (!navigator.mediaDevices) score += 1;
            
            return Math.min(score, 6);  // Cap at 6
        }
        
        // Calculate final difficulty: server minimum + optional client increase
        // Client can only INCREASE difficulty (defense in depth), never decrease
        const clientSuspicion = detectClientSuspicion();
        const clientBonus = Math.floor(clientSuspicion / 2);
        const DIFFICULTY = Math.min(SERVER_MIN_DIFFICULTY + clientBonus, 6);
        const TARGET = '0'.repeat(DIFFICULTY);
        
        async function sha256(message) {
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }
        
        async function solve() {
            status(`Computing proof-of-work (difficulty: ${DIFFICULTY})...`);
            const startTime = performance.now();
            let nonce = 0;
            let hash = '';
            
            const CHUNK_SIZE = 5000;
            
            while (true) {
                for (let i = 0; i < CHUNK_SIZE; i++) {
                    hash = await sha256(CHALLENGE + nonce);
                    if (hash.startsWith(TARGET)) {
                        const elapsed = performance.now() - startTime;
                        stats(`${nonce.toLocaleString()} hashes in ${(elapsed/1000).toFixed(2)}s`);
                        return { nonce: nonce.toString(), hash, elapsed: Math.round(elapsed) };
                    }
                    nonce++;
                }
                stats(`Checked ${nonce.toLocaleString()} hashes...`);
                await new Promise(r => setTimeout(r, 0));
            }
        }
        
        async function submit(nonce, elapsed) {
            status('Verifying...');
            const res = await fetch(location.href, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'X-PoW-Challenge': CHALLENGE,
                    'X-PoW-Nonce': nonce,
                    'X-PoW-Time': elapsed.toString()
                    // Note: Difficulty is embedded in signed challenge, not sent as header
                    // Server extracts and verifies difficulty from challenge signature
                }
            });
            
            if (res.status === 204 || res.ok) {
                status('Verified! Redirecting...');
                document.querySelector('.spinner-box').classList.add('success');
                setTimeout(() => location.reload(), 600);
            } else if (res.status === 429) {
                status('Too many attempts. Please wait...');
                setTimeout(() => location.reload(), 60000);
            } else {
                status('Verification failed. Retrying...');
                setTimeout(() => location.reload(), 2000);
            }
        }
        
        async function main() {
            try {
                if (!crypto.subtle) throw new Error('Web Crypto not available');
                const { nonce, elapsed } = await solve();
                await submit(nonce, elapsed);
            } catch (e) {
                status('Error: ' + e.message);
                console.error(e);
            }
        }
        
        main();
    </script>
</body>
</html>]]

ngx.say(html)
ngx.exit(503)
