# SHA256 Proof-of-Work Anti-DDoS Challenge

A cryptographic proof-of-work challenge system for Nginx/OpenResty that provides robust protection against DDoS attacks, automated scrapers, and AI-powered bots.

This lua script is much more lightweight than others, and thus much easier to implement with minimal overhead.

## Differences from upstream version

This version is tailored to Ubuntu (24.04 LTS) namings and locations, and re-worked as a module for additional lua code capability by utilizing an `access_by_lua_block`.

Environment variable code has been removed in favor of a separate config file, and defining difficulty in the Nginx lua block.

Instead of complicating the PoW lua script with unnecessary bloat that might not be applicable or compatible with your site, altering the base difficulty or bypassing certain URLs or User-Agents or whatever you can think of can be done much easier and effectively with Nginx maps and creating basic logic in the `access_by_lua_block`.

If you wanted to be truely nefarious for a known bot, you could force the highest level test and if they complete the PoW you can still deliver a 403 afterwards easily within the `access_by_lua_block`.

- Optimized with Nginx internal table shortcuts for better performance
- Additional server side and client side (JavaScript) suspicion tests
- Difficulty level 7 "honeypot" - only fake engines trigger this, then get rejected after wasting their time
- Suspiciously fast solve detection with random jitter and rechallenge (helps prevent against SHA256 acceleration methods)
- Some very basic minification stripping comments, newlines, and excessive spaces from output

### Requirements
- libnginx-mod-http-lua
- lua-nginx-string

### Sample Nginx Configuration

```nginx
http {
    server {
        # Apply PoW challenge to all requests (or specific locations)
        access_by_lua_block {
            -- Local shortcuts (micro-optimizations)
            local ngx_var = ngx.var
            local ngx_exit = ngx.exit
            local OK = ngx.OK

            -- Define difficulty for additional customizations before running PoW test.
            local difficulty = 3

            -- Example: Skip PoW for whitelisted URIs based on a Nginx map
            if ngx_var.bypass_uri == "1" then
                return ngx_exit(OK)
            end

            -- Example: You could boost based on a Nginx map
            if ngx_var.bad_bot == "1" then
                difficulty = difficulty + 1
            end

            local pow = require("pow_ddos_challenge")
            pow.check(difficulty)

            -- If check() hits a valid session, it simply returns and we reach here.
            -- If it hits an error or needs to show a challenge, it exits the request entirely.

            -- Additional lua code could go here

            -- Example: The bad bot wasted a lot of time completing the PoW, so now we block them
            if ngx_var.bad_bot == "1" then
                return ngx_exit(403)
            end
        }
        
        # Your normal configuration...
        location / {
            # Whatever
        }

    }
}
```

# (Stock Readme Below)

## How It Works

```
+-----------------------------------------------------------------------+
|  Client Request                                                       |
|       |                                                               |
|       v                                                               |
|  +---------------------------------------------------------------+    |
|  | 1. Server analyzes HTTP headers (bot fingerprinting)          |    |
|  | 2. Calculates difficulty based on suspicion score             |    |
|  | 3. Generates HMAC-signed challenge with embedded difficulty   |    |
|  +---------------------------------------------------------------+    |
|       |                                                               |
|       v                                                               |
|  +---------------------------------------------------------------+    |
|  | 4. Client receives challenge page (HTML + JavaScript)         |    |
|  | 5. Client-side fingerprinting (can only INCREASE difficulty)  |    |
|  | 6. Browser computes SHA256 PoW solution                       |    |
|  +---------------------------------------------------------------+    |
|       |                                                               |
|       v                                                               |
|  +---------------------------------------------------------------+    |
|  | 7. Server verifies challenge signature (tamper-proof)         |    |
|  | 8. Server verifies PoW solution at signed difficulty          |    |
|  | 9. Server checks nonce hasn't been used (replay prevention)   |    |
|  | 10. Issues session cookie (valid for configurable duration)   |    |
|  +---------------------------------------------------------------+    |
+-----------------------------------------------------------------------+
```

## Features

### Core Protection
- **SHA256 Proof-of-Work** - Forces computational cost per request
- **Configurable difficulty (1-6)** - Each level ~16x harder
- **Signed challenges** - HMAC prevents tampering with difficulty
- **Nonce replay prevention** - Each solution valid only once
- **Challenge expiry** - 5-minute window prevents stockpiling

### Bot Detection (Hybrid Approach)
- **Server-side fingerprinting** - Analyzes HTTP headers before any JS runs
- **Client-side fingerprinting** - Defense-in-depth for lazy automation
- **Adaptive difficulty** - Suspicious requests get harder challenges

### Rate Limiting
- **Per-IP rate limiting** - Configurable challenges per minute
- **Shared memory storage** - Efficient across worker processes

### Browser Requirements
- **Web Crypto API** - Blocks Node.js and simple HTTP clients
- **ES6 Modules** - Blocks legacy scrapers
- **JavaScript required** - Blocks curl/wget style tools

## Installation

### Requirements
- OpenResty (Nginx with Lua support)
- lua-resty-string module

### Nginx Configuration

```nginx
http {
    # Required: Shared memory for rate limiting and nonce tracking
    lua_shared_dict pow_rate_limit 10m;
    
    server {
        listen 80;
        
        # Apply PoW challenge to all requests (or specific locations)
        access_by_lua_file /path/to/pow_ddos_challenge.lua;
        
        # Your normal configuration...
        location / {
            proxy_pass http://backend;
        }
    }
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POW_SECRET` | (weak default) | **REQUIRED for production** - HMAC secret key |
| `POW_DIFFICULTY` | `3` | Base difficulty (1-6). Each level ~16x harder |
| `POW_EXPIRE` | `604800` | Session duration in seconds (default: 7 days) |
| `POW_RATE_LIMIT` | `10` | Max challenge requests per IP per minute |
| `POW_PROXY_MODE` | `direct` | IP detection mode (see below) |

### Proxy Mode Configuration

| Mode | Trusted Headers | Use When |
|------|-----------------|----------|
| `direct` | None (remote_addr only) | Direct connection to server |
| `cloudflare` | `CF-Connecting-IP` | Behind Cloudflare |
| `proxy` | `X-Forwarded-For` | Behind trusted reverse proxy |

**WARNING:** Only enable proxy modes when actually behind a trusted proxy. Otherwise attackers can spoof their IP address.

## Security Analysis

### Threat Model

This system protects against:

| Threat | Protection Level | Notes |
|--------|------------------|-------|
| Simple scrapers (curl, wget, requests) | [+] **Excellent** | Can't execute JavaScript |
| Basic headless browsers | [+] **Good** | Detected by fingerprinting |
| Puppeteer/Playwright (default) | [+] **Good** | `navigator.webdriver` detected |
| Puppeteer with stealth plugin | [~] **Moderate** | Still must solve PoW |
| Professional scraping services | [~] **Moderate** | CPU cost makes scale expensive |
| DDoS (Layer 7 floods) | [+] **Excellent** | CPU cost on attacker, not server |
| AI training data collection | [~] **Moderate** | Economic barrier at scale |

### How Professional Attackers Are Handled

Even sophisticated attackers who bypass all fingerprinting **must still**:

1. [+] **Solve the actual PoW** - Can't skip the computation
2. [+] **Solve at YOUR difficulty** - Can't reduce it (signed in challenge)
3. [+] **Use YOUR valid challenge** - Can't forge (HMAC verified)
4. [+] **Use each nonce only once** - Can't replay solutions
5. [+] **Complete within 5 minutes** - Can't stockpile challenges

### Economic Impact on Attackers

| Difficulty | Avg. Hashes | Time (modern CPU) | Cost per 1M requests |
|------------|-------------|-------------------|----------------------|
| 1 | ~16 | <1ms | Negligible |
| 2 | ~256 | ~1ms | Negligible |
| 3 | ~4,096 | ~10ms | $5-10 |
| 4 | ~65,536 | ~100ms | $80-160 |
| 5 | ~1,048,576 | ~2s | $1,300-2,600 |
| 6 | ~16,777,216 | ~30s | $20,000+ |

At difficulty 4+, scraping at scale becomes economically unfeasible.

### What This System Does NOT Protect Against

- **Targeted manual access** - Humans solve PoW normally
- **Browser automation with real solving** - If they pay the CPU cost
- **Compromised real user sessions** - Session tokens can be stolen
- **Application-layer vulnerabilities** - This is access control, not WAF

## Server-Side Bot Detection

The server analyzes HTTP headers to detect bots before any JavaScript runs:

| Signal | Suspicion Score | Rationale |
|--------|-----------------|-----------|
| Missing `Accept-Language` | +2 | All real browsers send this |
| Missing `Accept-Encoding` | +1 | Standard browser header |
| Missing/empty `User-Agent` | +3 | Obvious bot indicator |
| Bot-like User-Agent | +2 | curl, wget, python-requests, etc. |
| Missing `Sec-Fetch-*` headers | +1 | Modern browsers always send |
| Missing `Accept` header | +1 | Standard browser header |
| `Connection: close` | +1 | Scrapers often use this |

Suspicion score of 4+ increases difficulty by 2 levels.

## Client-Side Bot Detection (Defense in Depth)

The JavaScript layer provides additional detection that **can only increase** difficulty:

| Signal | Score | What It Catches |
|--------|-------|-----------------|
| `navigator.webdriver === true` | +3 | Selenium, Puppeteer, Playwright |
| Missing `navigator.languages` | +2 | Headless/misconfigured |
| PhantomJS globals | +3 | Legacy automation |
| Puppeteer/Cypress globals | +3 | Automation frameworks |
| Node.js globals | +2 | Server-side JS environments |
| `webdriver`/`selenium` attributes | +3 | Driver artifacts |
| Zero screen dimensions | +2 | Headless default |
| Missing Permissions API | +1 | Headless environments |
| Missing MediaDevices API | +1 | Headless environments |

**Important:** Client-side detection is "nice to have" - security doesn't depend on it because attackers can modify JavaScript. The server-side minimum is always enforced.

## Challenge Format

```
signature-timestamp-difficulty
Example: Abc123XyZ-1735500000-4
```

- **signature**: HMAC-SHA1(IP + timestamp + difficulty + secret), base64url encoded
- **timestamp**: Unix timestamp when challenge was issued
- **difficulty**: Server-determined difficulty level (1-6)

The signature makes it cryptographically impossible to modify the difficulty.

## Logging

All PoW events are logged to nginx error log at INFO level:

```
[PoW] ISSUED ip=1.2.3.4 base_difficulty=3 server_suspicion=2 effective_difficulty=4 rate_count=1
[PoW] VERIFIED ip=1.2.3.4 nonce=847362 difficulty=4 solve_time_ms=1847 hash_prefix=0000a7b3
[PoW] EXPIRED ip=1.2.3.4 age=312
[PoW] INVALID_CHALLENGE ip=1.2.3.4 challenge=tampered_value...
[PoW] NONCE_REPLAY ip=1.2.3.4 nonce=847362
[PoW] RATE_LIMITED ip=1.2.3.4 count=11 limit=10
```

## Performance Considerations

### Server Load
- Challenge generation: Minimal (one HMAC operation)
- Solution verification: Minimal (one SHA256 operation)
- Rate limiting: O(1) shared memory lookup

### Client Load
- PoW solving: Variable based on difficulty
- Real browsers: Usually <1 second at difficulty 3
- Mobile devices: May take longer, consider lower difficulty

### Memory Usage
- Shared dict sizing: ~100 bytes per tracked nonce
- 10MB dict: ~100,000 concurrent nonces
- Nonces expire after 5 minutes automatically

## Recommendations

### For API Protection
```bash
POW_DIFFICULTY=3     # Moderate difficulty
POW_EXPIRE=3600      # 1-hour sessions
POW_RATE_LIMIT=5     # Lower rate limit
```

### For Content Sites
```bash
POW_DIFFICULTY=2     # Lower difficulty for UX
POW_EXPIRE=604800    # Week-long sessions
POW_RATE_LIMIT=20    # More lenient
```

### Under Active Attack
```bash
POW_DIFFICULTY=5     # High difficulty
POW_RATE_LIMIT=3     # Aggressive rate limiting
```

## Comparison with Alternatives

| Solution | Blocks Bots | CPU Cost | Privacy | No 3rd Party |
|----------|-------------|----------|---------|--------------|
| **This PoW System** | [+] Good | On attacker | [+] Yes | [+] Yes |
| Cloudflare | [+] Good | On CF | [-] No | [-] No |
| reCAPTCHA | [+] Moderate | On Google | [-] No | [-] No |
| hCaptcha | [+] Moderate | On hCaptcha | [~] Better | [-] No |
| Simple rate limiting | [~] Poor | On you | [+] Yes | [+] Yes |

## License

MIT License - Use freely, modify as needed.

## Contributing

Issues and pull requests welcome. Please include test cases for security-related changes.
