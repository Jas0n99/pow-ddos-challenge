# SHA256 Proof-of-Work Anti-DDoS Challenge

A cryptographic proof-of-work challenge system for Nginx/OpenResty that provides robust protection against DDoS attacks, automated scrapers, and AI-powered bots.

This lua script is much more lightweight than others, and thus much easier to implement with minimal overhead.

## Differences from upstream version

This version is tailored to Debian/Ubuntu namings and locations, and re-worked as a module for additional lua code capability by utilizing an `access_by_lua_block`.

Environment variable code has been removed in favor of a separate config file, and defining difficulty in the Nginx lua block.

Instead of complicating the PoW lua script with unnecessary bloat that might not be applicable or compatible with your site, altering the base difficulty or bypassing certain URLs or User-Agents or whatever you can think of can be done much easier and effectively with Nginx maps and creating basic logic in the `access_by_lua_block`.

If you wanted to be truely nefarious for a known bot, you could force the highest level test and if they complete the PoW you can still deliver a 403 afterwards easily within the `access_by_lua_block`.

- Changed to a 3 step process
    1. Client must calculate and submit client-side suspicion score (No javascript = process stops here)
    2. Client then receives a server-set difficulty level, and server-generated challenge to complete
    3. Client must submit valid completed challenge to be authenticated
- Optimized with Nginx internal table shortcuts for better performance
- Included the hostname and uri as part of the challenge and some tracking methods to prevent cross-site issues / exploitation / race conditions
- Additional server side and client side (JavaScript) suspicion tests
- Difficulty level 7 "honeypot" - only fake engines trigger this, then get rejected after wasting their time
- Suspiciously fast solve detection with random jitter and rechallenge (helps prevent against SHA256 acceleration methods)
- JavaScript timing delay with server-side verification / notification / penalty
- Some very basic minification stripping comments, newlines, and excessive spaces from output
- robots.txt, ads.txt, favicon.ico, and /.well-known/ bypass due to necessary universal access

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

### Check README_ORIG.md for original / full documentation.
