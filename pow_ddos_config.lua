-- NOTE: This file gets placed in /etc/nginx/snippets

-- Common Configuration
return {
    secret = "CHANGE-ME-USE-LONG-RANDOM-STRING-HERE",  -- HMAC secret key, generate secret with: openssl rand -base64 48 | tr -d '+/='
    expire_time = 86400,    -- Session duration in seconds (default: 86400 = 1 day)
    rate_limit = 10,        -- Max challenge requests per IP per minute
    proxy_mode = "direct",  -- IP detection: "direct", "cloudflare", or "proxy" (default: direct)
}
