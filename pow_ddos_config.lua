-- NOTE: This file gets placed in /etc/nginx/snippets

-- Common Configuration
return {
    secret = "CHANGE-ME-USE-LONG-RANDOM-STRING-HERE",  -- HMAC secret key, easily generate random secret with: openssl rand -base64 48 | tr -d '+/='
    expire_time = 86400,             -- Session (Cookie) duration in seconds (default: 86400 = 1 day)
    rate_limit = 10,                 -- Max challenge requests per IP, per minute. NOTE: Each valid challenge will be minimum of 2 requests (ISSUED, VERIFIED)
    shared_zone = "pow_rate_limit",  -- Shared memory zone name for rate limiting
    proxy_mode = "direct",           -- IP detection: "direct", "cloudflare", or "proxy" (default: direct)
}
