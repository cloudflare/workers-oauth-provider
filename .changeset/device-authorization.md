---
'@cloudflare/workers-oauth-provider': minor
---

Add Device Authorization Grant (RFC 8628) for CLI/IoT clients. Enable with `deviceAuthorizationEndpoint`. Includes `slow_down` rate limiting, confidential client auth, jti-safe user codes, and `OAuthHelpers` methods for verification UI (`getDeviceCodeByUserCode`, `approveDeviceCode`, `denyDeviceCode`).
