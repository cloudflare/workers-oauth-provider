---
'@cloudflare/workers-oauth-provider': patch
---

Add configurable refresh token expiration

- New `refreshTokenTTL` option to set global expiration for refresh tokens
- Support for per-token TTL override via `tokenExchangeCallback`
- Expired tokens return `invalid_grant` error, forcing reauthentication
- Backward compatible: tokens without TTL never expire
