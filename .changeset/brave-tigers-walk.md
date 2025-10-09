---
'@cloudflare/workers-oauth-provider': minor
---

Add OAuth 2.0 client_credentials grant type for machine-to-machine authentication

- New `client_credentials` grant type for server-to-server authentication
- Issues access tokens without user interaction or refresh tokens
- Supports scope validation and custom token props via callback
- Token props include machine identity (`type: 'machine'`)
- Full test coverage with 9 new comprehensive tests
- Backward compatible with all existing functionality
