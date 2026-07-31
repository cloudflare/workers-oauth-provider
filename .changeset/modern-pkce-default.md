---
'@cloudflare/workers-oauth-provider': minor
---

Require S256 PKCE by default. Authorization servers now advertise only `S256` and reject PKCE challenges that use `plain` or omit `code_challenge_method` unless `allowPlainPKCE: true` is configured for legacy compatibility. Confidential clients may continue to omit PKCE entirely.
