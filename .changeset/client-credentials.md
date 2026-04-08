---
'@cloudflare/workers-oauth-provider': minor
---

Add `client_credentials` grant type for M2M auth (RFC 6749 §4.4). Enable with `allowClientCredentialsGrant: true`. Confidential clients only, no refresh token issued.
