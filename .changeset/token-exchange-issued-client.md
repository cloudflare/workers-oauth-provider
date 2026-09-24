---
'@cloudflare/workers-oauth-provider': patch
---

A token from an allowed cross-client token exchange is issued to the requesting client (RFC 8693) instead of being recorded as the subject token's client. `ctx.auth.clientId` and `unwrapToken()` now name the client that holds the token, and that client can revoke it; previously revocation failed its ownership check. The token still lives under the subject's grant, so revoking the grant removes it.
