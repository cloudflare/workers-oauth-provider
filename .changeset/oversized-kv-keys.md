---
'@cloudflare/workers-oauth-provider': patch
---

A `client_id`, authorization code, refresh token or access token too long to form a KV key is treated as unknown instead of failing the request. Cloudflare KV throws for a key over 512 bytes rather than reporting a miss, so an oversized value from a request threw: from `parseAuthRequest()` and `lookupClient()`, and out of `fetch()` at the token and revocation endpoints and on every API route, for a bearer shaped like `userId:grantId:secret`. Those requests now get the answer an unknown value gets: `invalid_client`, `invalid_grant`, `invalid_token`, a successful revocation, or `null`.
