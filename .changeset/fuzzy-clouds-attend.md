---
'@cloudflare/workers-oauth-provider': patch
---

Add OAuth 2.0 Token Exchange (RFC 8693) support. Clients can exchange an existing access token for a new one with narrowed scopes, a different audience, or a shorter TTL — without requiring the user to re-authorize. Gated behind the `allowTokenExchangeGrant` option (default `false`). Also adds scope downscoping (RFC 6749 Section 3.3) to authorization code and refresh token flows.
