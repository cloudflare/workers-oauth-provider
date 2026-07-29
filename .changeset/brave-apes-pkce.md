---
'@cloudflare/workers-oauth-provider': minor
---

Reject authorization-code requests from public clients that omit PKCE. OAuth 2.1 requires authorization servers to enforce `code_challenge` for clients that cannot authenticate at the token endpoint.
