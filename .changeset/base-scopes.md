---
'@cloudflare/workers-oauth-provider': minor
---

A resource's up-front scopes have their own option, `baseScopes`, on `OAuthResourceServer` and `OAuthProvider`: what MCP clients request first, published as the protected resource metadata's `scopes_supported` and named in the `401` challenge. It sits beside `resourceMetadata` instead of inside it, where it read like the authorization server's `scopesSupported` catalogue. `resourceMetadata.scopes_supported` still works but is deprecated in favour of `baseScopes`; setting both throws at construction.
