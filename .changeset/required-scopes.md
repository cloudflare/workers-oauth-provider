---
'@cloudflare/workers-oauth-provider': minor
---

A resource's required scopes have their own option, `requiredScopes`, on `OAuthResourceServer` and `OAuthProvider`: the scopes any access needs, published as the protected resource metadata's `scopes_supported` and named in the `401` challenge, so MCP clients request them first. It sits beside `resourceMetadata` instead of inside it, where it read like the authorization server's `scopesSupported` catalogue. It is advertised, not enforced: handlers check `ctx.auth.scope`, since only they know which scopes imply others. `resourceMetadata.scopes_supported` still works but is deprecated in favour of `requiredScopes`; setting both throws at construction.
