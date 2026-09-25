---
'@cloudflare/workers-oauth-provider': minor
---

An `OAuthResourceServer`'s `validateToken` can throw `OAuthError` to choose the response, as a `tokenExchangeCallback` already can. `temporarily_unavailable` with `statusCode: 429` and `Retry-After` passes through; `insufficient_scope` becomes the MCP `403` challenge naming the new `OAuthError` `requiredScopes` option (or the resource's `requiredScopes`); `invalid_token` becomes a `401` with the Bearer challenge. Anything else thrown is still a `503`. This lets one resource validate an upstream API's own credentials in `validateToken` before falling back to its authorization server. `OAuthProvider`'s `resolveExternalToken` and `ExternalTokenError` are unchanged.
