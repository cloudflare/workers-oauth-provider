---
'@cloudflare/workers-oauth-provider': minor
---

Enterprise-Managed Authorization (experimental) is ready for a multi-tenant authorization server:

- A jwt-bearer request that omits `resource` is bound to the resource the ID-JAG names. Before, an `OAuthAuthorizationServer` with several resources answered `invalid_target` unless the client repeated it, which MCP EMA §5.1 doesn't require. An explicit `resource` still has to match the signed claim.
- Requested and mapped scopes are capped at `scopesSupported`, as an interactive grant's are. Before, an assertion without a `scope` claim let `mapClaims` mint any scope.
- The JWKS cache is keyed by issuer and JWKS URL. A resolver that returns different `jwksUri` values for one issuer, such as two tenant rows, no longer shares cached keys between them.
- New `onTokenIssued(event)` runs after the grant and token are stored and before the response, with the claims, client, user ID, grant ID, resource, scope and lifetime, for audit logs or per-tenant grant indexes. A thrown error propagates, so the token is never returned.
