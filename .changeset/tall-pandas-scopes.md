---
'@cloudflare/workers-oauth-provider': minor
---

Separate authorization-server and protected-resource scope configuration. Explicit `resourceMetadata.scopes_supported` values become baseline Bearer challenge guidance, operation-specific `requiredScopes` takes precedence, and `offline_access` is omitted from provider-generated resource-facing scope lists. Deployments relying on the old `scopesSupported` fallback must configure protected-resource scopes explicitly.
