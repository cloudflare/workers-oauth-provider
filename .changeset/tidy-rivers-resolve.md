---
'@cloudflare/workers-oauth-provider': minor
---

Convert `OAuthError` thrown by `resolveExternalToken` into structured protected-resource error responses. Standard bearer-token failures receive `WWW-Authenticate` challenges, `requiredScopes` supplies step-up scope guidance, callback headers are preserved, browser clients can read `WWW-Authenticate` and `Retry-After` through CORS, and unexpected errors continue to surface as 500s.
