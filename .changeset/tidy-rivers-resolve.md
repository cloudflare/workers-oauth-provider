---
'@cloudflare/workers-oauth-provider': patch
---

Convert `OAuthError` thrown by `resolveExternalToken` into structured protected-resource error responses. Standard bearer-token failures receive `WWW-Authenticate` challenges, callback headers are preserved, and unexpected errors continue to surface as 500s.
