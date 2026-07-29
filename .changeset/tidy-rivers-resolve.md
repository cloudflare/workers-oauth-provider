---
'@cloudflare/workers-oauth-provider': minor
---

Add an exported `ExternalTokenError` for intentional structured errors from `resolveExternalToken`. Existing callbacks keep their previous behavior: returning `{ props, audience? }` authenticates, returning `null` returns a generic `401 invalid_token`, and every other thrown value, including `OAuthError`, propagates as an unexpected failure. Standard bearer-token `ExternalTokenError` failures receive `WWW-Authenticate` challenges, `requiredScopes` supplies step-up guidance, callback headers are preserved, and browser clients can read `WWW-Authenticate` and `Retry-After` through CORS.
