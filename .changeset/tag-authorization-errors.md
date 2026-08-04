---
'@cloudflare/workers-oauth-provider': minor
---

Export `AuthorizationError` and throw it from `parseAuthRequest()` for expected authorization-request validation failures. Errors carry a validated redirect URI, original state, and issuer only after exact client redirect validation succeeds, allowing applications to distinguish safe OAuth error redirects from failures that must be rendered locally.
