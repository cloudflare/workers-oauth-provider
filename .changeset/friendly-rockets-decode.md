---
'@cloudflare/workers-oauth-provider': patch
---

Return an RFC-compliant `401 invalid_client` response with a Basic authentication challenge when credentials contain malformed percent-encoding instead of throwing an uncaught `URIError`.
