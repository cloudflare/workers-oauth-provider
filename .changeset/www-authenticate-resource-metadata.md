---
'@cloudflare/workers-oauth-provider': patch
---

Include `resource_metadata` URL in `WWW-Authenticate` headers on 401 responses per RFC 9728 §5.1, enabling clients to discover the protected resource metadata endpoint directly from authentication challenges.
