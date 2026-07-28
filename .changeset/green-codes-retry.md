---
'@cloudflare/workers-oauth-provider': patch
---

Validate the RFC 8707 resource parameter before consuming an authorization code, so a token request rejected with `invalid_target` can be retried with an allowed resource.
