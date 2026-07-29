---
'@cloudflare/workers-oauth-provider': patch
---

Return a bare RFC 6750 bearer challenge when protected resource requests omit credentials or use an unsupported authorization scheme. These responses no longer mislabel absent credentials as `invalid_token` or include OAuth error details.
