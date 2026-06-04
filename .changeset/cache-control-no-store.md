---
'@cloudflare/workers-oauth-provider': patch
---

Add `Cache-Control: no-store` and `Pragma: no-cache` to OAuth responses carrying tokens, credentials, or other sensitive authorization data.
