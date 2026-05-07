---
'@cloudflare/workers-oauth-provider': patch
---

Add `Cache-Control: no-store` to token responses, DCR responses, and error responses per RFC 6749 §5.1.
