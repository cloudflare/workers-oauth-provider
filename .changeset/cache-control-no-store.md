---
'@cloudflare/workers-oauth-provider': patch
---

Add `Cache-Control: no-store` and `Pragma: no-cache` to OAuth responses that contain tokens or credentials, per RFC 6749 §5.1 (token endpoint responses and dynamic client registration responses carrying `client_secret`).
