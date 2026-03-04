---
'@cloudflare/workers-oauth-provider': patch
---

Include `client_secret_expires_at` and `client_secret_issued_at` in dynamic client registration responses when a `client_secret` is issued, per RFC 7591 §3.2.1.
