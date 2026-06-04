---
'@cloudflare/workers-oauth-provider': patch
---

Add `Cache-Control: no-store` and `Pragma: no-cache` to OAuth responses that carry tokens, credentials, or OAuth state, per RFC 6749 §5.1: token endpoint success responses, dynamic client registration responses carrying `client_secret`, and OAuth error responses.
