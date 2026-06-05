---
'@cloudflare/workers-oauth-provider': patch
---

Add `Cache-Control: no-store` and `Pragma: no-cache` to OAuth responses that carry tokens, credentials, or OAuth state, matching the response examples in RFC 6749 §5.1/§5.2: token endpoint responses (success and error), dynamic client registration responses carrying `client_secret`, and EMA JWT-bearer token responses.
