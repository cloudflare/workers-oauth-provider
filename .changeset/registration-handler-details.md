---
'@cloudflare/workers-oauth-provider': patch
---

Dynamic client registration stops reading a request body at 1 MiB even when it has no `Content-Length` (a chunked body), instead of reading all of it first. When `clientRegistrationCallback` throws, the client gets a fixed `Client registration callback failed` description rather than the error's message, which may be internal; `onError` still receives the error.
