---
'@cloudflare/workers-oauth-provider': patch
---

Fix worker crash (HTTP 500) when the `/token` request sends a malformed
`Content-Type` header. The endpoint previously used a loose `includes()` check,
so a header such as `application/json, application/x-www-form-urlencoded` passed
validation and then caused `request.formData()` to throw. The media type is now
parsed strictly (parameters are stripped and the exact media type is compared),
and form parsing is guarded so invalid bodies return a `400 invalid_request`
instead of crashing the worker.
