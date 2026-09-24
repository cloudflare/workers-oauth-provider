---
'@cloudflare/workers-oauth-provider': patch
---

CORS headers an API handler sets itself (`Access-Control-Allow-Origin`, `-Methods`, `-Headers`, `-Max-Age`) are kept instead of being overwritten, so a handler can narrow its own CORS policy; `Vary: Origin` and the exposed `WWW-Authenticate` and `Retry-After` headers are still added. `OAuthProvider` and `OAuthResourceServer` now share one implementation of CORS, header merging and resource scope filtering.
