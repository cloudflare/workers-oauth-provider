---
'@cloudflare/workers-oauth-provider': patch
---

Fix uncaught 500 when an ID-JAG assertion has under 60 seconds left. The EMA replay marker
took its KV TTL straight from the assertion's remaining lifetime, so KV rejected the write
and the request crashed instead of exchanging. The marker's TTL is now floored at 60s.
