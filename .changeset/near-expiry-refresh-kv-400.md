---
'@cloudflare/workers-oauth-provider': patch
---

Fix uncaught 500 when refreshing a near-expiry grant. A refresh arriving in the final
<60s of a grant's life previously passed the expiry check and then crashed with
"KV PUT failed: 400 Invalid expiration" because Cloudflare KV rejects absolute
expirations less than 60 seconds in the future. Such grants are now treated as expired
(returning `invalid_grant`), and `saveGrantWithTTL` clamps the absolute expiration to
KV's 60-second minimum as defense-in-depth.
