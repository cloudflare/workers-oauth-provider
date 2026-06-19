---
'@cloudflare/workers-oauth-provider': patch
---

Fix uncaught 500 when refreshing a near-expiry grant. A refresh arriving in the final
<60s of a grant's life previously passed the expiry check and then crashed with
"KV PUT failed: 400 Invalid expiration" because Cloudflare KV rejects absolute
expirations less than 60 seconds in the future. Such grants are now treated as expired
(returning `invalid_grant`).

The refresh handler also re-checks expiry after the `tokenExchangeCallback` runs, so a
slow callback (e.g. an upstream network refresh) that pushes the grant under the 60-second
threshold mid-request is rejected cleanly instead of crashing when writing the rotated
grant or the new access token (whose TTL is clamped to the grant's remaining lifetime).
As defense-in-depth, `saveGrantWithTTL` also clamps the absolute expiration to KV's
60-second minimum.
