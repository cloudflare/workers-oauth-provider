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

The token exchange grant (RFC 8693) shared the same root cause: the issued token's TTL is
clamped to the subject token's remaining lifetime, so a subject token in its final <60s (or
a `expires_in`/`accessTokenTTL` below 60) produced an unstorable token. The exchange now
rejects a subject token with under 60s remaining (`invalid_grant`) and a requested lifetime
below 60s (`invalid_request`) instead of crashing.

More broadly, any access token lifetime below KV's 60-second minimum is now caught instead of
crashing with an opaque KV 400:

- `accessTokenTTL` is validated at `OAuthProvider` construction (must be an integer of at
  least 60 seconds).
- A `tokenExchangeCallback` returning an `accessTokenTTL` below 60 on the authorization code
  or refresh grant is rejected with `invalid_request`.
- The enterprise-managed authorization (ID-JAG) grant rejects a mapper-supplied access token
  TTL below 60 (`invalid_grant`, "Invalid access token TTL").
