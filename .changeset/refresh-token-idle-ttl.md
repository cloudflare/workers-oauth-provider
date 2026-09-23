---
'@cloudflare/workers-oauth-provider': minor
---

Add opt-in sliding expiry for refresh tokens.

A grant's lifetime is fixed at the code exchange by default: it expires `refreshTokenTTL` seconds later however often it is refreshed. The new `refreshTokenIdleTTL` option makes that lifetime slide, moving the grant's expiry, and the KV expiration of its record, to that many seconds after every successful refresh. `tokenExchangeCallback` can return `refreshTokenIdleTTL` during a refresh to set the lifetime for that refresh alone, so a Worker that proxies an upstream OAuth service can give the grant exactly the lifetime of the upstream refresh token it just rotated.

The slide happens only when a refresh succeeds: a throwing callback, an expired grant, or a grant that expires while the callback runs leaves the old expiry in place. Returning `refreshTokenIdleTTL` for any other grant type, or a value that is not an integer of at least 60 seconds, is rejected with `invalid_request`. Nothing changes for deployments that do not set it.
