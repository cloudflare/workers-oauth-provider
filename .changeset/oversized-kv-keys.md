---
'@cloudflare/workers-oauth-provider': patch
---

Every KV key the provider builds now fits Cloudflare KV's 512-byte limit, which throws for a longer key instead of reporting a miss.

`completeAuthorization()` refuses a user ID over 424 bytes of UTF-8, the most an access token's key `token:{userId}:{grantId}:{tokenId}` leaves, with the same `TypeError` it throws for `:`. Before, a user ID of 425 to 489 bytes got a grant and a code whose exchange then threw writing the access token, and a longer one threw from `completeAuthorization()`. An Enterprise-Managed Authorization `mapClaims` result is held to the same rule (`invalid_mapped_user`).

A `client_id`, authorization code, refresh token or access token from a request that would need a longer key is treated as unknown. Before, it threw from `parseAuthRequest()` and `lookupClient()`, and out of `fetch()` at the token and revocation endpoints and on every API route. Those requests now get the answer an unknown value gets: `invalid_client`, `invalid_grant`, `invalid_token`, a successful revocation, or `null`. Codes and tokens are parsed once, in one place: three parts, a user ID within the limit, and a grant ID of the form this provider generates. A code or refresh token with any other grant ID is reported to `onError` as `code_malformed` or `refresh_token_malformed` rather than `grant_not_found`.
