---
'@cloudflare/workers-oauth-provider': minor
---

Expose `grantId` to `tokenExchangeCallback` via `TokenExchangeCallbackOptions`.

Implementations of `tokenExchangeCallback` already received `userId` and
`clientId`, but had no way to identify which specific grant the library was
operating on. This made it impossible to surgically revoke a single grant from
the callback (e.g. on a terminal upstream refresh failure) — implementations had
to either sweep all grants for a `(userId, clientId)` pair (racy under
concurrent refreshes) or maintain their own out-of-band mapping.

`grantId` is now provided alongside `userId` so callbacks can pass them
directly to `OAuthHelpers.revokeGrant`. Populated for all three grant types
(`authorization_code`, `refresh_token`, `token_exchange`). Stable across
refreshes for the lifetime of the grant.
