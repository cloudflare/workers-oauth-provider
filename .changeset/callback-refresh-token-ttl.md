---
'@cloudflare/workers-oauth-provider': patch
---

`tokenExchangeCallback` lifetimes no longer fail requests or silently remove expiry. `refreshTokenTTL: undefined` in a callback result now keeps the provider's lifetime; it used to make the grant never expire, which is what a callback passing through an upstream's missing `refresh_expires_in` did. `refreshTokenTTL` is validated (`0`, or an integer of at least 60 seconds) instead of failing the code exchange with a storage error. Each lifetime is ignored where it doesn't apply, rather than rejected after the callback ran: returning `refreshTokenTTL` on refresh, or `refreshTokenIdleTTL` at code exchange or token exchange, used to fail the request after the callback's side effects, such as rotating an upstream refresh token.
