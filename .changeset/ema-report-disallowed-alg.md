---
'@cloudflare/workers-oauth-provider': patch
---

An ID-JAG whose `alg` is not in the trusted issuer's `algorithms` now fails with `invalid_alg` instead of `issuer_not_trusted`, so `onError` shows the real cause. `algorithms` defaults to `['RS256']`, so a resolver for an IdP that signs with `ES256` and leaves `algorithms` unset rejected every assertion as `issuer_not_trusted` even though the issuer was trusted. The client still gets the same `invalid_grant` "Invalid assertion".
