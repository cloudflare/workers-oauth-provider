---
'@cloudflare/workers-oauth-provider': patch
---

`refreshTokenTTL` and `clientRegistrationTTL` are validated at construction, like `accessTokenTTL`. A value Cloudflare KV can't store (under 60 seconds, or not an integer) used to surface only at runtime, as a 500 on every code exchange or every dynamic client registration. `refreshTokenTTL` accepts `0` (no refresh tokens), `undefined` (no expiry) or an integer of at least 60; `clientRegistrationTTL` accepts `undefined` (no expiry) or an integer of at least 60. `0` is no longer accepted for `clientRegistrationTTL`, where it used to be treated as "no expiry" in one place and as a TTL in another.
