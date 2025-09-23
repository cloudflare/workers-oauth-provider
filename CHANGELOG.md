# @cloudflare/workers-oauth-provider

## 0.0.11

### Patch Changes

- [#78](https://github.com/cloudflare/workers-oauth-provider/pull/78) [`32560d1`](https://github.com/cloudflare/workers-oauth-provider/commit/32560d1e45fd74db8129b5d10d668a82deaff7f2) Thanks [@rc4](https://github.com/rc4)! - Use rejection sampling to avoid bias in `generateRandomString()`

## 0.0.10

### Patch Changes

- [#87](https://github.com/cloudflare/workers-oauth-provider/pull/87) [`1804446`](https://github.com/cloudflare/workers-oauth-provider/commit/1804446ba6d17fa7e6395e47a4fecef374d7e1bd) Thanks [@threepointone](https://github.com/threepointone)! - explicitly block javascript: (and other suspicious protocols) in redirect uris

  In https://github.com/cloudflare/workers-oauth-provider/pull/80, we blocked redirects that didn't start with http:// or https:// to prevent xss attacks with javascript: URIs. However this blocked redirects to custom apps like cursor:// et al. This patch now explicitly blocks javascript: (and other suspicious protocols) in redirect uris.

## 0.0.9

### Patch Changes

- [#81](https://github.com/cloudflare/workers-oauth-provider/pull/81) [`d18b865`](https://github.com/cloudflare/workers-oauth-provider/commit/d18b865bb21a669993424da89ebca47d391644ba) Thanks [@deathbyknowledge](https://github.com/deathbyknowledge)! - Add resolveExternalToken to support external token auth flows

  Adds resolveExternalToken to support auth for external tokens. The callback only runs IF internal auth check fails. E.g. a canonical OAuth server is used by multiple services, allowing server-server communication with the same token.

## 0.0.8

### Patch Changes

- [#74](https://github.com/cloudflare/workers-oauth-provider/pull/74) [`9d4b595`](https://github.com/cloudflare/workers-oauth-provider/commit/9d4b595f63d2aebd5700e4021967b98173cd3755) Thanks [@ghostwriternr](https://github.com/ghostwriternr)! - Add configurable refresh token expiration
  - New `refreshTokenTTL` option to set global expiration for refresh tokens
  - Support for per-token TTL override via `tokenExchangeCallback`
  - Expired tokens return `invalid_grant` error, forcing reauthentication
  - Backward compatible: tokens without TTL never expire

## 0.0.7

### Patch Changes

- [#62](https://github.com/cloudflare/workers-oauth-provider/pull/62) [`239e753`](https://github.com/cloudflare/workers-oauth-provider/commit/239e753b83091a32327f3b2a093e306bb6ee8498) Thanks [@whoiskatrin](https://github.com/whoiskatrin)! - token revocation endpoint support

- [#76](https://github.com/cloudflare/workers-oauth-provider/pull/76) [`0b064bf`](https://github.com/cloudflare/workers-oauth-provider/commit/0b064bf087df3722760bc1d328fbe4c869bb626f) Thanks [@ghostwriternr](https://github.com/ghostwriternr)! - Fix token revocation returning HTTP 500 instead of 200

- [#80](https://github.com/cloudflare/workers-oauth-provider/pull/80) [`9587b58`](https://github.com/cloudflare/workers-oauth-provider/commit/9587b5821a37a92d5bb86299afbce1958ee46a54) Thanks [@threepointone](https://github.com/threepointone)! - block javascript: redirect URIs

## 0.0.6

### Patch Changes

- [#52](https://github.com/cloudflare/workers-oauth-provider/pull/52) [`fe6b721`](https://github.com/cloudflare/workers-oauth-provider/commit/fe6b721520ed21e82cbea451f7afbedfa70b1a12) Thanks [@cnallam](https://github.com/cnallam)! - Fix for the Missing Validation for ClientId
