---
'@cloudflare/workers-oauth-provider': minor
---

Add opt-in RFC 9068 JWT access tokens.

- `createJwtAccessTokens()` gives `OAuthAuthorizationServer` a signer and a JWKS endpoint while it keeps its encrypted token records, so same-Worker resources, Service Binding validation, token exchange, and revocation are unchanged.
- `createJwtAccessTokenValidator()` validates those tokens offline in a separate resource Worker. Its `keys` resolver receives the token's `kid` and `alg`, so a cached key set can refresh once after the authorization server rotates.
- `accessTokenFormat` chooses `opaque` or `jwt` per issuance, so readers and the JWKS can roll out before any JWT is written, and existing tokens and refresh grants stay valid.
- Authorization codes, refresh tokens, and enterprise assertions stay retryable when signing fails; nothing is consumed before the token is built.
- A cross-client token exchange is owned by the authenticated exchanging client, and `deleteClient()` sweeps exchanged tokens regardless of the current `allowTokenExchangeGrant` setting. Hosted handlers' `ctx.props` take the class `Props` type. RSA public keys with a forgeable exponent are rejected.
