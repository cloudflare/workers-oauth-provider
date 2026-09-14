---
'@cloudflare/workers-oauth-provider': minor
---

Add opt-in RFC 9068 JWT access tokens.

- `createJwtAccessTokens()` gives `OAuthAuthorizationServer` a signer and a JWKS endpoint while it keeps its encrypted token records, so same-Worker resources, Service Binding validation, token exchange, and revocation are unchanged.
- Passing it as `jwtAccessTokens` installs the reader, signer and JWKS without changing what is issued. `accessTokenFormat` returns `opaque` or `jwt` per issuance and per resource, so readers always ship before any JWT is written, and existing tokens and refresh grants stay valid.
- `createJwtAccessTokenValidator()` validates those tokens offline in a separate resource Worker. `algorithms` is required, so an ES256 deployment cannot silently reject every token at a validator that assumed RS256.
- `createJwksKeyResolver()` fetches and caches an authorization server's JWKS for that validator over a Service Binding, refreshing for an unknown `kid` at most once per cooldown window.
- Authorization codes and refresh tokens stay retryable when signing fails; an enterprise assertion's signing key is proven before the assertion is consumed.
- `OAuthAuthorizationServer<Env, Props>` and `OAuthHelpers<Props>` carry the application props type, so a hosted handler's `ctx.props` is typed without a per-call type argument. Both parameters default, so existing code is unaffected.
- RSA public keys with a forgeable exponent are rejected.
