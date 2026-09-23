---
'@cloudflare/workers-oauth-provider': minor
---

Add opt-in RFC 9068 JWT access tokens, and name a separate resource Worker's validation mode.

- `createJwtAccessTokens({ issuer, jwksUri, keys, publicClaims?, issuance? })` gives `OAuthAuthorizationServer` a signer, a reader and a JWKS endpoint while it keeps its encrypted token records, so same-Worker resources, Service Binding validation, token exchange and revocation are unchanged. `issuance`, a boolean or a function of `{ env, resource }`, decides whether new tokens are JWTs; it is off by default so readers always ship before the first JWT is written, and existing tokens and refresh grants stay valid throughout.
- `createOAuthResourceServer({ validateToken })` accepts `{ online, offline }` as well as a function. `online` asks the authorization server over a private Service Binding: full props, immediate revocation. `offline` verifies the JWT locally against the authorization server's JWKS: `issuer`, required `algorithms`, `keys` as `{ jwksUri, fetcher?, cacheTtlSeconds? }` or a resolver, and `mapClaimsToProps`; the audience is the resource server's own. With both, a token offline cannot verify is asked about online, which carries a deployment from opaque tokens to JWTs without an outage.
- The JWKS is fetched from `jwksUri` and nowhere a token names, cached no longer than the response's `Cache-Control` allows, and refreshed for an unknown `kid` at most once per cooldown.
- Authorization codes and refresh tokens stay retryable when signing fails; an enterprise assertion's signing key is proven before the assertion is consumed.
- `OAuthAuthorizationServer<Env, Props>` and `OAuthHelpers<Props>` carry the application props type, so a hosted handler's `ctx.props` is typed without a per-call type argument. Both parameters default, so existing code is unaffected.
- RSA public keys with a forgeable exponent are rejected.
