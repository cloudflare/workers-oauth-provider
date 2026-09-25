# JWT access tokens (experimental)

**Experimental.** JWT access tokens are new, so the `accessTokens` option, `createJwtAccessTokenValidator()` and their exported types (`AccessTokenOptions`, `JwtAccessTokenOptions`, `JwtAccessTokenValidatorOptions`, `JwtAccessTokenClaims`, `JwtClaimsInput`, `JwtClaimValue`, `JwtKey`, `JwtKeySet`) are exempt from 1.x semver: they may change in a minor release, with the change documented in the changelog.

Access tokens are opaque by default. Set `accessTokens` on `OAuthAuthorizationServer` to issue [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access tokens instead. A resource server can then verify each token itself, instead of asking the authorization server on every request. [`examples/jwt-access-tokens`](../examples/jwt-access-tokens) has both Workers, key generation and rotation in full.

## Issuing

```ts
new OAuthAuthorizationServer<Env>({
  // …issuer, resources, endpoints
  accessTokenTTL: 5 * 60,
  accessTokens: {
    issuing: 'jwt', // the one format new tokens use: 'opaque' or 'jwt'
    jwt: {
      keys: (env) => ({
        current: JSON.parse(env.JWT_SIGNING_KEY), // EC P-256 private JWK with a kid
        additional: JSON.parse(env.JWT_ADDITIONAL_KEYS ?? '[]'), // optional: next or previous public keys
      }),
      claims: ({ props }) => ({ plan: props.plan }), // optional, readable by the client
    },
  },
});
```

- **Algorithm:** tokens are signed with ES256 (ECDSA P-256) only, with the JOSE header `typ: at+jwt`. Signing and verification use [`jose`](https://github.com/panva/jose).
- **Claims:** `iss`, `sub`, `aud` (the one resource), `exp`, `iat`, `jti`, `client_id`, `scope` and `grant_id`. `claims()` may add others but not replace these. The payload is signed, not encrypted: never put secrets in it.
- **JWKS:** the public keys are served at `/.well-known/jwks.json` and advertised as `jwks_uri` in the authorization server metadata.
- **Keys:** `keys()` resolves per request, so rotation is a secret change. Publish the next key in `additional`, then make it `current` and move the old one to `additional`, then remove the old one once its tokens have expired.
- **What stays the same:** authorization codes and refresh tokens stay opaque. The provider still stores a record per access token and finds it by the token's hash, so `validateToken()` decrypts props and sees revocation immediately; it doesn't need to check the signature. Opaque access tokens stay valid until they expire; see [Switching from opaque tokens](#switching-from-opaque-tokens).
- **Failures:** if signing or `claims()` fails, the token endpoint answers `server_error` before consuming the authorization code or rotating the refresh token, so the client can retry.

## Switching from opaque tokens

`issuing` is the one format new tokens use. Configuring `jwt` accepts JWTs and publishes their keys. Opaque tokens are always accepted until their records expire, and refresh tokens are always opaque. Each step is safe to roll back:

1. **Readers first.** `{ issuing: 'opaque', jwt }` publishes the JWKS while tokens stay opaque, so resource servers load the keys before any JWT exists.
2. **Issue JWTs.** `{ issuing: 'jwt', jwt }`. Opaque tokens from before keep working until they expire, `accessTokenTTL` later.

To roll back, issue `'opaque'` again and keep `jwt`, so outstanding JWTs stay valid until they expire. Removing `jwt` stops accepting them at once. `issuing: 'jwt'` without `jwt` is rejected when the server is constructed. Without `accessTokens` the server issues opaque tokens only.

## Validating without a call

```ts
import { createJwtAccessTokenValidator, OAuthResourceServer } from '@cloudflare/workers-oauth-provider';

export default new OAuthResourceServer<Env, AuthProps>({
  resourceMetadata: {
    resource: 'https://calendar.example.com/mcp',
    authorization_servers: ['https://auth.example.com'],
  },
  validateToken: createJwtAccessTokenValidator<Env, AuthProps>({
    issuer: 'https://auth.example.com',
    keys: (env) => authServerKeys(env), // the `keys` of the auth server's JWKS, loaded your way
    mapClaims: (claims) => ({ userId: claims.sub }),
  }),
  handler,
});
```

- **`issuer`** is the exact `iss` accepted. To accept several authorization servers, route each token to its own validator in your `validateToken`.
- **`keys`** returns the authorization server's public keys: fetch its `/.well-known/jwks.json` (over a Service Binding or the internet) and cache it, or read them from configuration. The library does no fetching. A thrown error fails closed with a 503, or with the response of a thrown `OAuthError`.
- **Checks:** each token's signature, `typ`, `alg`, `iss`, `aud`, `exp` and required claims are checked locally with `jose`.
- **`mapClaims`** is optional. It builds `ctx.props` from the verified claims, or returns `null` to reject. Without it `ctx.props` is `undefined`; it is never the encrypted grant props. The verified subject, client and scopes are on `ctx.auth` either way.
- **Trade-off:** a revoked token keeps working until it expires, so keep `accessTokenTTL` short.

|                  | `validateToken()` over a Service Binding | `createJwtAccessTokenValidator()`           |
| ---------------- | ---------------------------------------- | ------------------------------------------- |
| Call per request | Yes                                      | No                                          |
| Sees revocation  | Immediately                              | When the token expires                      |
| `ctx.props`      | Decrypted grant props                    | Mapped from verified claims, or `undefined` |
