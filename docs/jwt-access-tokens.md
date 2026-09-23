# JWT access tokens and separate resource Workers

Access tokens are opaque unless you ask for JWTs. This guide covers the two things that change when you do: the authorization server signs [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) tokens and publishes a JWKS, and a resource server in its own Worker can validate a token without asking the authorization server. Nothing here is required for a single Worker that uses `OAuthProvider` or `protectResource()`; those keep validating against the KV token record either way.

## Which validation mode

A separate resource Worker names its validation mode in `createOAuthResourceServer({ validateToken })`:

| Mode      | How                                                                   | You get                                                        | You give up                                                             |
| --------- | --------------------------------------------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `online`  | Ask the authorization server over a private Service Binding           | Full confidential `props`, immediate revocation, opaque tokens | One RPC per request                                                     |
| `offline` | Verify the authorization server's signed JWT locally against its JWKS | No round trip per request                                      | Only public claims; a revoked token verifies until it expires           |
| both      | `offline` first; whatever it cannot verify is asked about `online`    | A rollout path from opaque to JWT with no outage               | Nothing, once the last opaque token has expired and `online` is removed |

`online` takes a binding, not a URL. The validator is deliberately not something you point at over the public internet. `validateToken` also accepts a function of your own for any other issuer, such as an RFC 7662 introspection call.

## Online: a resource Worker that asks the authorization server

On the authorization server, expose the resource handle from a `WorkerEntrypoint`. Fixing the resource there means one resource Worker can never ask about another's tokens:

```ts
import { WorkerEntrypoint } from 'cloudflare:workers';

const calendar = authorizationServer.resource('https://calendar.example.com/mcp');

export class CalendarTokenValidator extends WorkerEntrypoint<Env> {
  validateToken(token: string) {
    return calendar.validateToken(token, this.env);
  }
}
```

In the Calendar Worker, bind `AUTHORIZATION_SERVER` to that entrypoint:

```ts
import { createOAuthResourceServer, type OnlineTokenValidator } from '@cloudflare/workers-oauth-provider';

interface CalendarEnv {
  AUTHORIZATION_SERVER: OnlineTokenValidator<{ userId: string; scope: string[] }>;
}

export default createOAuthResourceServer<CalendarEnv, { userId: string; scope: string[] }>({
  resourceMetadata: {
    resource: 'https://calendar.example.com/mcp',
    authorization_servers: ['https://auth.example.com'],
    scopes_supported: ['calendar:read'],
  },
  validateToken: { online: (env) => env.AUTHORIZATION_SERVER },
  handler: {
    fetch: (_request, _env, ctx) =>
      ctx.props.scope.includes('calendar:read') ? Response.json(ctx.props) : new Response('Forbidden', { status: 403 }),
  },
});
```

The host rejects a validation whose `audience` is not its canonical resource, and answers `503` when validation infrastructure throws, including a missing binding.

## Issue JWTs from the authorization server

`createJwtAccessTokens()` builds the signer, the reader and the JWKS publisher. Installing it as `jwtAccessTokens` publishes `jwks_uri` and lets the server read its own JWTs alongside opaque tokens. Its `issuance` setting decides whether new access tokens are JWTs, and it is off by default so that readers always ship before the first JWT is written. Authorization codes and refresh tokens stay opaque regardless.

```ts
import { createJwtAccessTokens, OAuthAuthorizationServer, type JwtKeySet } from '@cloudflare/workers-oauth-provider';

interface AuthProps {
  userId: string;
  tenantId: string;
  upstreamAccessToken: string; // Confidential: never in publicClaims.
}

// A non-extractable signing key and its public JWK from your key store, loaded once per isolate.
declare function loadAccessTokenKeys(env: Env): Promise<JwtKeySet>;

const jwtAccessTokens = createJwtAccessTokens<Env, AuthProps>({
  issuer: 'https://auth.example.com',
  jwksUri: 'https://auth.example.com/.well-known/jwks.json',
  keys: loadAccessTokenKeys,
  publicClaims: ({ props }) => ({ tenantId: props.tenantId }), // the only way props reach the token
  issuance: ({ env, resource }) => env.JWT_ISSUANCE_ENABLED, // boolean, or a function per token
});

const authorizationServer = new OAuthAuthorizationServer<Env, AuthProps>({
  issuer: 'https://auth.example.com',
  resources: ['https://calendar.example.com/mcp'],
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  jwtAccessTokens,
});
```

The token:

```json
{
  "typ": "at+jwt",
  "alg": "RS256",
  "kid": "2026-09",
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "https://calendar.example.com/mcp",
  "client_id": "abc",
  "scope": "calendar:read",
  "iat": 1758000000,
  "exp": 1758003600,
  "jti": "…",
  "https://workers.cloudflare.com/oauth-provider/claims/grant-id": "…",
  "https://workers.cloudflare.com/oauth-provider/claims/public": { "tenantId": "t-1" }
}
```

Signed is not encrypted: everything above is readable by the client. `props` never enter the token unless `publicClaims` projects them, and there is no default projection because deployments commonly keep upstream credentials in `props`. The two claim URIs are exported as `JWT_ACCESS_TOKEN_GRANT_ID_CLAIM` and `JWT_ACCESS_TOKEN_PUBLIC_CLAIMS` for consumers that read the token without this package.

The authorization server keeps writing its encrypted token record, so `protectResource()`, `resource(uri).validateToken()`, token exchange and revocation see the full confidential `props` and behave as before.

### The key set

```ts
const keySet: JwtKeySet = {
  signingKey: { kid: '2026-09', alg: 'RS256', privateKey /* non-extractable CryptoKey */, publicJwk },
  verificationKeys: [previousPublicJwk], // staged or retiring keys, published but not used to sign
};
```

`keys(env)` runs on every issuance and every same-Worker verification. Import the private key once per isolate and return the memoised set. `RS256` and `ES256` are supported; RSA keys must be at least 2048 bits with an odd exponent of at least 3, and the public JWK must be the private key's pair, which the server proves once per key.

Rotate in this order:

1. Add the next public JWK to `verificationKeys` while the old key stays `signingKey`.
2. Wait at least the JWKS cache lifetime after publication, five minutes from the authorization server's `Cache-Control`, before signing with it.
3. Promote it to `signingKey` and move the retiring key's public JWK to `verificationKeys`.
4. Remove the retiring key once its last token has passed the maximum access-token lifetime plus cache time and clock skew.

## Offline: a resource Worker that verifies the JWT itself

```ts
import { createOAuthResourceServer } from '@cloudflare/workers-oauth-provider';

interface CalendarEnv {
  AUTHORIZATION_SERVER_JWKS: Fetcher; // fetch Service Binding to the authorization Worker, used only for its JWKS
}

export default createOAuthResourceServer<CalendarEnv, { userId: string; tenantId: string; scopes: string[] }>({
  resourceMetadata: {
    resource: 'https://calendar.example.com/mcp',
    authorization_servers: ['https://auth.example.com'],
    scopes_supported: ['calendar:read'],
  },
  validateToken: {
    offline: {
      issuer: 'https://auth.example.com',
      algorithms: ['RS256'], // required, never read from the token
      keys: {
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        fetcher: (env) => env.AUTHORIZATION_SERVER_JWKS,
      },
      mapClaimsToProps({ userId, scope, publicClaims }) {
        const tenantId =
          publicClaims !== null && typeof publicClaims === 'object' && !Array.isArray(publicClaims)
            ? publicClaims.tenantId
            : undefined;
        if (typeof tenantId !== 'string') return null; // an unexpected claim is an invalid token
        return { userId, tenantId, scopes: scope };
      },
    },
  },
  handler: {
    fetch: (_request, _env, ctx) => Response.json(ctx.props),
  },
});
```

`keys` names the authorization server's `jwks_uri`, optionally reached over a Service Binding so the fetch stays on Cloudflare's network; only the key set travels over it, never the token. The package fetches that URL and nothing a token names, caches the key set no longer than the response's `Cache-Control` allows, and refreshes for an unknown `kid` at most once per 30 seconds, because a `kid` is unauthenticated input from whoever presented the token. `keys` also accepts a resolver function `(env, { kid, alg }) => JwtPublicKey[]` for pinned or otherwise sourced keys.

The audience is the resource server's own `resourceMetadata.resource`. A token for another resource, another issuer, an algorithm outside `algorithms`, a `jku`/`jwk`/`x5u`/`x5c`/`b64` header, a missing required claim, or a signature by a key not in the JWKS is `invalid_token`. A JWKS that cannot be fetched or parsed is `503`, not `401`.

Offline verification cannot see a token or grant being revoked. Use short access-token lifetimes, or make `mapClaimsToProps` check application state, when that matters; otherwise validate `online`.

## Move an existing deployment to JWTs

Reader before writer, at every step:

1. Install `jwtAccessTokens` with `issuance` unset and deploy the authorization server. It publishes `jwks_uri`, serves the key that will sign, reads both formats, and still issues opaque tokens.
2. Deploy `offline` to each separate resource Worker, with `online` alongside it:

   ```ts
   validateToken: {
     offline: { /* as above */ },
     online: (env) => env.AUTHORIZATION_SERVER, // opaque tokens still in circulation
   }
   ```

3. Wait at least the JWKS cache lifetime, then turn `issuance` on: globally, or one resource at a time with `({ resource }) => resource === CALENDAR`. New tokens on every grant type become JWTs; live opaque tokens and refresh grants stay valid.
4. Once every issuer instance issues JWTs, keep `online` for the maximum access-token lifetime measured from the last opaque issuance, then remove it.

To roll back after that, restore `online` first, then turn `issuance` off. Keep `jwtAccessTokens`, its JWKS and every verification key until the last JWT has expired. Never deploy a version or configuration that cannot read a JWT that is still live.

`issuance` runs before an authorization code is consumed, a refresh token rotated or an enterprise assertion marked used. A policy that throws or returns a non-boolean fails that request with `server_error` and leaves the credential retryable; it never silently issues an opaque token instead.

## Reference

| Option                                   | Where                       | Notes                                                                                               |
| ---------------------------------------- | --------------------------- | --------------------------------------------------------------------------------------------------- |
| `issuer`, `jwksUri`                      | `createJwtAccessTokens`     | `issuer` must equal the authorization server's; `jwksUri` is served by it (`http` only on loopback) |
| `keys(env)`                              | `createJwtAccessTokens`     | Returns a `JwtKeySet`; memoise it                                                                   |
| `publicClaims(input)`                    | `createJwtAccessTokens`     | JSON to put in the client-readable public claim; omit to publish nothing                            |
| `issuance`                               | `createJwtAccessTokens`     | `boolean` or `({ env, resource }) => boolean`; default `false`                                      |
| `validateToken.online(env)`              | `createOAuthResourceServer` | Returns the Service Binding to a `WorkerEntrypoint` wrapping `resource(uri).validateToken()`        |
| `validateToken.offline.issuer`           | `createOAuthResourceServer` | Exact `iss`                                                                                         |
| `validateToken.offline.algorithms`       | `createOAuthResourceServer` | `RS256` and/or `ES256`; required                                                                    |
| `validateToken.offline.keys`             | `createOAuthResourceServer` | `{ jwksUri, fetcher?, cacheTtlSeconds? }` or a resolver function                                    |
| `validateToken.offline.mapClaimsToProps` | `createOAuthResourceServer` | Verified claims to `ctx.props`; return `null` to reject                                             |
