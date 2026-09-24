# Advanced configuration

This guide covers features that are useful for proxying another authorization system, changing token data during exchange, or operating the provider over time. Start with the main [README](../README.md) for MCP discovery, client registration, and a minimal Worker.

## Token exchange callback

`tokenExchangeCallback` runs during authorization code and refresh token exchanges. It is useful when the Worker also acts as an OAuth client to an upstream service.

```ts
new OAuthProvider({
  // Other options...
  tokenExchangeCallback: async (options) => {
    if (options.grantType === 'authorization_code') {
      const upstream = await exchangeUpstream(options.props.authorizationCode);
      return {
        accessTokenProps: {
          ...options.props,
          upstreamAccessToken: upstream.access_token,
        },
        newProps: {
          ...options.props,
          upstreamRefreshToken: upstream.refresh_token,
        },
        accessTokenTTL: upstream.expires_in,
      };
    }

    if (options.grantType === 'refresh_token') {
      const upstream = await refreshUpstream(options.props.upstreamRefreshToken);
      return {
        accessTokenProps: {
          ...options.props,
          upstreamAccessToken: upstream.access_token,
        },
        newProps: {
          ...options.props,
          upstreamRefreshToken: upstream.refresh_token,
        },
        accessTokenTTL: upstream.expires_in,
        // The upstream just issued a new refresh token; let this grant live as long as it does.
        refreshTokenIdleTTL: upstream.refresh_expires_in,
      };
    }
  },
});
```

The callback receives the grant type, client ID, user ID, grant ID, grant scopes, effective requested scopes, and decrypted props. It may return:

- `accessTokenProps` for the current access token.
- `newProps` for the grant and future refreshes.
- `accessTokenTTL` for the current access token.
- `refreshTokenTTL` during authorization code exchange.
- `refreshTokenIdleTTL` during refresh token exchange, to move the grant's expiry to that many seconds from now.
- `accessTokenScope` to narrow the current token.

Return nothing to keep the existing values. If `newProps` is returned without `accessTokenProps`, the current access token also uses `newProps`.

Throw `OAuthError` when an upstream failure should become an OAuth token response:

```ts
throw new OAuthError('temporarily_unavailable', {
  description: 'The upstream authorization server is rate limited',
  statusCode: 429,
  headers: { 'Retry-After': '60' },
});
```

Plain errors continue to surface as 500 responses.

## OAuth 2.0 Token Exchange

Set `allowTokenExchangeGrant: true` to enable RFC 8693. Clients can exchange an existing access token for a token with narrower scopes or a shorter lifetime. Token exchange cannot change the subject grant's registered canonical resource audience.

Application code can also call:

```ts
await env.OAUTH_PROVIDER.exchangeToken({
  subjectToken,
  scope: ['documents:read'],
  aud: 'https://mcp.example.com/mcp', // Must match the subject grant's resource
  expiresIn: 900,
});
```

The new token cannot exceed the subject token's scope ceiling or remaining lifetime. Its subject audience and any `aud` request value must resolve to the same registered resource. Subject-token failures return `invalid_request`, as RFC 8693 §2.2.2 requires.

A client must register `urn:ietf:params:oauth:grant-type:token-exchange` in its `grant_types` to use the grant at the token endpoint. A token is exchanged by the client its grant was issued to. Exchanging a token that another client obtained is rejected with `invalid_request` unless `tokenExchangeCallback` allows that specific exchange. The callback sees both parties, so the decision can be per client pair:

```ts
tokenExchangeCallback: (options) => {
  if (options.grantType === 'urn:ietf:params:oauth:grant-type:token-exchange') {
    // options.clientId is the exchanging client; options.subjectClientId issued the grant.
    const trusted = options.subjectClientId === options.clientId || DELEGATES.has(options.clientId);
    return { allowCrossClientExchange: trusted };
  }
},
```

## Enterprise-managed authorization

The token endpoint accepts a validated ID-JAG assertion using the JWT bearer grant and returns an opaque, resource-bound access token.

```ts
new OAuthProvider({
  // Other options...
  resourceMetadata: { resource: 'https://mcp.example.com/mcp' },
  enterpriseManagedAuthorization: {
    trustedIssuers: async ({ iss }) =>
      iss === 'https://idp.example.com'
        ? {
            issuer: iss,
            jwksUri: 'https://idp.example.com/.well-known/jwks.json',
            algorithms: ['RS256'],
          }
        : null,
    mapClaims: async ({ claims, requestedScope }) => ({
      userId: `enterprise-${encodeURIComponent(claims.sub)}`,
      scope: requestedScope,
      metadata: { issuer: claims.iss, subject: claims.sub },
      props: { subject: claims.sub, email: claims.email },
    }),
  },
});
```

The provider validates ID-JAG type, signature, issuer, audience, client binding, resource, timestamps, maximum lifetime, and replay identifier. The audience must be the authorization server issuer as a string or a single-element array. Assertions containing `authorization_details` or `cnf` fail closed until typed authorization-detail and DPoP processing are implemented. Refresh tokens are not issued for this grant.

The grant requires client authentication by default. Set `allowPublicClients: true` only when public clients, including CIMD clients, must use it and the ID-JAG trust model is appropriate for the deployment.

The default replay marker uses KV and is best effort across Cloudflare locations because KV is eventually consistent. Signature checks, short assertion lifetime, audience, resource, and client binding limit the replay window. The package does not currently expose a custom replay store, so do not describe ID-JAG redemption as globally single-use.

## Client registration policy

`clientRegistrationCallback` runs before a DCR client is stored. Return nothing to allow registration, or return an object to reject it:

```ts
clientRegistrationCallback: async ({ clientMetadata, request }) => {
  if (!(await registrationIsAllowed(clientMetadata, request))) {
    return {
      code: 'access_denied',
      description: 'Client registration is not permitted',
      status: 403,
    };
  }
};
```

The callback receives raw client metadata and a clone of the request whose body can still be read. If `software_statement` is present, the application is responsible for verifying it and applying its claims.

`disallowPublicClientRegistration` affects DCR only. It does not prevent administrative code from creating a public client through `OAuthHelpers.createClient()`.

## CIMD fetch errors

A client ID Metadata Document can fail because of a timeout, network error, upstream response, or invalid document. Those failures are different from a client that does not exist.

At the token endpoint, the provider keeps the wire response generic as `invalid_client`. It sends the diagnostic reason to `onError.internal` with category `client-id-metadata-document`, stable reason `metadata_resolution_failed`, the metadata URL, and the underlying message.

`OAuthHelpers.lookupClient()`, `parseAuthRequest()`, `completeAuthorization()`, and `exchangeToken()` throw the exported `CimdFetchError` when they cannot resolve a CIMD client. `lookupClient()` returns `null` only when the client does not exist:

```ts
import { CimdFetchError } from '@cloudflare/workers-oauth-provider';

try {
  const client = await env.OAUTH_PROVIDER.lookupClient(clientId);
} catch (error) {
  if (error instanceof CimdFetchError) {
    console.error(error.reason, error.metadataUrl, error.detail);
  }
  throw error;
}
```

Do not log credentials or request bodies when recording these failures.

## Custom error responses

`onError` runs whenever the provider is about to return an OAuth error. Use it for logging or monitoring:

```ts
new OAuthProvider({
  // Other options...
  onError({ code, description, status, headers, internal }) {
    console.warn({ code, description, status, headers, internal });
  },
});
```

Return a `Response` to replace the default response. Return nothing to use the provider's RFC-formatted response.

### The internal reason

Every OAuth error response the library builds — everything `onError` observes — carries `internal: { category, reason, detail? }`: the exact check that failed, which the wire response deliberately does not reveal (RFC 6749 §5.2). Bare non-OAuth responses (the credential-less `401` challenge, `404`/`405` on metadata URLs) carry no OAuth error and do not run `onError`. It exists only on the path to `onError` and is never sent to the client, so `error_description` can stay generic while logs and alerting key on stable slugs instead of matching text:

```ts
onError({ code, internal }) {
  metrics.increment(`oauth.${internal.category}.${internal.reason}`);
},
```

`category` names the subsystem (kebab-case), `reason` the failed check (snake_case); both are stable across versions — treat additions like new enum members. `detail`, when present, carries structured context such as the caught error, a CIMD fetch diagnosis, or the offending parameter name; it never carries a secret.

| Category                           | Examples of `reason`                                                                                |
| ---------------------------------- | --------------------------------------------------------------------------------------------------- |
| `token-endpoint-request`           | `method_not_allowed`, `repeated_parameter`, `grant_type_not_supported`, `grant_type_not_registered` |
| `client-authentication`            | `client_not_found`, `client_secret_mismatch`, `multiple_authentication_methods`                     |
| `client-id-metadata-document`      | `metadata_resolution_failed` and the other typed CIMD reasons                                       |
| `authorization-code-grant`         | `code_replayed`, `code_verifier_mismatch`, `redirect_uri_mismatch`, `grant_not_found`               |
| `refresh-token-grant`              | `refresh_token_mismatch`, `refresh_token_expired`, `client_mismatch`, `grant_not_found`             |
| `token-exchange-grant`             | `subject_token_invalid`, `subject_token_near_expiry`, `requested_ttl_too_short`                     |
| `enterprise-managed-authorization` | the typed EMA validator reasons (`signature_failed`, `replayed`, `aud_mismatch`, …)                 |
| `resource-indicator`               | `resource_not_configured`, `resource_grant_mismatch`, `legacy_grant_unbound`                        |
| `token-issuance`                   | `kv_rate_limited`, `requested_ttl_too_short`                                                        |
| `token-revocation`                 | `token_missing`                                                                                     |
| `client-registration`              | `json_malformed`, `metadata_invalid`, `callback_denied`, `payload_too_large`                        |
| `protected-resource`               | `token_not_found`, `token_expired`, `audience_mismatch`, `resolver_rejected`                        |
| `token-exchange-callback`          | `callback_error` — an `OAuthError` thrown by a deployer callback without its own `internal`         |

`OAuthError(code, options)` supports token-endpoint errors from `tokenExchangeCallback`. `ExternalTokenError(code, options)` supports protected-resource errors from `resolveExternalToken`, including `requiredScopes` for an `insufficient_scope` challenge.

Both classes accept a public `description`, `statusCode`, and response `headers`. Only the exported class intended for that callback boundary is converted. Other errors remain unexpected failures. An `OAuthError` may also set `options.internal` to give `onError` its own category and reason; without one it arrives as `{ category: 'token-exchange-callback', reason: 'callback_error', detail: error }`.

## Token and client lifetimes

| Option                  | Default           | Notes                                                                               |
| ----------------------- | ----------------- | ----------------------------------------------------------------------------------- |
| `accessTokenTTL`        | 3,600 seconds     | Must be at least 60 seconds because of KV limits                                    |
| `refreshTokenTTL`       | 2,592,000 seconds | 30 days; set to `0` to disable refresh tokens; explicit `undefined` means no expiry |
| `refreshTokenIdleTTL`   | unset             | Sliding expiry: each successful refresh moves the grant's expiry this far out       |
| `clientRegistrationTTL` | 7,776,000 seconds | 90 days for DCR clients, renewed while in use; explicit `undefined` means no expiry |

A refresh rotates the token. The newly issued token and the immediately previous token can both recover a refresh whose response was lost. Once the new token is used, the previous token is invalidated and another token is issued.

Per-token `accessTokenTTL` and `refreshTokenTTL` overrides are available through `tokenExchangeCallback`.

### Sliding expiry

By default a grant's lifetime is fixed at the code exchange: it expires `refreshTokenTTL` seconds later no matter how often it is refreshed, which is the right policy when users must re-authenticate on a schedule. A Worker that proxies an upstream OAuth service usually wants the opposite: the grant should live as long as the upstream credentials it holds, and no longer.

`refreshTokenIdleTTL` makes the lifetime slide. Every successful refresh moves the grant's expiry, and the KV expiration of its record, to that many seconds after the refresh. `refreshTokenTTL` still sets a new grant's lifetime, so "30 days to start, then at least weekly" is `refreshTokenTTL: 30 * 86400` with `refreshTokenIdleTTL: 7 * 86400`. A grant that never expired keeps that status until its first refresh, after which it too idles out.

Returning `refreshTokenIdleTTL` from `tokenExchangeCallback` sets the lifetime for that one refresh and overrides the option, as in the example above. It sets rather than extends, so returning the upstream's remaining lifetime makes the grant track it exactly; return nothing when the upstream did not rotate and the option, or the fixed lifetime, applies.

The slide is committed by the same grant write that rotates the refresh token. A callback that throws fails the refresh before that write, so a failed upstream refresh never renews the downstream grant. A grant that has already expired, including one that expires while a slow callback runs, is rejected with `invalid_grant` and is not revived. If the access-token write after the grant write fails, the grant is already rotated and extended, and the client's previous refresh token is still valid to retry with; that retry slides the expiry again.

There is no built-in absolute maximum. A grant with `refreshTokenTTL: undefined` already lives indefinitely, and the callback is the place for lifetime policy: record the authorization time in `props` when the grant is created, and return a shrinking `refreshTokenIdleTTL`, or throw, once the grant is older than you allow.

## KV cleanup

KV TTLs remove expiring records automatically. `purgeExpiredData()` provides a defense-in-depth sweep for orphaned or expired grants and tokens:

```ts
const provider = new OAuthProvider({
  // Options...
});

export default {
  fetch(request, env, ctx) {
    return provider.fetch(request, env, ctx);
  },
  async scheduled(_event, env) {
    const result = await provider.purgeExpiredData(env, { batchSize: 100 });
    console.log(result);
  },
};
```

The default batch size is 50. `result.done` reports whether both key spaces were scanned completely during that invocation.

Deleting a client through `OAuthHelpers.deleteClient()` also revokes its grants and associated tokens across users.

## Multiple protected handlers

Use `apiHandlers` when different route prefixes need different handlers:

```ts
new OAuthProvider({
  apiHandlers: {
    '/api/users/': UsersApiHandler,
    '/api/documents/': DocumentsApiHandler,
    'https://api.example.com/': ExternalApiHandler,
  },
  // Other options...
});
```

Use either `apiHandlers` or `apiRoute` plus `apiHandler`, not both. Routes can be paths or full URLs.

## Helper access outside fetch

`getOAuthApi(options, env)` returns `OAuthHelpers` for RPC methods and other Worker entrypoints that do not receive the injected `env.OAUTH_PROVIDER` value.

## External token resolution

`resolveExternalToken` accepts a bearer credential that was not issued or stored by this provider. It runs only after the internal token lookup fails. The credential can be an external OAuth access token, opaque API key, or personal access token (PAT).

### MCP compatibility warning

This is an advanced compatibility feature, not the normal MCP authorization flow. The MCP 2026-07-28 specification says:

- MCP clients must not send tokens other than ones issued by the MCP server's authorization server.
- MCP servers must accept only tokens intended for their own resource.
- If an MCP server calls an upstream API, it must use a separate upstream token and must not forward the token received from the MCP client.

Accepting an API key minted by an upstream API directly at the MCP endpoint therefore falls outside the MCP authorization profile. Setting `audience` in the callback applies the provider's local resource policy, but it does not change who issued the credential or make an upstream API key MCP-compliant.

Some deployments intentionally use this compatibility pattern so users can present API keys minted by an existing upstream API. `resolveExternalToken` supports that choice, including validation through a trusted upstream endpoint and passing derived identity or permissions to the protected handler. If the handler forwards the same key to access upstream application data, that is token passthrough under the MCP security guidance and must not be described as MCP-conformant.

The preferred MCP design is to issue a local, audience-bound access token for the MCP server and keep any separate upstream credential in encrypted `props`. When compatibility requires direct upstream keys, restrict validation and use to fixed upstream hosts, request the narrowest permissions possible, never log the key, do not include it in errors or metadata, and make the non-conformant trust model explicit to operators.

### Validating an upstream API key

```ts
import { ExternalTokenError, OAuthProvider } from '@cloudflare/workers-oauth-provider';

const MCP_RESOURCE = 'https://mcp.example.com/mcp';

new OAuthProvider({
  // Other options...
  resourceMetadata: { resource: MCP_RESOURCE },

  resolveExternalToken: async ({ token, request, env }) => {
    const result = await validateUpstreamApiKey(token, request, env);

    if (result.kind === 'invalid') return null;
    if (result.kind === 'insufficient_scope') {
      throw new ExternalTokenError('insufficient_scope', {
        description: 'The API key needs account:read permission',
        statusCode: 403,
        requiredScopes: ['account:read'],
      });
    }
    if (result.kind === 'rate_limited') {
      throw new ExternalTokenError('temporarily_unavailable', {
        description: 'API key validation is temporarily rate limited',
        statusCode: 429,
        headers: { 'Retry-After': result.retryAfter },
      });
    }

    return {
      props: {
        upstreamSubject: result.subject,
        permissions: result.permissions,
      },

      // An opaque key has no MCP audience claim. This is an explicit local
      // policy binding applied only after successful validation.
      audience: MCP_RESOURCE,
    };
  },
});
```

The callback can:

- Return `{ props, audience }` to authenticate. The audience is required, must be a single string, and must identify the configured canonical `resourceMetadata.resource`; scheme and host comparisons are ASCII case-insensitive and an empty path equals `/`, while port, path, query, and trailing slash are strict. An array is rejected.
- Return `null` for a generic `401 invalid_token` response.
- Throw the exported `ExternalTokenError` for an intentional structured response.

`audience` means the local protected resource where the credential is accepted. It does not mean the issuer, user, upstream API, or permissions. For an opaque key, the callback supplies this as a local policy decision after validation. Do not use an upstream API URL as the audience for requests to the Worker.

Unexpected errors, plain objects, `OAuthError`, and app-local lookalike classes are re-thrown so validator bugs remain visible as 500 responses. Existing callback behavior is unchanged unless the callback deliberately throws this package's `ExternalTokenError`.

References:

- [MCP access token handling](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#token-handling)
- [MCP access token privilege restriction](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#access-token-privilege-restriction)
