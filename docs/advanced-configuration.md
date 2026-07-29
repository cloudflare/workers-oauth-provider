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

Set `allowTokenExchangeGrant: true` to enable RFC 8693. Clients can exchange an existing access token for a token with narrower scopes, a permitted resource, or a shorter lifetime.

Application code can also call:

```ts
await env.OAUTH_PROVIDER.exchangeToken({
  subjectToken,
  scope: ['documents:read'],
  aud: 'https://api.example.com/documents',
  expiresIn: 900,
});
```

The new token cannot exceed the subject token's scope ceiling, permitted resources, or remaining lifetime.

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

`OAuthError(code, options)` supports token-endpoint errors from `tokenExchangeCallback`. `ExternalTokenError(code, options)` supports protected-resource errors from `resolveExternalToken`, including `requiredScopes` for an `insufficient_scope` challenge.

Both classes accept a public `description`, `statusCode`, and response `headers`. Only the exported class intended for that callback boundary is converted. Other errors remain unexpected failures.

## Token and client lifetimes

| Option                  | Default           | Notes                                                                               |
| ----------------------- | ----------------- | ----------------------------------------------------------------------------------- |
| `accessTokenTTL`        | 3,600 seconds     | Must be at least 60 seconds because of KV limits                                    |
| `refreshTokenTTL`       | 2,592,000 seconds | 30 days; set to `0` to disable refresh tokens; explicit `undefined` means no expiry |
| `clientRegistrationTTL` | 7,776,000 seconds | 90 days for DCR clients; explicit `undefined` means no expiry                       |

A refresh rotates the token. The newly issued token and the immediately previous token can both recover a refresh whose response was lost. Once the new token is used, the previous token is invalidated and another token is issued.

Per-token `accessTokenTTL` and `refreshTokenTTL` overrides are available through `tokenExchangeCallback`.

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

- Return `{ props, audience }` to authenticate. If `resourceMetadata.resource` is configured, the audience is required and must exactly match it.
- Return `{ props }` when no explicit resource is configured. The provider applies its origin-bound default resource policy.
- Return `null` for a generic `401 invalid_token` response.
- Throw the exported `ExternalTokenError` for an intentional structured response.

`audience` means the local protected resource where the credential is accepted. It does not mean the issuer, user, upstream API, or permissions. For an opaque key, the callback supplies this as a local policy decision after validation. Do not use an upstream API URL as the audience for requests to the Worker.

Unexpected errors, plain objects, `OAuthError`, and app-local lookalike classes are re-thrown so validator bugs remain visible as 500 responses. Existing callback behavior is unchanged unless the callback deliberately throws this package's `ExternalTokenError`.

References:

- [MCP access token handling](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#token-handling)
- [MCP access token privilege restriction](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#access-token-privilege-restriction)
