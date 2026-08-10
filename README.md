# OAuth 2.1 Provider Framework for Cloudflare Workers

`@cloudflare/workers-oauth-provider` adds OAuth 2.1 authorization to HTTP APIs and remote MCP servers running on Cloudflare Workers.

## Install

```sh
npm install @cloudflare/workers-oauth-provider
```

The Worker needs a KV namespace bound as `OAUTH_KV`:

```jsonc
{
  "kv_namespaces": [
    {
      "binding": "OAUTH_KV",
      "id": "YOUR_KV_NAMESPACE_ID",
    },
  ],
}
```

To enable Client ID Metadata Documents, also add Cloudflare's SSRF protection compatibility flag:

```jsonc
{
  "compatibility_flags": ["global_fetch_strictly_public"],
}
```

See [Client registration](#client-registration) for the matching provider option.

## Quick start

The provider accepts either plain `ExportedHandler` objects or classes extending `WorkerEntrypoint`. This example uses both.

```ts
import {
  AuthorizationError,
  OAuthProvider,
  type AuthRequest,
  type OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { WorkerEntrypoint } from 'cloudflare:workers';

interface AuthProps {
  userId: string;
  displayName: string;
}

interface Env {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
}

class McpApiHandler extends WorkerEntrypoint<Env, AuthProps> {
  fetch(request: Request): Response {
    return Response.json({
      authenticated: true,
      userId: this.ctx.props.userId,
      displayName: this.ctx.props.displayName,
    });
  }
}

const defaultHandler: ExportedHandler<Env> = {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname !== '/authorize') {
      return new Response('Not found', { status: 404 });
    }

    // This parses the OAuth parameters and validates the client, redirect URI,
    // response type, resource indicators, and configured PKCE restrictions.
    let oauthRequest: AuthRequest;
    try {
      oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
    } catch (error) {
      if (!(error instanceof AuthorizationError)) throw error;
      if (!error.redirectUri) {
        // Unknown clients and invalid redirects must be rendered locally.
        return new Response(error.description, { status: 400 });
      }
      const redirect = new URL(error.redirectUri);
      redirect.searchParams.set('error', error.code);
      redirect.searchParams.set('error_description', error.description);
      if (error.state) redirect.searchParams.set('state', error.state);
      if (error.issuer) redirect.searchParams.set('iss', error.issuer);
      return Response.redirect(redirect, 302);
    }

    const client = await env.OAUTH_PROVIDER.lookupClient(oauthRequest.clientId);

    if (!client) {
      return new Response('Unknown OAuth client', { status: 400 });
    }

    // Authenticate the user and obtain consent here. Do not automatically
    // approve a request in production. This example assumes those steps have
    // produced the following user and scope values.
    const user = { id: 'user-123', displayName: 'Ada' };
    const grantedScopes = oauthRequest.scope.filter((scope) => scope === 'mcp:read');

    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthRequest,
      userId: user.id,
      metadata: { clientName: client.clientName },
      scope: grantedScopes,
      props: {
        userId: user.id,
        displayName: user.displayName,
      },
    });

    return Response.redirect(redirectTo, 302);
  },
};

export default new OAuthProvider<Env>({
  apiRoute: '/mcp',
  apiHandler: McpApiHandler,
  defaultHandler,

  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',

  scopesSupported: ['mcp:read'],

  resourceMetadata: {
    resource: 'https://mcp.example.com/mcp',
    authorization_servers: ['https://mcp.example.com'],
    scopes_supported: ['mcp:read'],
    resource_name: 'Example MCP server',
  },

  // Preferred for clients with no pre-existing relationship.
  // Also requires global_fetch_strictly_public in wrangler.jsonc.
  clientIdMetadataDocumentEnabled: true,

  // Optional compatibility fallback. MCP 2026 deprecates DCR for new clients.
  clientRegistrationEndpoint: '/oauth/register',
});
```

## Protecting routes

`apiRoute` and `apiHandler` protect one or more route prefixes with a single handler. Use `apiHandlers` when different prefixes need different handlers.

Before calling a protected handler, the provider reads the bearer token, rejects missing, invalid, or expired credentials, checks its audience, and exposes the authenticated application data through `ctx.props`. The handler does not need to parse or validate the token, but it must still enforce application permissions such as scope, ownership, and tenancy.

Requests outside the protected route prefixes go to `defaultHandler`. In the example above, that handler owns `/authorize`.

## How MCP authorization discovery works

An MCP client discovers authorization in two stages, following the [MCP authorization server discovery rules](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery).

For an MCP endpoint at `https://mcp.example.com/mcp`:

1. The client sends an unauthenticated request to `/mcp`.
2. The provider returns `401 Unauthorized` with a challenge similar to:

   ```http
   WWW-Authenticate: Bearer realm="OAuth", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
   ```

3. The client fetches the protected resource metadata:

   ```text
   https://mcp.example.com/.well-known/oauth-protected-resource/mcp
   ```

4. That document identifies one or more authorization server issuers through `authorization_servers`.
5. The client fetches this provider's RFC 8414 authorization server metadata:

   ```text
   https://mcp.example.com/.well-known/oauth-authorization-server
   ```

6. The metadata tells the client where to authorize, exchange tokens, and register if registration is enabled.

Protected resource metadata and authorization server metadata serve different roles:

- Protected resource metadata describes the MCP server and identifies its authorization servers.
- Authorization server metadata describes OAuth endpoints and capabilities such as PKCE and CIMD.

### Protected resource metadata

The provider always serves RFC 9728 metadata at:

```text
/.well-known/oauth-protected-resource
```

It also supports path-specific metadata. A request to:

```text
/.well-known/oauth-protected-resource/public/mcp
```

produces `https://example.com/public/mcp` as the derived resource unless `resourceMetadata.resource` overrides it.

For MCP deployments, configure the canonical MCP endpoint explicitly:

```ts
resourceMetadata: {
  resource: 'https://mcp.example.com/mcp',
  authorization_servers: ['https://auth.example.com'],
  scopes_supported: ['files:read'],
  bearer_methods_supported: ['header'],
  resource_name: 'Files MCP server',
}
```

`authorization_servers` may contain more than one issuer. The MCP client chooses an authorization server and must keep credentials and tokens separate for each issuer.

### Authorization server metadata

The provider publishes RFC 8414 metadata containing:

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `registration_endpoint`, when DCR is enabled
- supported response and grant types
- token endpoint authentication methods
- PKCE methods
- revocation endpoint
- RFC 9207 issuer support
- CIMD support when it is enabled and safe to use

The package serves RFC 8414 metadata rather than OpenID Connect discovery. MCP authorization servers need to provide at least one of those mechanisms, so RFC 8414 is sufficient.

## Authorization endpoint

Your `authorizeEndpoint` belongs to the application's `defaultHandler` because user authentication and consent are application-specific. The provider is not an identity provider.

A typical flow has three steps:

1. Call `parseAuthRequest(request)` to validate the client, redirect URI, response type, resource, and PKCE restrictions.
2. Authenticate the user, show consent, and decide which scopes to grant.
3. Call `completeAuthorization()` and redirect to its returned `redirectTo` URL.

`parseAuthRequest()` throws an exported `AuthorizationError` for expected request validation failures. Its optional `redirectUri` is present only after the client and exact registered redirect URI have been validated. Without it, render the error locally and never redirect. With it, the application can safely construct an OAuth error redirect using the error's `code`, `description`, original `state`, and RFC 9207 `issuer`, as shown in the quick start.

`completeAuthorization()` repeats response-type validation before writing a grant or revoking existing grants. Validation errors from reconstructed requests are also typed as `AuthorizationError`, but applications should not construct redirects from untrusted reconstructed values; the redirect context is attached only by `parseAuthRequest()`.

`completeAuthorization()` stores a new grant and, by default, revokes existing grants for the same user and client after the new grant is safely stored. Set `revokeExistingGrants: false` only when the application intentionally allows concurrent grants for the same user and client.

For Client ID Metadata Document clients, whose client_id is the metadata URL shared by every installation, default revocation is additionally scoped to grants created from the same redirect URI, so one installation's re-authorization does not revoke another's. Grants created before the redirect URI was recorded are never auto-revoked by CIMD clients.

For users with many grants, `revokeExistingGrantsBatchSize` controls the KV page size used during that scan. It defaults to `50` and is capped at KV's maximum page size of `1000`.

### Authorization response issuer

RFC 9207 issuer identification is always enabled. Authorization server metadata advertises `authorization_response_iss_parameter_supported: true`, and successful authorization responses include `iss` automatically.

`parseAuthRequest()` returns the expected `issuer`. If the application creates a terminal OAuth error redirect, include that value:

```ts
const oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
const redirect = new URL(oauthRequest.redirectUri);
redirect.searchParams.set('error', 'access_denied');
redirect.searchParams.set('state', oauthRequest.state);
if (oauthRequest.issuer) redirect.searchParams.set('iss', oauthRequest.issuer);
return Response.redirect(redirect.toString(), 302);
```

Intermediate identity-provider redirects and local HTML error pages do not need the OAuth `iss` parameter.

## Client registration

[MCP client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration) defines three ways for a client to obtain a client ID. Clients that support all three prefer pre-registration, then CIMD, then DCR.

### Pre-registered clients

Use `OAuthHelpers.createClient()` to create clients through application or administrative code. These clients are stored in KV and are not subject to `clientRegistrationTTL`.

### Client ID Metadata Documents

CIMD lets a client use an HTTPS URL with a non-root path as its `client_id`. That URL serves a JSON metadata document describing the client and its redirect URIs.

Enable it in both places:

```ts
new OAuthProvider({
  // Other options...
  clientIdMetadataDocumentEnabled: true,
});
```

```jsonc
{
  "compatibility_flags": ["global_fetch_strictly_public"],
}
```

The compatibility flag prevents outbound CIMD fetches from using legacy same-zone origin routing, which is necessary for SSRF protection. The provider advertises `client_id_metadata_document_supported: true` only when both settings are present. CIMD fetches also use the `cache` option of `fetch`, which requires a compatibility date of `2024-11-11` or later (or the `cache_option_enabled` compatibility flag).

CIMD validation follows [draft-ietf-oauth-client-id-metadata-document-00](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00) — the revision pinned by the MCP 2026-07-28 authorization spec — and includes:

- An HTTPS Client Identifier URL with a path component and no userinfo, fragment, or dot path segments.
- A document `client_id` exactly matching its URL.
- Non-empty `client_name` and `redirect_uris` fields, as MCP requires, with unsafe redirect schemes rejected at ingestion.
- Exact authorization-request redirect URI validation, with RFC 8252 loopback port handling.
- A 5 KB response size limit and a 10 second timeout covering both headers and body.
- Valid UTF-8 JSON object syntax and safe URI schemes for client metadata fields.
- No embedded client secrets or private JWK material.

Validated documents are cached according to their `Cache-Control` headers, capped at 7 days. Error responses and invalid documents are never cached, and a cached document that stops validating is evicted and re-resolved from origin within the same request.

CIMD token endpoint authentication is negotiated from `token_endpoint_auth_method` and the OpenID RP Metadata Choices field `token_endpoint_auth_methods_supported`. The provider currently implements only `none`: a client may prefer `private_key_jwt` while also offering `none`, in which case the provider selects `none` and applies public-client PKCE requirements. A client that offers only `private_key_jwt` is rejected until assertion validation is implemented.

When a CIMD document cannot be fetched or validated, the token endpoint returns a generic `invalid_client` response and reports diagnostics through `onError.internal`. `OAuthHelpers` methods that resolve a CIMD client throw the exported `CimdFetchError`, allowing applications to distinguish an upstream metadata failure from a client that does not exist. See [Advanced configuration](https://github.com/cloudflare/workers-oauth-provider/blob/main/docs/advanced-configuration.md#cimd-fetch-errors) for an example.

### Dynamic Client Registration

Set `clientRegistrationEndpoint` to enable RFC 7591 Dynamic Client Registration:

```ts
clientRegistrationEndpoint: '/oauth/register';
```

MCP 2026-07-28 deprecates DCR for new implementations in favor of CIMD. The endpoint remains useful for compatibility with clients that do not support CIMD.

Registration accepts only authentication methods, grants, and response types implemented by the configured provider, and rejects inconsistent grant/response combinations before storage. Choice-valued `token_endpoint_auth_methods_supported` input is negotiated to one effective `token_endpoint_auth_method`; grant and response registrations remain strict. Omitted metadata uses the RFC 7591 defaults: `client_secret_basic`, `grant_types: ["authorization_code"]`, and `response_types: ["code"]`.

The effective `token_endpoint_auth_method` returned by registration is enforced exactly. When both authentication metadata fields are omitted, no explicit-method marker is stored and the client may use either `client_secret_basic` or `client_secret_post`, provided the same stored secret validates. Client records written by earlier releases have no marker and receive the same compatibility. This never crosses between `none` and a secret method and does not apply to CIMD clients.

Calling `OAuthHelpers.updateClient()` with `tokenEndpointAuthMethod` adds the marker; unrelated updates leave it unchanged.

Related options:

- `clientRegistrationTTL` controls the lifetime of dynamically registered clients. The default is 90 days.
- `disallowPublicClientRegistration` rejects DCR clients using `token_endpoint_auth_method: "none"`.
- `clientRegistrationCallback` can allow or reject registration based on application policy.

Clients created by `OAuthHelpers.createClient()` are not affected by the DCR TTL or public-registration restriction.

## PKCE and token lifecycle

Public clients must use PKCE with authorization code flow. PKCE challenges use only S256 by default. Confidential clients may still omit PKCE.

Legacy deployments with clients that cannot use S256 can opt back into plain PKCE:

```ts
allowPlainPKCE: true;
```

`allowImplicitFlow` defaults to `false`; leave it disabled for MCP and other new OAuth deployments.

The provider owns `tokenEndpoint`. It exchanges authorization codes for tokens, refreshes access tokens, and handles RFC 7009 revocation. Refresh tokens rotate on use. The immediately previous token remains valid until its replacement is first used, allowing a client to retry after losing a refresh response.

## Resources and token audiences

MCP clients are required to send the canonical MCP server URI as `resource` in authorization and token requests. The provider tolerates omission for compatibility: when `resourceMetadata.resource` is configured, it is used as the canonical default and inherited by later token requests; otherwise a token request inherits any resource already stored on the grant. An explicit resource that does not match a bound grant is rejected with `invalid_target`.

Legacy grants may have no stored resource. With no configured canonical resource, omitting `resource` preserves that unbound state. If a client supplies a resource during code exchange or refresh, it applies to that issued token but is not persisted as a new grant binding. Path-aware audiences use path-boundary prefix matching, so a token for `https://example.com/mcp` can be used at `/mcp/tools`, but not at `/mcp-other`.

`resourceMatchOriginOnly` is deprecated; its existing behavior is unchanged. Prefer `resourceMetadata.resource` for new deployments.

## Scopes and step-up authorization

`scopesSupported` is published only in authorization server metadata. Configure `resourceMetadata.scopes_supported` explicitly with the minimal scopes required for basic protected-resource functionality and baseline Bearer challenges.

The application decides which requested scopes to grant through `completeAuthorization({ scope })`. Token and refresh requests can only narrow those scopes.

The provider does not expose a standard effective-token authorization context to API handlers or enforce operation-level scope policy. Protected resource metadata supplies baseline scope guidance in Bearer challenges. Advanced integrations can provide operation-specific step-up guidance through external-token validation.

## Advanced features

The package also supports:

- External API keys and bearer credentials through `resolveExternalToken` as an advanced compatibility feature.
- Updating encrypted props, token scope, and token lifetimes with `tokenExchangeCallback`.
- OAuth 2.0 Token Exchange when `allowTokenExchangeGrant` is enabled.
- Structured callback errors through the exported `OAuthError` and `ExternalTokenError` classes.
- Custom error observation or responses through `onError`.
- Experimental MCP Enterprise-Managed Authorization using ID-JAG assertions.
- Multiple protected handlers through `apiHandlers`.
- Configurable access token, refresh token, and DCR client lifetimes.

See [Advanced configuration](https://github.com/cloudflare/workers-oauth-provider/blob/main/docs/advanced-configuration.md) for examples and security notes.

## KV storage and cleanup

Sensitive values are not stored in plaintext:

- Access tokens, refresh tokens, authorization codes, and client secrets are stored only by hash.
- `props` are encrypted with AES-GCM using key material wrapped by the corresponding secret token.
- Grant `userId` and `metadata` are not encrypted because applications use them to enumerate and revoke grants. Treat those fields as storage-visible metadata.

See [storage-schema.md](https://github.com/cloudflare/workers-oauth-provider/blob/main/storage-schema.md) for the complete KV layout.

KV TTLs remove expiring records automatically. `purgeExpiredData()` provides a manual sweep for orphaned or expired grants and tokens:

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

## Configuration reference

| Option                             | Purpose                                                  | Default                                     |
| ---------------------------------- | -------------------------------------------------------- | ------------------------------------------- |
| `apiRoute` and `apiHandler`        | Protect one or more route prefixes with one handler      | Use these or `apiHandlers`                  |
| `apiHandlers`                      | Map protected route prefixes to different handlers       | Use this or `apiRoute` plus `apiHandler`    |
| `defaultHandler`                   | Handle authorization UI and other unprotected routes     | Required                                    |
| `authorizeEndpoint`                | Application-owned authorization and consent endpoint     | Required                                    |
| `tokenEndpoint`                    | Provider-owned token and revocation endpoint             | Required                                    |
| `clientRegistrationEndpoint`       | Enable RFC 7591 DCR                                      | Disabled                                    |
| `scopesSupported`                  | Publish authorization server scopes                      | Omitted                                     |
| `resourceMetadata`                 | Configure RFC 9728 metadata                              | Derived from the request and token endpoint |
| `clientIdMetadataDocumentEnabled`  | Enable CIMD lookup and advertisement                     | `false`                                     |
| `allowPlainPKCE`                   | Permit the legacy plain PKCE method                      | `false`                                     |
| `allowImplicitFlow`                | Enable implicit token responses                          | `false`                                     |
| `disallowPublicClientRegistration` | Reject public clients at DCR                             | `false`                                     |
| `clientRegistrationCallback`       | Apply application policy before storing a DCR client     | None                                        |
| `allowTokenExchangeGrant`          | Enable RFC 8693                                          | `false`                                     |
| `tokenExchangeCallback`            | Update props, scopes, or lifetimes during token exchange | None                                        |
| `resolveExternalToken`             | Validate external bearer credentials (advanced)          | None                                        |
| `resourceMatchOriginOnly`          | Deprecated origin-only resource comparison               | `false`                                     |
| `enterpriseManagedAuthorization`   | Enable experimental ID-JAG grant support                 | Disabled                                    |
| `onError`                          | Observe or replace OAuth error responses                 | Logs a warning                              |

Consult the exported `OAuthProviderOptions`, callback interfaces, and JSDoc in [`src/oauth-provider.ts`](https://github.com/cloudflare/workers-oauth-provider/blob/main/src/oauth-provider.ts) for the complete typed API.

## OAuth helpers

Handlers receive `env.OAUTH_PROVIDER`, which implements `OAuthHelpers`. It can:

- Parse authorization requests and complete authorization.
- Look up, create, list, update, and delete clients.
- List and revoke grants for a user.
- Inspect internally issued tokens with `unwrapToken()`.
- Exchange access tokens when RFC 8693 is enabled.
- Purge expired and orphaned KV data.

`getOAuthApi(options, env)` provides the same helper API outside a fetch handler, including RPC methods and other Worker entrypoints.

## Standards

The package implements or supports the relevant portions of:

- [MCP authorization, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [OAuth 2.1, draft-ietf-oauth-v2-1-13](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [OAuth 2.0 Bearer Token Usage, RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750)
- [OAuth 2.0 Token Revocation, RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)
- [OAuth 2.0 Dynamic Client Registration, RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)
- [Proof Key for Code Exchange, RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.0 Authorization Server Metadata, RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)
- [OAuth 2.0 Token Exchange, RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)
- [Resource Indicators for OAuth 2.0, RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)
- [OAuth 2.0 Authorization Server Issuer Identification, RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207)
- [OAuth 2.0 Protected Resource Metadata, RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)
- [OAuth Client ID Metadata Documents](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00)
- [OpenID Connect RP Metadata Choices 1.0](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html)
- [MCP Enterprise-Managed Authorization](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization), with experimental package support

## Development

Node 24 or newer is required.

```sh
npm install
npm run build
npm run check
npm run prettier
```

Changes that affect behavior or the public API need a Changeset. See [AGENTS.md](https://github.com/cloudflare/workers-oauth-provider/blob/main/AGENTS.md) for repository conventions and [SECURITY.md](https://github.com/cloudflare/workers-oauth-provider/blob/main/SECURITY.md) for vulnerability reporting.

## Project history

Kenton Varda's original account of how this library was created is preserved in [HISTORY.md](https://github.com/cloudflare/workers-oauth-provider/blob/main/HISTORY.md).
