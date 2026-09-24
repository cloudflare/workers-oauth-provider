# Authorization server reference

The authorization endpoint, client registration, tokens, resources, scopes, storage, and every option. For a runnable starting point see [`examples/split-workers`](../examples/split-workers).

## Authorization endpoint

Your `authorizeEndpoint` is application code, because user authentication and consent are application-specific. With split roles it is the `/authorize` route in your authorization server's `fetch`, using `authorizationServer.getOAuthApi(env)`; with `OAuthProvider` it lives in `defaultHandler`, using `env.OAUTH_PROVIDER`. The helpers are the same. The provider is not an identity provider.

A typical flow has three steps:

1. Call `parseAuthRequest(request)` to validate the client, redirect URI, response type, resource, and PKCE restrictions.
2. Authenticate the user, show consent, and decide which scopes to grant.
3. Call `completeAuthorization()` and redirect to its returned `redirectTo` URL.

[docs/consent-page.md](consent-page.md) shows a safe consent page (what it must display, escaping client metadata, Allow and Deny) and which errors to redirect back to the client and which to render.

`parseAuthRequest()` throws an exported `AuthorizationError` for expected request validation failures. Its optional `redirectUri` is present only after the client and exact registered redirect URI have been validated. Without it, render the error locally and never redirect. With it, the application can safely construct an OAuth error redirect using the error's `code`, `description`, original `state`, and RFC 9207 `issuer`, as shown in [`examples/split-workers`](../examples/split-workers/auth-server/index.ts).

`completeAuthorization()` repeats response-type validation before writing a grant or revoking existing grants. Validation errors from reconstructed requests are also typed as `AuthorizationError`, but applications should not construct redirects from untrusted reconstructed values; the redirect context is attached only by `parseAuthRequest()`.

`completeAuthorization()` stores a new grant and, by default, revokes existing grants for the same user, client, and resource after the new grant is safely stored. A grant for another registered resource is a separate authorization and is not revoked. Set `revokeExistingGrants: false` only when the application intentionally allows concurrent grants within the same resource.

For Client ID Metadata Document clients, whose client_id is the metadata URL shared by every installation, default revocation is additionally scoped to grants created from the same redirect URI, so one installation's re-authorization does not revoke another's. Grants created before the redirect URI was recorded are never auto-revoked by CIMD clients.

For users with many grants, `revokeExistingGrantsBatchSize` controls the KV page size used during that scan. It defaults to `50` and is capped at KV's maximum page size of `1000`.

### Authorization response issuer

RFC 9207 issuer identification is always enabled. Authorization server metadata advertises `authorization_response_iss_parameter_supported: true`, and successful authorization responses include `iss` automatically.

Error redirects carry it too. `AuthorizationError.redirectTo` is ready-made for `parseAuthRequest()` failures, and `authorizationErrorRedirect()` builds one for an error your application decides on, from a request the library validated:

```ts
const oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
// …the user declined:
return Response.redirect(authorizationErrorRedirect(oauthRequest, 'access_denied'), 302);
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
- Non-empty `client_name` and `redirect_uris` fields, as MCP requires. Redirect URIs must use `https`, or `http` on a loopback host (`localhost`, `127.0.0.0/8`, `::1`), with no userinfo or fragment. The same rule applies to CIMD documents, `createClient()`, `updateClient()`, and every authorization request, so older clients are held to it too. Native apps using RFC 8252 private-use schemes (`com.example.app:/cb`) need `allowPrivateUseRedirectUris: true`; remote `http` is never accepted.
- Exact authorization-request redirect URI validation, with RFC 8252 loopback port handling.
- A 5 KB response size limit and a 10 second timeout covering both headers and body.
- Valid UTF-8 JSON object syntax and safe URI schemes for client metadata fields.
- No embedded client secrets or private JWK material.

Validated documents are cached according to their `Cache-Control` headers, capped at 7 days. Error responses and invalid documents are never cached, and a cached document that stops validating is evicted and re-resolved from origin within the same request.

CIMD token endpoint authentication is negotiated from `token_endpoint_auth_method` and the OpenID RP Metadata Choices field `token_endpoint_auth_methods_supported`. The provider currently implements only `none`: a client may prefer `private_key_jwt` while also offering `none`, in which case the provider selects `none` and applies public-client PKCE requirements. A client that offers only `private_key_jwt` is rejected until assertion validation is implemented.

When a CIMD document cannot be fetched or validated, the token endpoint returns a generic `invalid_client` response and reports diagnostics through `onError.internal`. `OAuthHelpers` methods that resolve a CIMD client throw the exported `CimdFetchError`, allowing applications to distinguish an upstream metadata failure from a client that does not exist. See [Advanced configuration](advanced-configuration.md#cimd-fetch-errors) for an example.

### Dynamic Client Registration

Set `clientRegistrationEndpoint` to enable RFC 7591 Dynamic Client Registration:

```ts
clientRegistrationEndpoint: '/oauth/register';
```

MCP 2026-07-28 deprecates DCR for new implementations in favor of CIMD. The endpoint remains useful for compatibility with clients that do not support CIMD.

Registration accepts only authentication methods, grants, and response types implemented by the configured provider, and rejects inconsistent grant/response combinations before storage. Choice-valued `token_endpoint_auth_methods_supported` input is negotiated to one effective `token_endpoint_auth_method`; grant and response registrations remain strict. Omitted metadata uses the RFC 7591 defaults: `client_secret_basic`, `grant_types: ["authorization_code"]`, and `response_types: ["code"]`. The token endpoint enforces each client's registered grant types with `unauthorized_client`; `refresh_token` is implied by `authorization_code`, and a client must register `urn:ietf:params:oauth:grant-type:token-exchange` to use token exchange.

The effective `token_endpoint_auth_method` returned by registration is enforced exactly. When both authentication metadata fields are omitted, no explicit-method marker is stored and the client may use either `client_secret_basic` or `client_secret_post`, provided the same stored secret validates. Client records written by earlier releases have no marker and receive the same compatibility. This never crosses between `none` and a secret method and does not apply to CIMD clients.

Calling `OAuthHelpers.updateClient()` with `tokenEndpointAuthMethod` adds the marker; unrelated updates leave it unchanged.

Related options:

- `clientRegistrationTTL` controls the lifetime of dynamically registered clients. The default is 90 days. A registration still in use does not expire: once it has passed half its lifetime, the next successful token request renews it for the full TTL, so a client that keeps refreshing keeps its `client_id` while an abandoned one is cleaned up. The `client_secret_expires_at` returned at registration describes the initial lifetime; there is no channel to report a renewal, so a client that honours it re-registers on that schedule as before.
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

A grant expires `refreshTokenTTL` seconds after the code exchange (30 days by default) however often it is refreshed. Set `refreshTokenIdleTTL` to make that lifetime slide instead: each successful refresh moves the expiry to that many seconds later, so a grant lives while the client keeps using it and expires once idle. `tokenExchangeCallback` can return `refreshTokenIdleTTL` to set the lifetime for one refresh, which lets a Worker that proxies an upstream OAuth service match the lifetime of the upstream refresh token it just rotated. See [Advanced configuration](advanced-configuration.md#token-and-client-lifetimes).

## Resources and token audiences

An authorization server may register one or more protected resources. Each resource has one canonical `resourceMetadata.resource`: an absolute HTTPS URI without a fragment, with lowercase `https` and a lowercase host, and an RFC 3986-safe producer serialization. Userinfo, default ports, dot-segment paths, and an empty path before a query are rejected because `Request` would rewrite them before RFC 9728 comparison. A bare origin is the only empty-path exception; use `/` before a query. Query components are supported but discouraged by RFC 9728.

For local development, `http` is accepted for resources, `authorization_servers`, the explicit `OAuthAuthorizationServer` issuer, and absolute endpoint URLs only when the host is a loopback address (`localhost`, `127.0.0.0/8`, `::1`), so `wrangler dev` works at `http://localhost:8787`. Any other host must use `https`: Workers are always served over `https`, and OAuth 2.1 requires it. A local MCP client's loopback redirect URI is unaffected by this rule; it is governed by the RFC 8252 loopback handling described under client registration.

Every authorization grant and access token is bound to exactly one registered resource. A central authorization server can therefore issue separate Calendar and Drive tokens from one KV namespace, but it never turns those into one multi-audience bearer token. Completing a new authorization for Drive does not replace the same user and client's Calendar grant.

Conforming MCP clients are required to send `resource` in authorization and token requests. Resource selection and compatibility work as follows:

- When the authorization server has one registered resource, that sole resource is selected if an authorization request omits `resource`. This preserves existing `OAuthProvider` behavior.
- When it has multiple registered resources, an authorization request must identify exactly one of them. Set `defaultResource` on `OAuthAuthorizationServer` only when older clients that omit `resource` should be routed to a deliberate compatibility default.
- An authorization-code or refresh-token request may omit `resource`; the server inherits the resource already stored on the grant. If present, it must match that grant and cannot retarget it.
- Malformed, unknown, or multi-valued resource input returns `invalid_target` before code consumption, callbacks, refresh rotation, or storage writes.

ASCII case differences in the URI scheme and host are accepted, but port, path, query, trailing slash, and array cardinality remain strict. The authorization server always stores and returns the configured lowercase scheme-and-host spelling. The token response includes the selected resource, and the access-token audience contains that resource alone.

Token exchange cannot change the resource. Both the subject-token audience and any explicit requested resource must resolve to the same registered canonical value. A token is exchanged by the client its grant was issued to unless `tokenExchangeCallback` returns `allowCrossClientExchange: true`. Internally and externally validated tokens are accepted at a protected route only when their audience matches that route's resource.

Path-aware API validation uses path-boundary prefix matching. A canonical audience for `https://example.com/mcp` covers `/mcp` and `/mcp/tools`, but not `/mcp-other`. A canonical trailing slash remains significant.

## Scopes and step-up authorization

`scopesSupported` is published only in authorization server metadata. Configure each protected resource's `resourceMetadata.scopes_supported` explicitly with the minimal scopes required for its basic functionality and baseline Bearer challenges.

The application decides which requested scopes to grant through `completeAuthorization({ scope })`. Token and refresh requests can only narrow those scopes.

Both hosts name `scopes_supported` in the initial `401` challenge, so a client asks for the right scopes first time. Operation-level policy stays in the handler, which reads the token's scopes from `ctx.auth.scope` and answers a shortfall with `insufficientScope(ctx.auth, ['files:write'])`: `403`, `error="insufficient_scope"`, every scope the operation needs in one challenge, and the resource's metadata URL. See [docs/resource-servers.md](resource-servers.md#what-the-handler-sees).

## KV storage and cleanup

Sensitive values are not stored in plaintext:

- Access tokens, refresh tokens, authorization codes, and client secrets are stored only by hash.
- `props` are encrypted with AES-GCM using key material wrapped by the corresponding secret token.
- Grant `userId` and `metadata` are not encrypted because applications use them to enumerate and revoke grants. Treat those fields as storage-visible metadata.

See [storage-schema.md](../storage-schema.md) for the complete KV layout.

By default `completeAuthorization()` revokes the user's earlier grants for the same client and resource. It finds them from KV key metadata that every grant written by 1.0 or later carries, so the cost is one `list()` per thousand grants the user has, not a read per grant. Grants written before 1.0 are read individually, `revokeExistingGrantsBatchSize` at a time (default 50), until a refresh rewrites them with metadata.

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

The existing `OAuthProvider` combined configuration uses these options:

| Option                             | Purpose                                                                     | Default                                  |
| ---------------------------------- | --------------------------------------------------------------------------- | ---------------------------------------- |
| `apiRoute` and `apiHandler`        | Protect one or more route prefixes with one handler                         | Use these or `apiHandlers`               |
| `apiHandlers`                      | Map protected route prefixes to different handlers                          | Use this or `apiRoute` plus `apiHandler` |
| `defaultHandler`                   | Handle authorization UI and other unprotected routes                        | Required                                 |
| `authorizeEndpoint`                | Application-owned authorization and consent endpoint                        | Required                                 |
| `tokenEndpoint`                    | Provider-owned token and revocation endpoint                                | Required                                 |
| `clientRegistrationEndpoint`       | Enable RFC 7591 DCR                                                         | Disabled                                 |
| `scopesSupported`                  | Publish authorization server scopes                                         | Omitted                                  |
| `resourceMetadata.resource`        | Canonical HTTPS resource and token audience                                 | Required                                 |
| `clientIdMetadataDocumentEnabled`  | Enable CIMD lookup and advertisement                                        | `false`                                  |
| `allowPrivateUseRedirectUris`      | Accept RFC 8252 private-use scheme redirect URIs for native apps            | `false`                                  |
| `cookiePrefix`                     | Prefix for the consent and upstream helpers' cookies (must be `__Host-…`)   | `__Host-oauth-`                          |
| `allowPlainPKCE`                   | Permit the legacy plain PKCE method                                         | `false`                                  |
| `allowImplicitFlow`                | Enable implicit token responses                                             | `false`                                  |
| `disallowPublicClientRegistration` | Reject public clients at DCR                                                | `false`                                  |
| `clientRegistrationCallback`       | Apply application policy before storing a DCR client                        | None                                     |
| `allowTokenExchangeGrant`          | Enable RFC 8693                                                             | `false`                                  |
| `tokenExchangeCallback`            | Update props, scopes, or lifetimes during token exchange                    | None                                     |
| `resolveExternalToken`             | Validate external bearer credentials (advanced)                             | None                                     |
| `enterpriseManagedAuthorization`   | Enable experimental ID-JAG grant support                                    | Disabled                                 |
| `onError`                          | Observe or replace OAuth error responses; `internal` names the failed check | Logs a warning                           |

The functional role API adds these surfaces without removing `OAuthProvider`:

| Surface                                                  | Purpose                                                                                     |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `new OAuthAuthorizationServer({ issuer, resources, … })` | Create the AS role with a canonical RFC 8414 issuer and its fixed resource registry         |
| `validateToken(resource, token, env)`                    | Validate an access token for one declared resource; what a resource server calls            |
| `defaultResource`                                        | Select a deliberate default for new authorization requests that omit it                     |
| `legacyGrantResource`                                    | Select the server-controlled migration target for old unbound grants                        |
| `getOAuthApi(env)`                                       | Obtain OAuth helpers for an application-owned authorization route                           |
| `new OAuthResourceServer({ … })`                         | Host one resource, in this Worker or another; `validateToken` points at the AS or a binding |

Consult the exported `OAuthProviderOptions`, `OAuthAuthorizationServerOptions`, resource-server callback interfaces, and JSDoc in [`src/oauth-provider.ts`](../src/oauth-provider.ts) for the complete typed API.

## OAuth helpers

Handlers receive `env.OAUTH_PROVIDER`, which implements `OAuthHelpers`. It can:

- Parse authorization requests and complete authorization.
- Run a consent page and a third-party sign-in redirect safely (`beginConsent()`, `approveConsent()`, `denyConsent()`, `isConsentRemembered()`, `beginUpstream()`, `finishUpstream()`).
- Look up, create, list, update, and delete clients.
- List and revoke grants for a user.
- Inspect internally issued tokens with `unwrapToken()`.
- Exchange access tokens when RFC 8693 is enabled.
- Purge expired and orphaned KV data.

`getOAuthApi(options, env)` provides the same helper API outside a fetch handler, including RPC methods and other Worker entrypoints.
