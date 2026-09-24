# Migrating from 0.x to 1.0

1.0 binds every grant and access token to one canonical resource (RFC 8707 / RFC 9728) and adds role classes for multi-Worker deployments. Stored 0.x data keeps working — there is no KV migration. For most deployments the code diff is one field.

## Am I affected?

- **Single Worker on `OAuthProvider`** (the common shape): add `resourceMetadata: { resource }` if you don't have it. Usually that is the whole migration.
- **You set `resourceMatchOriginOnly`**: remove it; construction now rejects it.
- **You use `resolveExternalToken`**: return `audience` (now required).
- **You registered clients over DCR with an explicit narrow `grant_types`**: registered grant types are now enforced at the token endpoint.
- **Your clients send a different `redirect_uri` at code exchange than at authorization**: OAuth 2.1 §4.1.3 is now enforced.
- **Nothing else**: existing grants, refresh tokens, access tokens and authorization codes keep working under the legacy rules below.

## The canonical resource is required

```diff
 export default new OAuthProvider<Env>({
   apiRoute: ['/mcp'],
   apiHandler,
   defaultHandler,
   authorizeEndpoint: '/authorize',
   tokenEndpoint: '/oauth/token',
+  resourceMetadata: { resource: 'https://mcp.example.com/mcp' },
 });
```

`resource` is the URL your MCP clients connect to: an absolute HTTPS URI with lowercase scheme and host, no fragment, userinfo, default port, or dot segments. A bare origin (`https://mcp.example.com`) is allowed and covers every path. `http` is accepted only on loopback hosts, so `wrangler dev` works at `http://localhost:8787`.

Construction validates the whole configuration against it and throws with a named rule when something is off:

- Every `apiRoute` / `apiHandlers` key must be the resource's path or a path-boundary descendant (`/mcp` covers `/mcp` and `/mcp/tools`, not `/mcp-other`); absolute routes must be on the resource's origin.
- The resource must not sit inside `/.well-known/oauth-protected-resource`.

In 0.x the metadata document was derived per request when `resourceMetadata` was omitted; in 1.0 the configured resource is the identity every token is bound to, so it cannot be implicit.

## Removed: `resourceMatchOriginOnly`

A configuration that still sets it fails at construction. Audiences are now compared exactly against the canonical resource, with two tolerances: ASCII case in scheme and host is folded, and an empty path equals `/` (RFC 3986 §6.2.3). Port, path, query, and trailing slash stay strict.

## `resolveExternalToken` names its audience

`ResolveExternalTokenResult.audience` is required and a single string, and must be the configured canonical resource — a token accepted for another audience is a 401:

```diff
 resolveExternalToken: async ({ token }) => {
   const session = await upstream.introspect(token);
   if (!session) return null;
-  return { props: { userId: session.sub } };
+  return { props: { userId: session.sub }, audience: 'https://mcp.example.com/mcp' };
 },
```

## Registered grant types are enforced

A token request for a grant type the client did not register fails with `unauthorized_client`. `refresh_token` is implied by `authorization_code`; token exchange must be registered explicitly (and enabled with `allowTokenExchangeGrant`). This is a data-side change: clients registered under 0.x with a deliberately narrow `grant_types` array may now be refused where 0.x ignored the field.

## Token exchange

- A subject token is exchanged by the client its grant was issued to. The cross-client case requires `tokenExchangeCallback` to return `allowCrossClientExchange: true`; the callback receives `subjectClientId` to decide.
- Subject-token failures return `invalid_request`.
- The exchange cannot retarget the resource: the subject token's audience and any explicit `resource` parameter must resolve to the same registered value.

## `redirect_uri` is bound to the authorization request

OAuth 2.1 §4.1.3: the `redirect_uri` presented at code exchange must equal the one used in the authorization request (0.x accepted any registered URI). Without PKCE, `redirect_uri` is required at exchange.

## One grant per user, client, and resource

Completing a new authorization replaces the user and client's earlier grant _for the same resource_ only. In 0.x replacement was per user and client, so a central server issuing tokens for several resources no longer drops one resource's grant when the user authorizes another.

## Existing stored data — nothing to do

- An access token stored without an audience keeps working until it expires. It is treated as bound to the migration resource: the sole configured resource, or `legacyGrantResource` on a multi-resource server.
- Refresh binds the grant to that resource and returns a bound replacement token.
- A stored 0.x audience array resolves to the registered resource it contains.
- A grant bound only to unregistered values fails refresh with `invalid_grant`; conformant clients (Claude, the MCP SDKs) answer that by starting a fresh authorization.
- A multi-resource `OAuthAuthorizationServer` without `legacyGrantResource` has no safe destination for unbound records and rejects them; set it for the migration window and keep it fixed.
- Authorization codes issued by 0.x redeem under the same rules.

## Type-level changes

| 0.x                                                 | 1.0                 |
| --------------------------------------------------- | ------------------- |
| `ExchangeTokenOptions.aud?: string \| string[]`     | `aud?: string`      |
| `AuthRequest.resource?: string \| string[]`         | `resource?: string` |
| `TokenExchangeCallbackOptions.resource` (array-ish) | single `string`     |
| `ResolveExternalTokenResult.audience?` (optional)   | required `string`   |

## New in 1.0, adopt when useful

None of these require changes to a migrated 0.x deployment:

- **Role classes** — `OAuthAuthorizationServer` (one AS, many resources) and `OAuthResourceServer` (host a resource in the AS Worker or its own, validating over a Service Binding). See [resource-servers.md](resource-servers.md).
- **`ctx.auth` and `insufficientScope()`** — handlers see the verified token facts beside `ctx.props` and answer scope shortfalls with the MCP `403` challenge. See [Scopes and step-up authorization](authorization-server.md#scopes-and-step-up-authorization).
- **`onError.internal`** — every library error carries a stable `{ category, reason }` for logs and alerting; the wire stays generic.
- **`refreshTokenIdleTTL`** — opt-in sliding refresh-token expiry.
- Dynamically registered clients in active use renew automatically; grant listing and revocation are KV-bounded.
