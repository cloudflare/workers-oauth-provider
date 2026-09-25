# Migrating to 1.x

This guide takes a Worker from 0.10.x, 1.0 or 1.1 to the latest 1.x release. Each change is tagged with the version that introduced it, so skip the ones older than the version you're on. Stored grants, tokens and clients keep working throughout: there is no KV migration.

Coding agents can follow [`skills/migrate-to-1.0/SKILL.md`](../skills/migrate-to-1.0/SKILL.md), which ships in the npm package and points back at the sections below.

## Am I affected?

Search your code for each of these. Anything you don't use needs no change.

| You use                                                                                                                              | Since | Change                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------ | ----- | ------------------------------------------------------------------------------------------- |
| `new OAuthProvider(` without `resourceMetadata`                                                                                      | 1.0   | [Add the canonical resource](#the-canonical-resource-is-required-10)                        |
| `resourceMatchOriginOnly`                                                                                                            | 1.0   | [Delete it](#removed-resourcematchoriginonly-10)                                            |
| `resolveExternalToken`                                                                                                               | 1.0   | [Return `audience`](#resolveexternaltoken-names-its-audience-10)                            |
| `resourceMetadata.scopes_supported`                                                                                                  | 1.2   | [Move it to `requiredScopes`](#requiredscopes-replaces-resourcemetadatascopes_supported-12) |
| `allowImplicitFlow` or `allowPlainPKCE`                                                                                              | 1.2   | [Delete them](#removed-the-implicit-grant-and-plain-pkce-12)                                |
| Clients with remote `http` or `com.example.app:/` redirect URIs                                                                      | 1.2   | [Redirect URI policy](#redirect-uris-must-be-https-or-loopback-http-12)                     |
| `clientRegistrationTTL: 0`, or any lifetime under 60 seconds                                                                         | 1.2   | [Lifetimes are validated](#lifetimes-are-validated-at-construction-12)                      |
| User IDs containing `:`                                                                                                              | 1.2   | [Encode them](#user-ids-cannot-contain--12)                                                 |
| `revokeExistingGrantsBatchSize`                                                                                                      | 1.2   | [Delete it](#removed-revokeexistinggrantsbatchsize-12)                                      |
| `resourceMatches`, `validateResourceUri`, `isValidOAuthScopeToken`, `base64UrlToBytes`, `parseJwtJsonPart`, `getJwtCryptoAlgorithms` | 1.2   | [No longer exported](#internal-helpers-are-no-longer-exported-12)                           |
| `createClient()` or `updateClient()`                                                                                                 | 1.2   | [Client helpers validate](#client-helpers-validate-what-they-store-12)                      |
| `tokenExchangeCallback`                                                                                                              | 1.1   | [It can revoke grants, and lifetimes changed](#tokenexchangecallback-11-12)                 |
| `purgeExpiredData()` on a schedule                                                                                                   | 1.2   | [Persist the cursor](#purgeexpireddata-resumes-from-a-cursor-12)                            |
| `OAuthAuthorizationServer` (1.0 or 1.1)                                                                                              | 1.2   | [Endpoints have defaults](#oauthauthorizationserver-endpoints-have-defaults-12)             |

Construction errors name the rule that failed, so a Worker that starts and passes its tests has cleared most of these. The redirect URI policy and the user ID rule act on stored data and live requests instead: check those by hand.

## Required changes

### The canonical resource is required (1.0)

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

`resource` is the URL your MCP clients connect to, and it becomes every token's audience. Use an absolute HTTPS URI with a lowercase scheme and host, and no fragment, userinfo, default port or dot segments. A bare origin (`https://mcp.example.com`) is allowed and covers every path. `http` is accepted only on loopback hosts, so `wrangler dev` works at `http://localhost:8787`.

Construction validates the rest of the configuration against it:

- Every `apiRoute` and `apiHandlers` key must be the resource's path or a path-boundary descendant: `/mcp` covers `/mcp` and `/mcp/tools`, not `/mcp-other`. Absolute routes must be on the resource's origin.
- The resource must not sit inside `/.well-known/oauth-protected-resource`.

In 0.x the metadata document was derived per request when `resourceMetadata` was omitted. In 1.x the resource is the identity every token is bound to, so it can't be implicit.

### Removed: `resourceMatchOriginOnly` (1.0)

Delete the option. A configuration that still sets it throws `resourceMatchOriginOnly was removed in 1.0`. Audiences are compared exactly against the canonical resource, with two tolerances: ASCII case in the scheme and host is folded, and an empty path equals `/` (RFC 3986 §6.2.3). Port, path, query and trailing slash stay strict.

### `resolveExternalToken` names its audience (1.0)

`ResolveExternalTokenResult.audience` is required, a single string, and must be the configured resource. A token accepted for any other audience is a `401`.

```diff
 resolveExternalToken: async ({ token }) => {
   const session = await upstream.introspect(token);
   if (!session) return null;
-  return { props: { userId: session.sub } };
+  return { props: { userId: session.sub }, audience: 'https://mcp.example.com/mcp' };
 },
```

Since 1.2, a token in this library's own format that isn't in storage (an expired access token, say) is answered `invalid_token` without calling `resolveExternalToken`. Your resolver no longer sees them, so it no longer forwards them upstream.

### `requiredScopes` replaces `resourceMetadata.scopes_supported` (1.2)

A resource's required scopes, the ones any access needs, have their own option on `OAuthProvider` and `OAuthResourceServer`. The wire is unchanged: they're still published as the protected resource metadata's `scopes_supported` and named in the `401` challenge.

```diff
 new OAuthProvider<Env>({
   // …
-  resourceMetadata: { resource: 'https://mcp.example.com/mcp', scopes_supported: ['mcp:read'] },
+  resourceMetadata: { resource: 'https://mcp.example.com/mcp' },
+  requiredScopes: ['mcp:read'],
 });
```

The old field still works but is deprecated, and setting both throws `Set requiredScopes only: resourceMetadata.scopes_supported is deprecated in its favour`. Don't confuse it with `scopesSupported`, the authorization server's catalogue of everything it can grant. See [Scopes and step-up authorization](authorization-server.md#scopes-and-step-up-authorization).

### Removed: the implicit grant and plain PKCE (1.2)

OAuth 2.1 and MCP use the authorization code flow with S256 PKCE only.

```diff
 new OAuthProvider<Env>({
   // …
-  allowImplicitFlow: true,
-  allowPlainPKCE: true,
 });
```

Passing either as `true` throws at construction. At runtime, `response_type=token` is answered `unsupported_response_type`, and `code_challenge_method=plain` is refused with `invalid_request`. An authorization code issued with a plain challenge before the upgrade fails at the token endpoint with `invalid_grant`, so the client authorizes again. Codes live ten minutes, so this only touches authorizations in flight during the deploy.

If you have your own clients on either flow, move them to the authorization code flow with `code_challenge_method=S256` before upgrading.

### Redirect URIs must be HTTPS or loopback HTTP (1.2)

Redirect URIs must use `https`, or `http` on `localhost`, `127.0.0.0/8` or `::1`, with no userinfo or fragment. That's what MCP and OAuth 2.1 require. The rule applies wherever a redirect URI enters: dynamic registration, CIMD documents, `createClient()`, `updateClient()`, and every authorization request.

Because it applies at authorization too, clients registered before 1.2 are held to it. A client with a remote `http` redirect URI gets a locally rendered `invalid_request` ("Invalid redirect URI") and is never redirected. It has to register a compliant URI.

Native apps that use RFC 8252 private-use schemes (`com.example.app:/oauth/callback`) keep working if you opt in:

```ts
new OAuthProvider<Env>({
  // …
  allowPrivateUseRedirectUris: true, // native apps only; leave off for MCP servers
});
```

Remote `http` is never accepted.

### Lifetimes are validated at construction (1.2)

`accessTokenTTL`, `refreshTokenTTL`, `refreshTokenIdleTTL` and `clientRegistrationTTL` are checked when the provider is created, instead of failing every code exchange or registration at runtime. Cloudflare KV can't expire anything sooner than 60 seconds, so:

| Option                  | Accepts                                                  |
| ----------------------- | -------------------------------------------------------- |
| `accessTokenTTL`        | an integer of at least 60                                |
| `refreshTokenTTL`       | `0` (no refresh tokens), `undefined` (no expiry), or 60+ |
| `refreshTokenIdleTTL`   | an integer of at least 60                                |
| `clientRegistrationTTL` | `undefined` (no expiry), or 60+                          |

`clientRegistrationTTL: 0` is no longer accepted. In 0.x it meant "no expiry" in one code path and a zero TTL in another. Write `undefined` for registrations that never expire:

```diff
-  clientRegistrationTTL: 0,
+  clientRegistrationTTL: undefined, // never expire; omit the option for the 90-day default
```

### User IDs cannot contain `:` (1.2)

`completeAuthorization()` throws `userId must be a non-empty string without ":"`. The colon separates the parts of issued tokens and KV keys, so such a user's tokens could never be validated anyway. Encode composite IDs:

```diff
 await oauth.completeAuthorization({
   request: authRequest,
-  userId: `${tenant}:${user}`,
+  userId: encodeURIComponent(`${tenant}:${user}`),
   // …
 });
```

If you look grants up with `listUserGrants()` or `revokeGrant()`, pass the same encoded ID.

### Removed: `revokeExistingGrantsBatchSize` (1.2)

Delete it from `completeAuthorization()`. Every grant written by 1.0 or later carries KV key metadata, so earlier grants are found without reading them. The few pre-1.0 grants that still need reading are read 50 at a time.

```diff
 await oauth.completeAuthorization({
   request: authRequest,
   userId,
   metadata: {},
   scope: authRequest.scope,
   props,
-  revokeExistingGrantsBatchSize: 100,
 });
```

### Internal helpers are no longer exported (1.2)

These were exported by accident and never documented: `resourceMatches`, `validateResourceUri`, `isValidOAuthScopeToken`, `base64UrlToBytes`, `parseJwtJsonPart` and `getJwtCryptoAlgorithms`. Importing one is now a build error. There's no replacement export; copy the logic you need. For scope tokens, RFC 6749 §3.3 allows `/^[\x21\x23-\x5B\x5D-\x7E]+$/`.

### Client helpers validate what they store (1.2)

`createClient()` and `updateClient()` now apply the checks dynamic registration always did:

- Grant and response types must be ones the server implements, so `grantTypes: ['implicit']` throws `Unsupported grant_type: implicit`.
- Redirect URIs follow the [redirect URI policy](#redirect-uris-must-be-https-or-loopback-http-12).
- `updateClient()` refuses a Client ID Metadata Document client while CIMD is enabled (`Client ID Metadata Document clients are updated by changing their document`). Its metadata lives in its document.

Since 1.1, `updateClient()` also leaves clients created with `createClient()` permanent. It used to give them `clientRegistrationTTL`.

### Type changes (1.0)

| 0.x                                                 | 1.x                 |
| --------------------------------------------------- | ------------------- |
| `ExchangeTokenOptions.aud?: string \| string[]`     | `aud?: string`      |
| `AuthRequest.resource?: string \| string[]`         | `resource?: string` |
| `TokenExchangeCallbackOptions.resource` (array-ish) | single `string`     |
| `ResolveExternalTokenResult.audience?` (optional)   | required `string`   |

## Behavior your clients may notice

These need no code change, but responses differ.

- **Registered grant types are enforced (1.0).** A token request for a grant type the client didn't register fails with `unauthorized_client`. `refresh_token` is implied by `authorization_code`; token exchange must be registered explicitly and enabled with `allowTokenExchangeGrant`. Clients registered over DCR in 0.x with a deliberately narrow `grant_types` may now be refused.
- **`redirect_uri` is bound to the authorization request (1.0).** The `redirect_uri` at code exchange must equal the one in the authorization request (OAuth 2.1 §4.1.3). 0.x accepted any registered URI. Without PKCE, it's required at exchange.
- **One grant per user, client and resource (1.0).** A new authorization replaces the user and client's earlier grant _for the same resource_ only. In 0.x it replaced every grant for that user and client.
- **Token exchange (1.0, 1.2).** A subject token is exchanged by the client its grant was issued to, unless `tokenExchangeCallback` returns `allowCrossClientExchange: true` (it gets `subjectClientId` to decide). Subject-token failures return `invalid_request`, and the exchange can't change the resource. Since 1.2 an allowed cross-client token is issued to the requesting client: `ctx.auth.clientId` and `unwrapToken()` name it, and it can revoke the token.
- **Scope requests that match nothing (1.2).** A token request whose `scope` names only scopes the grant doesn't hold is refused with `invalid_scope`. Naming at least one granted scope still narrows silently, as before.
- **Public clients under `disallowPublicClientRegistration` (1.2).** A registration that prefers `none` but also supports a secret method is registered with the secret method instead of being refused.
- **Dynamic client registration (1.0, 1.2).** A registration in use renews itself: a successful token request in the second half of `clientRegistrationTTL` extends it. Bodies over 1 MiB are refused even without `Content-Length`, and a throwing `clientRegistrationCallback` gets a fixed `Client registration callback failed` description on the wire (`onError` still sees the error).
- **Grants without a refresh token expire (1.2).** With `refreshTokenTTL: 0`, a grant now expires with its access token instead of staying in KV for good.
- **CORS headers from your handler are kept (1.2).** `Access-Control-Allow-*` headers an API handler sets are no longer overwritten, so it can narrow its own policy.
- **`deleteClient()` (1.2).** The client is deleted first, so it stops working even if revoking its grants fails partway; calling it again finishes the job.

## `tokenExchangeCallback` (1.1, 1.2)

**`invalid_grant` revokes the grant (1.1).** Throwing `OAuthError('invalid_grant')` now revokes the grant the callback ran for, with its access tokens, and the client authorizes again. Use it when the upstream says the grant is gone for good, and throw `temporarily_unavailable` for failures worth retrying:

```ts
tokenExchangeCallback: async ({ grantType, props, env }) => {
  if (grantType !== 'refresh_token') return;
  const upstream = await refreshUpstream(props.upstreamRefreshToken, env.UPSTREAM_CLIENT_SECRET);
  if (upstream.error === 'invalid_grant') {
    throw new OAuthError('invalid_grant', { description: 'Upstream access was revoked' }); // revokes this grant
  }
  if (!upstream.ok) {
    throw new OAuthError('temporarily_unavailable', { description: 'Upstream unavailable', statusCode: 503 });
  }
  return { newProps: { ...props, upstreamRefreshToken: upstream.refreshToken } };
},
```

**It receives `env` (1.2)**, as in the example above, so it can reach secrets and bindings without rebuilding the provider per request.

**Lifetimes (1.2).** `refreshTokenTTL: undefined` in a result now keeps the provider's lifetime; it used to make the grant never expire, which is what passing through an upstream's missing `refresh_expires_in` did. `refreshTokenTTL` applies at code exchange only and `refreshTokenIdleTTL` at refresh only; returned anywhere else they're ignored rather than failing the request after your side effects ran. Values are validated like the options above.

## `purgeExpiredData()` resumes from a cursor (1.2)

Each call now returns a `cursor` when the sweep isn't finished. Before 1.2 every call restarted from the first grant, so a scheduled sweep over more than `batchSize` grants never reached the rest. Store the cursor between runs:

```ts
async scheduled(_event, env) {
  const cursor = (await env.OAUTH_KV.get('purge-cursor')) ?? undefined;
  const result = await provider.purgeExpiredData(env, { batchSize: 100, cursor });
  if (result.cursor) await env.OAUTH_KV.put('purge-cursor', result.cursor);
  else await env.OAUTH_KV.delete('purge-cursor'); // done: the next run starts a new sweep
},
```

## `OAuthAuthorizationServer` endpoints have defaults (1.2)

If you adopted `OAuthAuthorizationServer` in 1.0 or 1.1, `authorizeEndpoint` and `tokenEndpoint` are now optional. They default to `${issuer}/authorize` and `${issuer}/oauth/token`, under the issuer's path if it has one. Delete them when they match:

```diff
 const authorizationServer = new OAuthAuthorizationServer<Env>({
   issuer: 'https://auth.example.com',
   resources: ['https://mcp.example.com/mcp'],
-  authorizeEndpoint: '/authorize',
-  tokenEndpoint: '/oauth/token',
 });
```

You still route the authorization endpoint yourself, before `authorizationServer.fetch()`. `parseAuthRequest()` rejects a request that arrives anywhere else, so a route on the wrong path fails on its first request. Construction also rejects an endpoint that another would claim, such as one on the metadata path behind a query. `OAuthProvider` still requires both options.

## Existing stored data: nothing to do

- An access token stored without an audience keeps working until it expires. It's treated as bound to the migration resource: the sole configured resource, or `legacyGrantResource` on a multi-resource server.
- Refresh binds the grant to that resource and returns a bound replacement token.
- A stored 0.x audience array resolves to the registered resource it contains.
- A grant bound only to unregistered values fails refresh with `invalid_grant`; conformant clients (Claude, the MCP SDKs) answer by starting a fresh authorization.
- A multi-resource `OAuthAuthorizationServer` without `legacyGrantResource` has no safe destination for unbound records and rejects them. Set it for the migration window and keep it fixed.
- Authorization codes issued by 0.x redeem under the same rules, except plain-PKCE ones ([above](#removed-the-implicit-grant-and-plain-pkce-12)).
- Grants written before 1.0 have no KV key metadata; each refresh adds it.

## New, adopt when useful

None of these are needed to upgrade.

**Role classes (1.0).** `OAuthAuthorizationServer` runs one authorization server for several resources, and `OAuthResourceServer` hosts a resource in the same Worker or its own, validating over a Service Binding. See [resource-servers.md](resource-servers.md).

**`ctx.auth` and `insufficientScope()` (1.0).** Handlers see the verified token beside `ctx.props`, and answer a missing scope with the MCP step-up challenge:

```ts
if (!ctx.auth.scope.includes('mcp:write')) return insufficientScope(ctx.auth, ['mcp:read', 'mcp:write']);
```

**`onError.internal` (1.0).** Every library error carries a stable `{ category, reason }` naming the check that failed. The wire response stays generic.

```ts
onError: ({ status, code, internal }) => console.warn({ status, code, ...internal }),
```

**`refreshTokenIdleTTL` (1.0).** Sliding expiry: each refresh moves the grant's expiry that far ahead.

**Consent and third-party sign-in helpers (1.1).** `beginConsent()`, `approveConsent()`, `denyConsent()`, `isConsentRemembered()`, `beginUpstream()` and `finishUpstream()`, with `cookiePrefix`. See [consent-page.md](consent-page.md) and [upstream-sign-in.md](upstream-sign-in.md).

**Consent page facts and error redirects (1.2).** `describeConsent()` returns what a consent page must show. `AuthorizationError.redirectTo` is the ready-made error redirect back to the client, and `authorizationErrorRedirect()` builds one for an error you decide on:

```ts
try {
  authRequest = await oauth.parseAuthRequest(request);
} catch (error) {
  if (error instanceof AuthorizationError && error.redirectTo) return Response.redirect(error.redirectTo, 302);
  throw error;
}
// …the user declined:
return Response.redirect(authorizationErrorRedirect(authRequest, 'access_denied'), 302);
```

**`OAuthError` from `validateToken` (1.2).** An `OAuthResourceServer`'s validator can throw `OAuthError` to choose the response, such as a `429` with `Retry-After`. See [resource-servers.md](resource-servers.md#alongside-your-own-tokens).
