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

Before calling a protected handler, the provider reads the bearer token, rejects missing, invalid, or expired credentials, checks its audience, and exposes the authenticated application data through `ctx.props`. The handler does not need to parse or validate the token, but it must still enforce ownership, tenancy, and any application permissions deliberately stored in `props`. Effective OAuth token scope is not added to `ctx.props`; see [Scope behavior](#scope-behavior).

Requests outside the protected route prefixes go to `defaultHandler`. In the example above, that handler owns `/authorize`.

## One authorization server with multiple MCP resources

`OAuthAuthorizationServer` separates the authorization-server role from each protected-resource role while keeping them composable. Call `protectResource()` once for every MCP resource hosted by the same Worker. Each call registers one canonical audience with the authorization server and returns a fetch handler that serves only that resource's RFC 9728 metadata, Bearer challenges, and protected API.

The following optional example (`npm install hono`) binds one Worker to three custom domains and uses Hono's hostname-aware path function to route without a hostname `switch`. The application owns the interactive `/authorize` route; `authorizationServer.fetch()` owns discovery, token, revocation, and optional registration endpoints. The original `Request` is forwarded as `c.req.raw`, so authorization-server and protected-resource URL validation still sees the real origin.

```ts
import { Hono } from 'hono';
import { OAuthAuthorizationServer } from '@cloudflare/workers-oauth-provider';

const AUTH_ISSUER = 'https://auth.example.com';
const CALENDAR_RESOURCE = 'https://calendar.example.com/mcp';
const DRIVE_RESOURCE = 'https://drive.example.com/mcp';

interface Env {
  OAUTH_KV: KVNamespace;
}

interface AuthProps {
  userId: string;
}

const authorizationServer = new OAuthAuthorizationServer<Env, AuthProps>({
  issuer: AUTH_ISSUER,
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  clientRegistrationEndpoint: '/oauth/register',
  scopesSupported: ['calendar:read', 'drive:read'],
});

const calendar = authorizationServer.protectResource({
  resourceMetadata: {
    resource: CALENDAR_RESOURCE,
    scopes_supported: ['calendar:read'],
    resource_name: 'Calendar MCP',
  },
  handler: {
    async fetch(_request, _env, ctx) {
      return Response.json({ userId: ctx.props.userId, server: 'calendar' });
    },
  },
});

const drive = authorizationServer.protectResource({
  resourceMetadata: {
    resource: DRIVE_RESOURCE,
    scopes_supported: ['drive:read'],
    resource_name: 'Drive MCP',
  },
  handler: {
    async fetch(_request, _env, ctx) {
      return Response.json({ userId: ctx.props.userId, server: 'drive' });
    },
  },
});

const app = new Hono<{ Bindings: Env }>({
  getPath(request) {
    const url = new URL(request.url);
    return `/${url.hostname}${url.pathname}`;
  },
});

// Authenticate the user and obtain consent here. Production code should render
// AuthorizationError safely as shown in the quick start.
app.get('/auth.example.com/authorize', async (c) => {
  const oauth = authorizationServer.getOAuthApi(c.env);
  const request = await oauth.parseAuthRequest(c.req.raw);
  const { redirectTo } = await oauth.completeAuthorization({
    request,
    userId: 'user-123',
    metadata: {},
    scope: request.scope,
    props: { userId: 'user-123' },
  });
  return c.redirect(redirectTo);
});

app.all('/auth.example.com/*', (c) => authorizationServer.fetch(c.req.raw, c.env, c.executionCtx));
app.all('/calendar.example.com/*', (c) => calendar.fetch(c.req.raw, c.env, c.executionCtx));
app.all('/drive.example.com/*', (c) => drive.fetch(c.req.raw, c.env, c.executionCtx));

export default app;
```

Route all three custom domains to that Worker:

```jsonc
{
  "workers_dev": false,
  "routes": [
    { "pattern": "auth.example.com", "custom_domain": true },
    { "pattern": "calendar.example.com", "custom_domain": true },
    { "pattern": "drive.example.com", "custom_domain": true },
  ],
}
```

`authorizationServer.fetch()` serves only the AS role at `auth.example.com`; the handles returned by `protectResource()` serve only their registered resource. Authorization server metadata advertises both canonical identifiers in `protected_resources`, while Calendar and Drive publish independent protected resource metadata that points back to `https://auth.example.com`.

Registration is functional and happens during module initialization. Call `protectResource()` or `registerResource()` before the first request; an authorization server with no registered resources cannot publish useful metadata or issue a resource-bound grant.

### Resource servers in separate Workers

Use `registerResource()` when the authorization server issues tokens for a resource it does not host. The standalone resource Worker can use `createOAuthResourceServer()` to publish its own RFC 9728 metadata, issue Bearer challenges, enforce the canonical audience, and expose validated application data as `ctx.props`:

```ts
import { createOAuthResourceServer, type ValidatedAccessToken } from '@cloudflare/workers-oauth-provider';

const AUTH_ISSUER = 'https://auth.example.com';
const CALENDAR_RESOURCE = 'https://calendar.example.com/mcp';

interface AuthProps {
  userId: string;
  scopes: string[];
}

interface CalendarEnv {
  AUTHORIZATION_SERVER: {
    validateToken(token: string): Promise<ValidatedAccessToken<{ userId: string }> | null>;
  };
}

export default createOAuthResourceServer<CalendarEnv, AuthProps>({
  resourceMetadata: {
    resource: CALENDAR_RESOURCE,
    authorization_servers: [AUTH_ISSUER],
    scopes_supported: ['calendar:read'],
    resource_name: 'Calendar MCP',
  },
  async validateToken({ token, env }) {
    const validation = await env.AUTHORIZATION_SERVER.validateToken(token);
    if (!validation) return null;
    return {
      audience: validation.audience,
      expiresAt: validation.expiresAt,
      props: {
        ...validation.props,
        scopes: validation.scope,
      },
    };
  },
  handler: {
    async fetch(_request, _env, ctx) {
      if (!ctx.props.scopes.includes('calendar:read')) {
        return new Response('Forbidden', { status: 403 });
      }
      return Response.json({ userId: ctx.props.userId });
    },
  },
});
```

The `validateToken` callback is deliberately transport-independent. For Workers, a private Service Binding can expose a resource-specific method backed by `authorizationServer.validateToken()`:

```ts
import { WorkerEntrypoint } from 'cloudflare:workers';

authorizationServer.registerResource(CALENDAR_RESOURCE).registerResource(DRIVE_RESOURCE);

export class CalendarTokenValidator extends WorkerEntrypoint<Env> {
  validateToken(token: string) {
    return authorizationServer.validateToken(token, CALENDAR_RESOURCE, this.env);
  }
}
```

Bind the Calendar Worker to `CalendarTokenValidator`; expose a separate Drive entrypoint fixed to `DRIVE_RESOURCE`. Fixing the resource on the authorization-server side prevents one resource Worker from asking to validate tokens for another audience. `createOAuthResourceServer()` also rejects a successful callback result whose `audience` is not its configured canonical resource and returns `503` when validation infrastructure throws. It passes only the validator's `props` to the handler, so the validator must copy or derive every scope and identity field the handler needs, as above, or enforce authorization itself. The package does not create a public token-introspection or validation endpoint; applications choose and secure the callback transport.

### Signed JWT access tokens

Access tokens remain opaque by default. An `OAuthAuthorizationServer` can install signed [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) JWT access-token support with `createJwtAccessTokens()`. With no issuance policy, new access tokens become JWTs. Authorization codes and refresh tokens remain opaque.

OAuth clients must continue treating the access-token string as opaque; JWT validation is a resource-server concern.

Signed does not mean encrypted. The JWT's issuer, subject (`userId`), audience, client ID, scope, timestamps, token ID, and provider grant ID are readable by the client. Application `props` are not copied into the JWT. Use `publicClaims` only to project non-secret JSON data that is safe for the client and anyone holding the access token to read:

```ts
import {
  createJwtAccessTokens,
  OAuthAuthorizationServer,
  type JwtAccessTokenKeySet,
} from '@cloudflare/workers-oauth-provider';

const AUTH_ISSUER = 'https://auth.example.com';
const CALENDAR_RESOURCE = 'https://calendar.example.com/mcp';

interface Env {
  OAUTH_KV: KVNamespace;
  JWT_ISSUANCE_ENABLED: boolean;
}

interface AuthProps {
  userId: string;
  tenantId: string;
  upstreamAccessToken: string; // Confidential: never put this in publicClaims.
}

// Resolve a non-extractable signing key and its public JWK from your
// application-owned key store. See the rotation guidance below.
declare function loadAccessTokenKeys(env: Env): Promise<JwtAccessTokenKeySet>;

const jwtAccessTokens = createJwtAccessTokens<Env, AuthProps>({
  issuer: AUTH_ISSUER,
  jwksUri: `${AUTH_ISSUER}/.well-known/jwks.json`,
  keys: loadAccessTokenKeys,
  publicClaims: ({ props }) => ({ tenantId: props.tenantId }),
});

const authorizationServer = new OAuthAuthorizationServer<Env, AuthProps>({
  issuer: AUTH_ISSUER,
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  accessTokens: jwtAccessTokens,
});

const calendar = authorizationServer.protectResource({
  resourceMetadata: {
    resource: CALENDAR_RESOURCE,
    scopes_supported: ['calendar:read'],
  },
  handler: {
    async fetch(_request, _env, ctx) {
      // Same-Worker validation still checks the KV token record and decrypts
      // the complete props. The confidential upstream token is not in the JWT.
      return Response.json({
        userId: ctx.props.userId,
        hasUpstreamToken: Boolean(ctx.props.upstreamAccessToken),
      });
    },
  },
});
```

The authorization server publishes `jwks_uri` in its RFC 8414 metadata and serves the resolver's public keys at that exact URL. It also retains the encrypted token-context record in KV. Consequently, resources returned by `protectResource()`, `authorizationServer.validateToken()`, token exchange, and revocation keep their stateful behavior and can use the full confidential `ctx.props`; the JWT is not the source of those props.

A separate resource Worker that needs only public data can validate the JWT locally. Register that remote audience at the authorization server with `authorizationServer.registerResource(CALENDAR_RESOURCE)`; unlike `protectResource()`, registration advertises and permits the audience but does not attach a handler. `createJwtAccessTokenValidator()` validates the package-specific profile emitted by `createJwtAccessTokens()`, including its provider grant-ID claim; it is not a generic verifier for arbitrary RFC 9068 issuers. The resource Worker's verifier pins the issuer, audience, allowed algorithm, and trusted key source. `mapClaimsToProps` receives verified claims and must validate the application-specific public claim before exposing it to the handler:

```ts
import {
  createJwtAccessTokenValidator,
  createOAuthResourceServer,
  type JwtAccessTokenPublicKey,
  type ValidatedAccessToken,
} from '@cloudflare/workers-oauth-provider';

const AUTH_ISSUER = 'https://auth.example.com';
const CALENDAR_RESOURCE = 'https://calendar.example.com/mcp';
const JWKS_URI = `${AUTH_ISSUER}/.well-known/jwks.json`;

interface StatefulCalendarProps {
  userId: string;
  tenantId: string;
}

interface CalendarEnv {
  // Fetch Service Binding to the authorization Worker's default entrypoint.
  AUTHORIZATION_SERVER_JWKS: Fetcher;
  // Temporary RPC Service Binding to the resource-pinned validator shown above.
  LEGACY_TOKEN_VALIDATOR?: {
    validateToken(token: string): Promise<ValidatedAccessToken<StatefulCalendarProps> | null>;
  };
}

interface CalendarProps {
  userId: string;
  tenantId: string;
  scopes: string[];
}

let cachedJwks: { keys: JwtAccessTokenPublicKey[]; expiresAt: number } | undefined;

async function loadTrustedAccessTokenKeys(env: CalendarEnv): Promise<JwtAccessTokenPublicKey[]> {
  if (cachedJwks && cachedJwks.expiresAt > Date.now()) return cachedJwks.keys;

  // Fetch only the configured URI over the AS Service Binding. Never follow a
  // key URL supplied by a token.
  const response = await env.AUTHORIZATION_SERVER_JWKS.fetch(
    new Request(JWKS_URI, { headers: { Accept: 'application/json' } })
  );
  if (!response.ok) throw new Error(`JWKS request failed: ${response.status}`);

  const document: unknown = await response.json();
  if (!document || typeof document !== 'object' || !('keys' in document) || !Array.isArray(document.keys)) {
    throw new Error('JWKS response has no keys array');
  }
  const keys = document.keys as JwtAccessTokenPublicKey[];
  const maxAge = /(?:^|,)\s*max-age=(\d+)/i.exec(response.headers.get('Cache-Control') ?? '');
  cachedJwks = {
    keys,
    expiresAt: Date.now() + (maxAge ? Number(maxAge[1]) * 1000 : 0),
  };
  return keys;
}

const validateCalendarJwt = createJwtAccessTokenValidator<CalendarEnv, CalendarProps>({
  issuer: AUTH_ISSUER,
  audience: CALENDAR_RESOURCE,
  algorithms: ['RS256'],
  keys: loadTrustedAccessTokenKeys,
  mapClaimsToProps({ userId, scope, publicClaims }) {
    const tenantId =
      publicClaims !== null && typeof publicClaims === 'object' && !Array.isArray(publicClaims)
        ? publicClaims.tenantId
        : undefined;
    if (typeof tenantId !== 'string') return null;
    return { userId, tenantId, scopes: scope };
  },
});

export default createOAuthResourceServer<CalendarEnv, CalendarProps>({
  resourceMetadata: {
    resource: CALENDAR_RESOURCE,
    authorization_servers: [AUTH_ISSUER],
    scopes_supported: ['calendar:read'],
  },
  validateToken: validateCalendarJwt,
  handler: {
    async fetch(_request, _env, ctx) {
      if (!ctx.props.scopes.includes('calendar:read')) return new Response('Forbidden', { status: 403 });
      return Response.json({ userId: ctx.props.userId, tenantId: ctx.props.tenantId });
    },
  },
});
```

Offline verification cannot observe deletion of a token or grant record. Use short access-token lifetimes, or make `mapClaimsToProps` perform an application status check when immediate revocation is required. If a separate Worker needs confidential props, individual-token revocation, or grant revocation without waiting for expiry, use the private Service Binding and `authorizationServer.validateToken()` pattern above instead.

During migration, a separate Worker can try offline JWT validation first and fall back only to its resource-pinned authorization-server binding for old opaque tokens:

```ts
async function validateDuringMigration(input: Parameters<typeof validateCalendarJwt>[0]) {
  const jwt = await validateCalendarJwt(input);
  if (jwt) return jwt;

  const legacyValidator = input.env.LEGACY_TOKEN_VALIDATOR;
  if (!legacyValidator) return null;
  const legacy = await legacyValidator.validateToken(input.token);
  if (!legacy) return null;
  return {
    audience: legacy.audience,
    expiresAt: legacy.expiresAt,
    props: {
      userId: legacy.props.userId,
      tenantId: legacy.props.tenantId,
      scopes: legacy.scope,
    },
  };
}

// Temporarily use this instead of validateCalendarJwt in createOAuthResourceServer().
```

Do not fall through to a permissive external-token resolver. The fallback above is the `CalendarTokenValidator` Service Binding from the preceding example, so its authorization-server-side call is fixed to `CALENDAR_RESOURCE`. Remove it only after the rollout checks and maximum-lifetime window below.

Rotate keys in this order:

1. Add the next public JWK to `verificationKeys` while the old key remains `current`.
2. Wait at least the JWKS cache lifetime after publication—currently five minutes from the authorization server's `Cache-Control` header—before signing with the new key.
3. Promote the new private key to `current`, remove its now-duplicate public JWK from `verificationKeys`, and add the old current key's public JWK there.
4. Keep the old public JWK until the last token signed with it has passed the maximum effective access-token lifetime, plus JWKS cache time and clock skew; then remove it.

Resource Workers should fetch only the configured `jwks_uri`, never cache longer than its response allows, and select exactly one key by `kid` and pinned algorithm.

Roll this out reader before writer. `accessTokens` installs the JWT reader, signer, and JWKS; `accessTokenFormat` controls only the representation of each newly issued access token:

```ts
const authorizationServer = new OAuthAuthorizationServer<Env, AuthProps>({
  issuer: AUTH_ISSUER,
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  accessTokens: jwtAccessTokens,
  accessTokenFormat: ({ env }) => (env.JWT_ISSUANCE_ENABLED ? 'jwt' : 'opaque'),
});
```

The policy runs for every access-token issuance. Its immutable context contains `env`, the authenticated `clientId`, and the canonical `resource`, so application code can use a deployment flag or a deterministic client/resource cohort. Keep it local and highly available: throwing, rejecting, or returning anything except `opaque` or `jwt` fails before one-use authorization state is consumed rather than silently downgrading security.

1. Configure `accessTokens` while the callback returns `opaque`, then deploy the authorization server everywhere. It publishes `jwks_uri`, serves the future signing key, and accepts both compatible opaque tokens and JWTs while continuing to issue opaque access tokens.
2. Deploy JWT validation to every token consumer. A separate resource Worker must temporarily fall back to its resource-pinned Service Binding validator for old opaque tokens.
3. Verify the deployment and wait at least the JWKS cache lifetime before changing the callback to return `jwt`. New authorization-code, refresh, implicit, token-exchange, and enterprise-managed access tokens now become JWTs. Existing access tokens are not converted or invalidated, and authorization codes and refresh tokens remain opaque.
4. Confirm every issuer instance and rollout cohort now returns `jwt`, then keep the opaque fallback for the maximum effective access-token lifetime measured from the last possible opaque issuance, including any TTL overrides. To roll back after removing that fallback, first restore the resource-pinned opaque fallback to every JWT-only consumer, then return `opaque`; retain `accessTokens`, its JWKS, and every required verification key until all previously issued JWTs have expired plus cache time and clock skew.

State-backed provider surfaces continue accepting compatible access tokens issued in the old opaque format until those tokens expire. A JWT-only offline validator does not understand an old opaque token, which is why the temporary fallback is required. Never roll back to a package version or configuration that cannot read still-live JWT access tokens. This token-format rollout does not bypass the resource migration policy: a pre-resource access-token record with no trustworthy canonical audience remains unusable, although its refresh grant can migrate according to `legacyGrantResource`.

The existing `OAuthProvider` constructor remains supported. It is the concise combined AS-and-resource API used by the quick start and is appropriate when one Worker protects one canonical resource. Existing applications do not need to move to `OAuthAuthorizationServer` to upgrade.

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
5. The client fetches RFC 8414 authorization server metadata from the selected issuer. In the single-origin quick start that is:

   ```text
   https://mcp.example.com/.well-known/oauth-authorization-server
   ```

6. The metadata tells the client where to authorize, exchange tokens, and register if registration is enabled.

Protected resource metadata and authorization server metadata serve different roles:

- Protected resource metadata describes the MCP server and identifies its authorization servers.
- Authorization server metadata describes OAuth endpoints and capabilities such as PKCE and CIMD.

### Protected resource metadata

Every protected resource needs its own `resourceMetadata.resource`. Configure each canonical HTTPS identifier with a lowercase scheme and host:

```ts
resourceMetadata: {
  resource: 'https://mcp.example.com/mcp',
  authorization_servers: ['https://auth.example.com'],
  scopes_supported: ['files:read'],
  bearer_methods_supported: ['header'],
  resource_name: 'Files MCP server',
}
```

For the example above, an unauthenticated request to the exact canonical URL receives a Bearer challenge pointing to:

```text
https://mcp.example.com/.well-known/oauth-protected-resource/mcp
```

That document returns the configured canonical `resource`. The discovery URL is built from the canonical resource: an origin uses `/.well-known/oauth-protected-resource`, and a path and query are inserted after the well-known prefix.

RFC 9728 requires challenge-discovered metadata to identify the original requested resource URL. The provider therefore includes `resource_metadata` only when the protected request URL is the canonical resource itself. A canonical path may still be a base audience for descendants: a token for `https://mcp.example.com/mcp` is accepted at `/mcp/tools`, but a request to that descendant does not advertise a mismatched metadata document. If clients must discover authorization from multiple entry paths, register a distinct canonical resource for each entry point and route its protected-resource handle explicitly.

`authorization_servers` may contain more than one issuer. Each value must use canonical HTTPS issuer spelling: lowercase scheme and host, with no userinfo, default port, dot segments, query, or fragment. OAuth issuer comparison is exact. The MCP client chooses an authorization server and must keep credentials and tokens separate for each issuer. A resource registered with `OAuthAuthorizationServer.protectResource()` defaults this list to that server's configured `issuer`; the standalone `createOAuthResourceServer()` requires it explicitly.

### Authorization server metadata

The provider publishes RFC 8414 metadata containing:

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `protected_resources`, containing the authorization server's registered canonical resources
- `jwks_uri`, when RFC 9068 JWT access tokens are enabled
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

`completeAuthorization()` stores a new grant and, by default, revokes existing grants for the same user, client, and resource after the new grant is safely stored. A grant for another registered resource is a separate authorization and is not revoked. Set `revokeExistingGrants: false` only when the application intentionally allows concurrent grants within the same resource.

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

The compatibility flag prevents outbound CIMD fetches from using legacy same-zone origin routing, which is necessary for SSRF protection. The provider advertises `client_id_metadata_document_supported: true` only when both settings are present.

CIMD validation includes:

- HTTPS URL with a non-root path.
- A document `client_id` exactly matching its URL.
- Non-empty `client_name` and `redirect_uris` fields.
- Exact authorization-request redirect URI validation, with RFC 8252 loopback port handling.
- A 5 KB response size limit and 10 second fetch timeout.
- Safe URI schemes for client metadata fields.

CIMD currently supports only `token_endpoint_auth_method: "none"`.

When a CIMD document cannot be fetched or validated, the token endpoint returns a generic `invalid_client` response and reports diagnostics through `onError.internal`. `OAuthHelpers` methods that resolve a CIMD client throw the exported `CimdFetchError`, allowing applications to distinguish an upstream metadata failure from a client that does not exist. See [Advanced configuration](https://github.com/cloudflare/workers-oauth-provider/blob/main/docs/advanced-configuration.md#cimd-fetch-errors) for an example.

### Dynamic Client Registration

Set `clientRegistrationEndpoint` to enable RFC 7591 Dynamic Client Registration:

```ts
clientRegistrationEndpoint: '/oauth/register';
```

MCP 2026-07-28 deprecates DCR for new implementations in favor of CIMD. The endpoint remains useful for compatibility with clients that do not support CIMD.

Registration accepts only authentication methods, grants, and response types implemented by the configured provider, and rejects inconsistent grant/response combinations before storage. Omitted metadata uses the RFC 7591 defaults: `client_secret_basic`, `grant_types: ["authorization_code"]`, and `response_types: ["code"]`.

An explicitly supplied `token_endpoint_auth_method` is enforced exactly. When it is omitted, no explicit-method marker is stored and the client may use either `client_secret_basic` or `client_secret_post`, provided the same stored secret validates. Client records written by earlier releases have no marker and receive the same compatibility. This never crosses between `none` and a secret method and does not apply to CIMD clients.

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

An authorization server may register one or more protected resources. Each resource has one canonical `resourceMetadata.resource`: an absolute HTTPS URI without a fragment, with lowercase `https` and a lowercase host, and an RFC 3986-safe producer serialization. Userinfo, default ports, dot-segment paths, and an empty path before a query are rejected because `Request` would rewrite them before RFC 9728 comparison. A bare origin is the only empty-path exception; use `/` before a query. Query components are supported but discouraged by RFC 9728.

Every authorization grant and access token is bound to exactly one registered resource. A central authorization server can therefore issue separate Calendar and Drive tokens from one KV namespace, but it never turns those into one multi-audience bearer token. Completing a new authorization for Drive does not replace the same user and client's Calendar grant.

Conforming MCP clients are required to send `resource` in authorization and token requests. Resource selection and compatibility work as follows:

- When the authorization server has one registered resource, that sole resource is selected if an authorization request omits `resource`. This preserves existing `OAuthProvider` behavior.
- When it has multiple registered resources, an authorization request must identify exactly one of them. Set `defaultResource` on `OAuthAuthorizationServer` only when older clients that omit `resource` should be routed to a deliberate compatibility default.
- An authorization-code or refresh-token request may omit `resource`; the server inherits the resource already stored on the grant. If present, it must match that grant and cannot retarget it.
- Malformed, unknown, or multi-valued resource input returns `invalid_target` before code consumption, callbacks, refresh rotation, or storage writes.

ASCII case differences in the URI scheme and host are accepted, but port, path, query, trailing slash, and array cardinality remain strict. The authorization server always stores and returns the configured lowercase scheme-and-host spelling. The token response includes the selected resource, and the access-token audience contains that resource alone.

Token exchange cannot change the resource. Both the subject-token audience and any explicit requested resource must resolve to the same registered canonical value. Internally and externally validated tokens are accepted at a protected route only when their audience matches that route's resource.

Path-aware API validation uses path-boundary prefix matching. A canonical audience for `https://example.com/mcp` covers `/mcp` and `/mcp/tools`, but not `/mcp-other`. A canonical trailing slash remains significant.

### Upgrading to 1.0

The existing combined `OAuthProvider` configuration has one `resourceMetadata.resource`. That sole resource automatically acts as both the omitted-authorization default and the migration destination for grants created before resource binding, so existing single-resource clients can continue without adding a `resource` parameter.

For a multi-resource `OAuthAuthorizationServer`, `defaultResource` and `legacyGrantResource` solve different compatibility problems:

- `defaultResource` selects the resource for a new authorization request that omits `resource`.
- `legacyGrantResource` is the server-controlled migration destination for an old stored grant that has no resource. A client-supplied token-request parameter cannot choose or change this destination.

Both values must name a registered resource. If a multi-resource server omits `legacyGrantResource`, an old unbound grant cannot be migrated safely and must be reauthorized. A stored grant already bound to a registered resource keeps that resource; a grant bound to an unregistered value fails closed.

Previously issued access tokens with no audience are rejected by 1.0's protected-resource check, but an eligible refresh grant can acquire the server-selected migration resource on refresh. Multiple resources can share the same authorization server, provider implementation, and KV namespace; separate storage is an optional deployment boundary, not a resource-binding requirement.

The 1.0 API removes `resourceMatchOriginOnly`. Canonical matching with scheme/host case tolerance replaces it.

## Scopes and step-up authorization

`scopesSupported` is published only in authorization server metadata. Configure each protected resource's `resourceMetadata.scopes_supported` explicitly with the minimal scopes required for its basic functionality and baseline Bearer challenges.

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
- One authorization server with multiple same-Worker or separately routed MCP resources.
- Opt-in RFC 9068 JWT access tokens with stateful confidential props or offline public-claim validation.
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

The existing `OAuthProvider` combined configuration uses these options:

| Option                             | Purpose                                                  | Default                                  |
| ---------------------------------- | -------------------------------------------------------- | ---------------------------------------- |
| `apiRoute` and `apiHandler`        | Protect one or more route prefixes with one handler      | Use these or `apiHandlers`               |
| `apiHandlers`                      | Map protected route prefixes to different handlers       | Use this or `apiRoute` plus `apiHandler` |
| `defaultHandler`                   | Handle authorization UI and other unprotected routes     | Required                                 |
| `authorizeEndpoint`                | Application-owned authorization and consent endpoint     | Required                                 |
| `tokenEndpoint`                    | Provider-owned token and revocation endpoint             | Required                                 |
| `clientRegistrationEndpoint`       | Enable RFC 7591 DCR                                      | Disabled                                 |
| `scopesSupported`                  | Publish authorization server scopes                      | Omitted                                  |
| `resourceMetadata.resource`        | Canonical HTTPS resource and token audience              | Required                                 |
| `clientIdMetadataDocumentEnabled`  | Enable CIMD lookup and advertisement                     | `false`                                  |
| `allowPlainPKCE`                   | Permit the legacy plain PKCE method                      | `false`                                  |
| `allowImplicitFlow`                | Enable implicit token responses                          | `false`                                  |
| `disallowPublicClientRegistration` | Reject public clients at DCR                             | `false`                                  |
| `clientRegistrationCallback`       | Apply application policy before storing a DCR client     | None                                     |
| `allowTokenExchangeGrant`          | Enable RFC 8693                                          | `false`                                  |
| `tokenExchangeCallback`            | Update props, scopes, or lifetimes during token exchange | None                                     |
| `resolveExternalToken`             | Validate external bearer credentials (advanced)          | None                                     |
| `enterpriseManagedAuthorization`   | Enable experimental ID-JAG grant support                 | Disabled                                 |
| `onError`                          | Observe or replace OAuth error responses                 | Logs a warning                           |

The functional role API adds these surfaces without removing `OAuthProvider`:

| Surface                                          | Purpose                                                                     |
| ------------------------------------------------ | --------------------------------------------------------------------------- |
| `new OAuthAuthorizationServer({ issuer, … })`    | Create the AS role with a canonical RFC 8414 issuer                         |
| `createJwtAccessTokens({ … })`                   | Install JWT signing, reading, and JWKS while retaining stateful token props |
| `accessTokenFormat(context)`                     | Select opaque or JWT format for each newly issued access token              |
| `createJwtAccessTokenValidator({ … })`           | Validate pinned JWT claims offline for one fixed resource                   |
| `protectResource({ resourceMetadata, handler })` | Register and host one protected resource, returning its fetch surface       |
| `registerResource(resource)`                     | Register a canonical audience hosted by another Worker or service           |
| `defaultResource`                                | Select a deliberate default for new authorization requests that omit it     |
| `legacyGrantResource`                            | Select the server-controlled migration target for old unbound grants        |
| `getOAuthApi(env)`                               | Obtain OAuth helpers for an application-owned authorization route           |
| `validateToken(token, resource, env)`            | Validate a provider token against one fixed registered audience             |
| `createOAuthResourceServer({ … })`               | Create a standalone resource role around an application validation callback |

Consult the exported `OAuthProviderOptions`, `OAuthAuthorizationServerOptions`, resource-server callback interfaces, and JSDoc in [`src/oauth-provider.ts`](https://github.com/cloudflare/workers-oauth-provider/blob/main/src/oauth-provider.ts) for the complete typed API.

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
- [JSON Web Token Profile for OAuth 2.0 Access Tokens, RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html)
- [OAuth 2.0 Token Exchange, RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)
- [Resource Indicators for OAuth 2.0, RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)
- [OAuth 2.0 Authorization Server Issuer Identification, RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207)
- [OAuth 2.0 Protected Resource Metadata, RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)
- [OAuth Client ID Metadata Documents](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00)
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
