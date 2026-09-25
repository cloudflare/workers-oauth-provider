# Resource servers

An `OAuthAuthorizationServer` issues tokens; a resource server accepts them. Every resource, whether it runs in the authorization server's Worker or in its own, is hosted the same way:

```ts
new OAuthResourceServer<Env, Props>({
  resourceMetadata: { resource, authorization_servers: [issuer] },
  requiredScopes: ['calendar:read'], // needed for any access; advertised, checked by your handler
  validateToken: (env, request) => (resource, token) =>
    Promise<{ props; audience; expiresAt?; scope?; userId?; clientId? } | null>,
  handler: { fetch(request, env, ctx) {} }, // ctx.props: Props, ctx.auth: OAuthResourceAuth
});
```

The host publishes RFC 9728 metadata at `/.well-known/oauth-protected-resource<path>`, answers unauthenticated requests with a Bearer challenge that names it and the `requiredScopes` to ask for (published as `scopes_supported`), calls your validator with its own canonical resource and the presented token, refuses a result whose `audience` is not that resource, and answers `503` when the validator throws. Only `validateToken` changes between the topologies below.

## What the handler sees

`ctx.props` is the application data the validator returned. `ctx.auth` is what was verified about the token: `{ token, audience, expiresAt?, scope, userId?, clientId? }`. `OAuthAuthorizationServer.validateToken()` fills all of it; a validator of your own reports what it knows and `scope` defaults to `[]`.

Scope policy is the handler's. When a valid token lacks what an operation needs, answer with `insufficientScope`, which builds the MCP scope challenge — `403`, `error="insufficient_scope"`, every scope the operation requires, and the same `resource_metadata` URL the `401` advertised — so the client can step up in one round trip:

```ts
handler: {
  fetch(request, env, ctx) {
    if (request.method === 'DELETE' && !ctx.auth.scope.includes('calendar:write')) {
      return insufficientScope(ctx.auth, ['calendar:write']);
    }
    // …
  },
},
```

A `WorkerEntrypoint` handler reads the same fields from `this.ctx`; declare it as `OAuthResourceContext<Props>` to type them. `OAuthProvider` sets `ctx.auth` for its `apiHandler` too, from its own token record, so a handler moves between the two hosts unchanged.

## Same Worker

```ts
const authorizationServer = new OAuthAuthorizationServer<Env>({
  issuer: 'https://auth.example.com',
  resources: ['https://calendar.example.com/mcp', 'https://drive.example.com/mcp'],
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
});

const local = (env: Env) => (resource: string, token: string) =>
  authorizationServer.validateToken(resource, token, env);

const calendar = new OAuthResourceServer<Env, AuthProps>({
  resourceMetadata: {
    resource: 'https://calendar.example.com/mcp',
    authorization_servers: ['https://auth.example.com'],
  },
  validateToken: local,
  handler: calendarHandler,
});
```

You own routing. This example (`npm install hono`) puts one Worker on three custom domains and uses Hono's hostname-aware path so no `switch` is needed; the original `Request` is forwarded as `c.req.raw` so URL validation sees the real origin:

```ts
const app = new Hono<{ Bindings: Env }>({
  getPath: (request) => `/${new URL(request.url).hostname}${new URL(request.url).pathname}`,
});

app.get('/auth.example.com/authorize', async (c) => {
  const oauth = authorizationServer.getOAuthApi(c.env);
  const request = await oauth.parseAuthRequest(c.req.raw); // render AuthorizationError safely in production
  const { redirectTo } = await oauth.completeAuthorization({
    request,
    userId: 'user-123',
    metadata: {},
    scope: request.scope,
    props: { userId: 'user-123', scopes: request.scope },
  });
  return c.redirect(redirectTo);
});
app.all('/auth.example.com/*', (c) => authorizationServer.fetch(c.req.raw, c.env, c.executionCtx));
app.all('/calendar.example.com/*', (c) => calendar.fetch(c.req.raw, c.env, c.executionCtx));
app.all('/drive.example.com/*', (c) => drive.fetch(c.req.raw, c.env, c.executionCtx));

export default app;
```

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

Authorization server metadata advertises every declared resource in `protected_resources`; each resource publishes its own protected resource metadata pointing back at the issuer. `resources` is fixed at construction and `defaultResource` and `legacyGrantResource` are checked against it then; a resource server that asks about an undeclared resource gets a rejection, which the host turns into `503`.

## Separate Workers

Only the authorization server can validate a token: the props are encrypted with a key wrapped by the token itself, and the token record lives in its KV. A resource Worker therefore asks it, over a Service Binding.

Authorization Worker, exposing the method from a `WorkerEntrypoint`:

```ts
import { WorkerEntrypoint } from 'cloudflare:workers';

export default class AuthServer extends WorkerEntrypoint<Env> {
  fetch(request: Request) {
    // Your /authorize route goes here too; everything else is the authorization server's.
    return authorizationServer.fetch(request, this.env, this.ctx);
  }
  validateToken(resource: string, token: string) {
    return authorizationServer.validateToken(resource, token, this.env);
  }
}
```

Resource Worker, with a binding to it:

```jsonc
{ "services": [{ "binding": "AUTH_SERVER", "service": "auth" }] }
```

```ts
import { OAuthResourceServer, type AuthorizationServerBinding } from '@cloudflare/workers-oauth-provider';

interface Env {
  AUTH_SERVER: AuthorizationServerBinding<AuthProps>; // or Service<AuthServer> from wrangler types
}

export default new OAuthResourceServer<Env, AuthProps>({
  resourceMetadata: {
    resource: 'https://calendar.example.com/mcp',
    authorization_servers: ['https://auth.example.com'],
  },
  validateToken: (env) => env.AUTH_SERVER.validateToken,
  handler,
});
```

The host calls the method it is handed with its resource and the token, so neither is repeated. The binding is not a URL: the validator is never exposed to the public internet, and the resource Worker cannot ask about another resource's tokens by accident because the host always passes its own. One RPC per request, on Cloudflare's network. `ctx.props` is the same `AuthProps` the authorization flow stored, decrypted by the authorization server; `ctx.auth` carries the token's scopes, subject and client back with it; and revocation is immediate.

## Another issuer, at your own risk

`validateToken` is just a function. A resource that accepts tokens from an authorization server that is not this package validates them itself — an RFC 7662 introspection call, a JWT library against that issuer's JWKS — and returns `{ props, audience, expiresAt }`:

```ts
validateToken: (env) => async (resource, token) => {
  const { payload } = await jwtVerify(token, keys, { issuer: OTHER_ISSUER, audience: resource, typ: 'at+jwt' });
  return { props: { userId: payload.sub! }, audience: resource, expiresAt: payload.exp };
},
```

The host still enforces the audience and expiry it is given, and it fails closed on a malformed `scope`, `userId` or `clientId`. Everything else about that issuer's tokens is between you and it. MCP's security guidance is blunt on the point that a resource server must accept only tokens issued for it; keep `audience` honest.

### Alongside your own tokens

One resource can also accept both this authorization server's tokens and an upstream API's own credentials, such as a proxy that lets users present their API token directly. Recognise the upstream's tokens by shape, and validate them yourself. Check the upstream first, and only by a shape the upstream uses, so an expired token of your own is never sent to a third party:

```ts
validateToken: (env) => async (resource, token) => {
  if (token.startsWith('cfut_')) {
    const upstream = await fetch('https://api.example.com/user', { headers: { Authorization: `Bearer ${token}` } });
    if (upstream.status === 429) {
      throw new OAuthError('temporarily_unavailable', {
        description: 'Upstream rate limited',
        statusCode: 429,
        headers: { 'Retry-After': upstream.headers.get('Retry-After') ?? '30' },
      });
    }
    if (!upstream.ok) return null; // 401 invalid_token
    return { props: await upstream.json(), audience: resource };
  }
  return env.AUTH_SERVER.validateToken(resource, token);
},
```

Return `null` for a token that isn't valid here, which gets the `401` challenge. Throw `OAuthError` for a specific answer: `invalid_token` becomes a `401` and `insufficient_scope` a `403` with its challenge (naming `requiredScopes`, or the resource's), each with a Bearer challenge; any other code keeps its status and headers. Anything else thrown is a `503`. Throw it in this Worker's validator: an `OAuthError` thrown in another Worker arrives over RPC as a plain `Error`. With the combined `OAuthProvider`, the same job is `resolveExternalToken`, which throws `ExternalTokenError`.
