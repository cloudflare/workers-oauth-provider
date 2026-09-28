# OAuth 2.1 Provider Framework for Cloudflare Workers

`@cloudflare/workers-oauth-provider` adds OAuth 2.1 authorization to HTTP APIs and remote MCP servers running on Cloudflare Workers.

> **Upgrading from 0.x, 1.0 or 1.1?** Read the [migration guide](docs/migration-1.0.md), which covers every change since 0.10 with code, or point your coding agent at [`skills/migrate-to-1.0/`](skills/migrate-to-1.0/SKILL.md), which also ships in the npm package.

## Install

```sh
npm install @cloudflare/workers-oauth-provider
```

The authorization server needs a KV namespace bound as `OAUTH_KV`, and the `global_fetch_strictly_public` compatibility flag if it accepts Client ID Metadata Documents.

## Quick start

An MCP deployment has two roles. The **authorization server** signs users in and issues tokens. The **resource server** is your MCP endpoint: it accepts those tokens and checks them with the authorization server over a [Service Binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/).

```ts
// auth-server/index.ts
const authorizationServer = new OAuthAuthorizationServer<Env>({
  issuer: 'https://auth.example.com',
  resources: ['https://mcp.example.com/mcp'],
  scopesSupported: ['mcp:read', 'mcp:write', 'offline_access'], // everything this server can grant
  clientIdMetadataDocumentEnabled: true,
});

export default class AuthServer extends WorkerEntrypoint<Env> {
  fetch(request: Request) {
    // /authorize is yours: parseAuthRequest(), sign the user in and ask for consent, completeAuthorization().
    if (new URL(request.url).pathname === '/authorize') return authorize(request, this.env);
    return authorizationServer.fetch(request, this.env, this.ctx); // discovery, token, revocation
  }

  // Resource servers call this over their Service Binding.
  validateToken(resource: string, token: string) {
    return authorizationServer.validateToken(resource, token, this.env);
  }
}
```

```ts
// mcp-server/index.ts
export default new OAuthResourceServer<Env, AuthProps>({
  resourceMetadata: {
    resource: 'https://mcp.example.com/mcp',
    authorization_servers: ['https://auth.example.com'],
  },
  requiredScopes: ['mcp:read'], // needed for any access; clients request these first
  validateToken: (env) => env.AUTH_SERVER.validateToken,
  handler: {
    fetch(request, env, ctx) {
      // ctx.props: what completeAuthorization() stored. ctx.auth: the verified token.
      // Step-up: a 403 naming the missing scope, and the client re-authorizes for it.
      const needed = request.method === 'GET' ? ['mcp:read'] : ['mcp:read', 'mcp:write'];
      if (!needed.every((scope) => ctx.auth.scope.includes(scope))) return insufficientScope(ctx.auth, needed);
      return Response.json({ userId: ctx.props.userId });
    },
  },
});
```

**[`examples/split-workers`](examples/split-workers)** has both Workers in full, including the `/authorize` handler and `wrangler.jsonc`, with an end-to-end test that runs them in workerd.

The resource server publishes its RFC 9728 metadata, answers unauthenticated requests with a challenge pointing at it, and accepts only tokens issued for its own resource. The handler owns authorization beyond that: scopes, ownership, tenancy.

On the wire both lists are called `scopes_supported`, as the specs name them, but they mean different things: `scopesSupported` is everything the authorization server can grant; a resource's `requiredScopes` is what any access needs, so MCP clients request it first, and more comes by step-up. The handler checks `ctx.auth.scope`: the library advertises the required scopes but doesn't enforce them, since only your code knows which scopes imply others. See [Scopes](docs/authorization-server.md#scopes-and-step-up-authorization).

## One Worker: `OAuthProvider`

The split roles above are the recommended shape. `OAuthProvider` remains fully supported for one Worker that is both the authorization server and its only resource, which was the 0.x shape: it combines the roles. Requests under `apiRoute` reach `apiHandler` with `ctx.props` and `ctx.auth`; everything else goes to `defaultHandler`, which owns `/authorize` and reaches the helpers as `env.OAUTH_PROVIDER`:

```ts
export default new OAuthProvider<Env>({
  apiRoute: '/mcp',
  apiHandler: McpApiHandler,
  defaultHandler, // your /authorize page
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  scopesSupported: ['mcp:read', 'mcp:write', 'offline_access'], // everything this server can grant
  resourceMetadata: {
    resource: 'https://mcp.example.com/mcp',
    authorization_servers: ['https://mcp.example.com'],
  },
  requiredScopes: ['mcp:read'], // needed for any access; clients request these first
  clientIdMetadataDocumentEnabled: true,
});
```

## Documentation

- [Resource servers](docs/resource-servers.md): more resources, both roles in one Worker, what the handler sees, other issuers.
- [Consent page](docs/consent-page.md): what it must show, Allow and Deny, remembering consent.
- [Signing in through another provider](docs/upstream-sign-in.md): GitHub, Google and friends as the identity step.
- [Authorization server reference](docs/authorization-server.md): the authorize endpoint, client registration (pre-registered, CIMD, DCR), PKCE and token lifetimes, resources and audiences, scopes, KV storage, every option.
- [MCP authorization discovery](docs/mcp-discovery.md): how a client gets from a `401` to your authorization server.
- [Advanced configuration](docs/advanced-configuration.md): external tokens, token exchange, `tokenExchangeCallback`, `onError`, Enterprise-Managed Authorization (experimental).
- [Storage schema](storage-schema.md): the KV layout. Tokens, codes and secrets are stored only as hashes; `props` are encrypted with a key only the token holder can unwrap.

## Standards

[MCP authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13), and RFCs [6750](https://datatracker.ietf.org/doc/html/rfc6750), [7009](https://datatracker.ietf.org/doc/html/rfc7009), [7591](https://datatracker.ietf.org/doc/html/rfc7591), [7636](https://datatracker.ietf.org/doc/html/rfc7636), [8414](https://datatracker.ietf.org/doc/html/rfc8414), [8693](https://datatracker.ietf.org/doc/html/rfc8693), [8707](https://datatracker.ietf.org/doc/html/rfc8707), [9207](https://datatracker.ietf.org/doc/html/rfc9207) and [9728](https://datatracker.ietf.org/doc/html/rfc9728), plus [Client ID Metadata Documents](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00), [OpenID Connect RP Metadata Choices](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html) and, experimentally, [MCP Enterprise-Managed Authorization](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization).

## Development

Node 24 or newer. `npm install`, `npm run build`, `npm run check`. Changes that affect behavior or the public API need a Changeset; see [AGENTS.md](AGENTS.md) for conventions, [SECURITY.md](SECURITY.md) for vulnerability reporting, and [HISTORY.md](HISTORY.md) for how the library began.
