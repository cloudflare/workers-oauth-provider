# Separate authorization server and MCP resource server

Two Workers: one is the OAuth 2.1 authorization server, the other is the MCP resource
server. The MCP Worker holds no OAuth state and never touches the KV namespace; it
validates bearer tokens by calling a named `WorkerEntrypoint` on the authorization server
over a private Service Binding that is pinned to its own resource identifier. This is the
topology to copy when the team that owns identity is not the team that owns the MCP server.

```
                      https://localhost:8787 (authorization server)
  ┌──────────────┐    ┌─────────────────────────────────────────────┐
  │  MCP client  │    │  OAuthAuthorizationServer                   │
  │  discovery ──┼───►│  /.well-known/oauth-authorization-server    │
  │  register  ──┼───►│  /oauth/register       (DCR, or use CIMD)   │
  │  authorize ──┼───►│  /authorize            (this app)           │
  │  token     ──┼───►│  /oauth/token          (+ RFC 7009 revoke)  │
  │              │    └─────────────────────────────────────────────┘
  │              │       │ OAUTH_KV                 ▲ AUTHORIZATION_SERVER (Service
  │              │       ▼ (clients, grants,        │ Binding, entrypoint McpTokenValidator,
  │              │          tokens)                 │ pinned to https://localhost:8788/mcp)
  │              │    ┌─────────────────────────────────────────────┐
  │  MCP calls ──┼───►│  https://localhost:8788 (MCP resource)      │
  │              │    │  /.well-known/oauth-protected-resource/mcp  │
  └──────────────┘    │  /mcp ──► McpServer (whoami, add)           │
                      │  no KV, no client or token storage          │
                      └─────────────────────────────────────────────┘
```

Files: each Worker has an `src/index.ts` that wires its OAuth object; the authorization
server adds `authorize.ts` and `login-page.ts` (the placeholder login), the MCP Worker adds
`mcp.ts`, and `shared/config.ts` holds what the two agree on.

## Prerequisites

- Node 22 and npm
- `npm install` in this directory. The provider is linked from the repository root
  through `"@cloudflare/workers-oauth-provider": "file:../.."`, so run `npm run build` at
  the root first if `dist/` is older than `src/`.
- `curl`, `jq`, and `openssl` for the by-hand recipe below

## Run locally

Two terminals, because these are two Workers. Start the authorization server first:

```sh
npm run dev:auth    # https://localhost:8787
npm run dev:mcp     # https://localhost:8788
curl -k https://localhost:8787/.well-known/oauth-authorization-server
curl -k https://localhost:8788/.well-known/oauth-protected-resource/mcp
curl -ki https://localhost:8788/mcp    # 401 with WWW-Authenticate: Bearer ... resource_metadata="..."
```

`--local-protocol https` is not optional. The issuer (`https://localhost:8787`) and the
resource (`https://localhost:8788/mcp`) must be absolute HTTPS URLs on this branch, and the
library compares them against the request URL, so a plain-HTTP dev server never matches
itself. The certificate is self-signed, so pass `-k` to curl and set
`NODE_TLS_REJECT_UNAUTHORIZED=0` for a Node client.

Both dev scripts pass `--inspector-port` because two `wrangler dev` sessions otherwise
fight over the same debugger port and the second exits with `Address already in use`, so
ports 8787, 8788, 9229, and 9230 must all be free.

The issuer and both resource identifiers are build-time constants, inlined by wrangler's
`define` map, because each OAuth object is constructed once at module scope, before any
request exists, and its constructor validates them. `define` is not inherited by a named
environment, so each environment repeats it: the top level names the localhost URLs above
and serves `npm run dev:auth`, `npm test` and `npm run conformance`, while `env.production`
names the deployed domains. The alternative is to build both objects lazily inside
`fetch()` from `env` vars and memoize them. Either way these are protocol values rather
than mere ports, so moving a Worker means editing the `define` map as well as `--port`, and
the resource string is written in five places that must agree byte for byte:
`registerResource()`, the pinned `validateToken()` call, `resourceMetadata.resource`, and
the `define` map in each of the two configs.

Wrangler's dev registry connects the Service Binding between the two sessions. Until the
authorization server is running, the MCP Worker prints
`env.AUTHORIZATION_SERVER ... [not connected]` and token validation fails closed with a
bodyless `503`. Use `localhost`, not `127.0.0.1`: requests are matched against the
configured issuer and resource, so `https://127.0.0.1:8787/...` answers a bare 404, and
only the RFC 9728 path-suffix form of the resource metadata is published, so
`/.well-known/oauth-protected-resource` with no `/mcp` suffix is a 404 by design.

## Run the tests

```sh
npm test
npm run typecheck
```

`test/e2e.test.ts` starts both Workers in one `createTestHarness()` server and runs the
whole flow: discovery, dynamic client registration, the authorization code grant with PKCE
S256 through the login page, an MCP `tools/call`, scope enforcement at the resource,
refresh, revocation taking effect across the binding on the next request, and a token
minted for the _other_ registered audience being rejected at the MCP Worker. It runs the
same build as the dev scripts, so it shares their canonical URLs, and addresses each Worker
with `harness.getWorker(name).fetch()`.

## Run the MCP conformance suite

```sh
npm run conformance    # stop the dev servers first: this needs ports 8787, 8788 and 3000
```

`scripts/conformance.mjs` starts both dev servers, registers a public client by DCR, runs
the official `@modelcontextprotocol/conformance` `authorization` scenarios against
`https://localhost:8787`, then plays the part of the browser: it reads the authorization
URL from the CLI's output, submits the login form, and follows the redirect into the CLI's
callback server. It exits non-zero if any check is not `SUCCESS` (the CLI itself exits 0
even when a check fails) and writes raw results to `conformance-results/`. Expected:

```
SUCCESS  authorization-code-grant
SUCCESS  authorization-server-metadata
SUCCESS  authorization-server-metadata-cimd
```

The suite's authorization request omits both `resource` and `scope` and has no flag for
either: `defaultResource` is what keeps the grant scenario green on a server with two
audiences, and the token it obtains carries no scope, so `/mcp` would refuse it with
`403 insufficient_scope`. There are no resource-server scenarios today, so the binding is
covered only by `npm test`.

## Try it with an MCP client

Point any MCP client that speaks OAuth at `https://localhost:8788/mcp`. It reads the
protected resource metadata, discovers `https://localhost:8787`, registers itself, and
opens the login page. Most clients reject a self-signed certificate; a Node client can be
started with `NODE_TLS_REJECT_UNAUTHORIZED=0`, anything else wants a deployed hostname.

By hand, with both dev servers running:

```sh
CLIENT=$(curl -sk -X POST https://localhost:8787/oauth/register -H 'content-type: application/json' \
  -d '{"client_name":"curl","redirect_uris":["http://127.0.0.1:3000/callback"],
       "grant_types":["authorization_code"],"response_types":["code"],
       "token_endpoint_auth_method":"none"}' | jq -r .client_id)

# PKCE S256 is mandatory, so mint a verifier and its challenge.
VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -binary -sha256 | base64 | tr '+/' '-_' | tr -d '=')

# Approve. A browser would GET this first and render the form; the POST is the submission.
# `scope` must include mcp:read or the MCP server answers 403.
CODE=$(curl -sk -i -X POST "https://localhost:8787/authorize?response_type=code&client_id=$CLIENT\
&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback&scope=mcp%3Aread+mcp%3Awrite&state=demo\
&resource=https%3A%2F%2Flocalhost%3A8788%2Fmcp&code_challenge=$CHALLENGE&code_challenge_method=S256" \
  -d 'username=demo&action=approve' | sed -n 's/^[Ll]ocation:.*[?&]code=\([^&]*\).*/\1/p')

# `resource` must repeat here: it is what binds the token to the MCP resource.
TOKEN=$(curl -sk -X POST https://localhost:8787/oauth/token -d grant_type=authorization_code \
  -d "code=$CODE" -d "client_id=$CLIENT" -d 'redirect_uri=http://127.0.0.1:3000/callback' \
  -d "code_verifier=$VERIFIER" -d 'resource=https://localhost:8788/mcp' | jq -r .access_token)

curl -sk https://localhost:8788/mcp -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}'
```

`whoami` echoes the `userId` from the login form, the client id, and the effective token
scope: the clearest way to see what the token carried.

## Deploy

1. Create the KV namespace and put its id in `authorization-server/wrangler.jsonc` under
   `env.production.kv_namespaces`: `npx wrangler kv namespace create OAUTH_KV`. Only the
   authorization server stores anything.
2. Replace the placeholder domains. `define`, `kv_namespaces`, `services`, and `routes` are
   all non-inheritable, so the `env.production` block in each config repeats them. The two
   Workers must agree on `MCP_RESOURCE` exactly: it is compared strictly, with a lowercase
   scheme and host, no default port, and a significant trailing slash.
3. Deploy the authorization server first (`npm run deploy:auth`), then the MCP server
   (`npm run deploy:mcp`).

   `wrangler deploy --env production` suffixes the Worker name, so the bound service in
   `mcp-server/wrangler.jsonc` carries the same suffix
   (`example-authorization-server-production`) and keeps `entrypoint: "McpTokenValidator"`.

4. Attach the custom domains (`auth.example.com`, `mcp.example.com`) to their Workers.

## Before production

- **Replace the login placeholder.** `authorization-server/src/login-page.ts` accepts any
  username and `authorize.ts` believes it. Put a real session behind it: a signed cookie,
  an upstream IdP such as GitHub or Google, or Cloudflare Access in front of `/authorize`,
  and add a CSRF token to the consent form. See
  [docs/advanced-configuration.md](../../docs/advanced-configuration.md) and the
  upstream-federation demos in [cloudflare/ai](https://github.com/cloudflare/ai).
- **Decide a scope policy.** `grantableScopes()` only drops scopes this server never
  advertised, which is a floor rather than a policy: the provider publishes
  `scopesSupported` but never enforces it. A client that omits `scope` gets an empty-scope
  token that `/mcp` refuses with `403`.
- **Keep reading scope from the token.** The validator copies `ValidatedAccessToken.scope`
  into `props` because only `props` reaches the handler. Reading scope from the grant props
  instead would silently grant more than a narrowed token carries.
- **Set token lifetimes.** `accessTokenTTL`, `refreshTokenTTL`, and `clientRegistrationTTL`
  default to 1 hour, 30 days, and 90 days. The MCP Worker keeps no token state, so
  revocation is immediate across the binding and a short access token TTL is cheap.
- **Keep the binding private.** `McpTokenValidator` is reachable only through the Service
  Binding. Do not add a public route that exposes token validation.
