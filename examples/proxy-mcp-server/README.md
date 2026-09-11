# Proxy MCP server

One Worker that is both the OAuth 2.1 authorization server and the MCP resource server.
Every request to `/mcp` is proxied through `OAuthProvider`, which resolves the bearer
token, checks that it is live and issued for this resource, and only then hands the
request to an MCP server running in the same isolate. This is the simplest MCP
authorization topology: one deployment, one hostname, one KV namespace, no bindings.

```
                      http://localhost:8787 (one Worker)
  ┌──────────────┐    ┌─────────────────────────────────────────────┐
  │  MCP client  │    │  OAuthProvider                              │
  │              │    │                                             │
  │  discovery ──┼───►│  /.well-known/oauth-authorization-server    │
  │              │    │  /.well-known/oauth-protected-resource/mcp  │
  │  register  ──┼───►│  /oauth/register       (DCR, or use CIMD)   │
  │  authorize ──┼───►│  /authorize ──► defaultHandler (login page) │
  │  token     ──┼───►│  /oauth/token          (+ RFC 7009 revoke)  │
  │              │    │                                             │
  │  MCP calls ──┼───►│  /mcp ─ token check ─► apiHandler ──┐       │
  │              │    │                                     ▼       │
  │              │    │                     McpServer (whoami, add) │
  └──────────────┘    └─────────────────────────────────────────────┘
                                         │
                                         ▼
                                   OAUTH_KV (clients, grants, tokens)
```

Files: `src/index.ts` wires the provider, `src/authorize.ts` owns the interactive
authorization endpoint, `src/login-page.ts` is the placeholder login, `src/mcp.ts` is the
protected handler, `src/config.ts` holds what the two halves share.

## Prerequisites

- Node 22 and npm
- `npm install` in this directory. The provider is linked from the repository root
  through `"@cloudflare/workers-oauth-provider": "file:../.."`, so run `npm run build` at
  the root first if `dist/` is older than `src/`.
- `curl`, `jq`, and `openssl` for the by-hand recipe below

## Run locally

```sh
npm run dev    # http://localhost:8787
curl http://localhost:8787/.well-known/oauth-authorization-server
curl -i http://localhost:8787/mcp    # 401 with WWW-Authenticate: Bearer ... resource_metadata="..."
```

Plain `http` works here because each Worker sets `allowHttp: true` from the top-level `define`
map. The production environment inlines `false`: OAuth 2.1 requires `https` everywhere else.

The canonical resource is a build-time constant, inlined by wrangler's `define` map,
because an `OAuthProvider` is constructed once at module scope, before any request exists,
and its constructor validates the resource. `define` is not inherited by a named
environment, so each environment repeats it, together with `ALLOW_HTTP`:

| Environment      | `MCP_RESOURCE`                | Used by                   |
| ---------------- | ----------------------------- | ------------------------- |
| top level        | `http://localhost:8787/mcp`   | `npm run dev`, `npm test` |
| `env.production` | `https://mcp.example.com/mcp` | `npm run deploy`          |

The alternative is to build the provider lazily inside `fetch()` from `env` vars and
memoize it for the life of the isolate.

Use `localhost`, not `127.0.0.1`: the issuer is derived from the request origin, so the
two hostnames are two different authorization servers and tokens do not cross between
them. Only the RFC 9728 path-suffix form of the resource metadata is published, so
`/.well-known/oauth-protected-resource` with no `/mcp` suffix is a 404 by design.

## Run the tests

```sh
npm test
npm run typecheck
```

`test/e2e.test.ts` boots the real Worker with `createTestHarness()` from wrangler and runs
the whole flow: discovery, Bearer challenges, dynamic client registration, the
authorization code grant with PKCE S256 through the login page, MCP `initialize`,
`tools/list` and `tools/call`, scope filtering, refresh, and revocation. It runs the same
build as `npm run dev`, so it uses the same canonical URLs. Requests go through
`harness.getWorker(name).fetch()` because `harness.fetch()` rewrites `https` to `http`,
which this topology cannot survive.

## Try it with an MCP client

Point any MCP client that speaks OAuth at `http://localhost:8787/mcp`. It discovers
`/.well-known/oauth-protected-resource/mcp` from the `WWW-Authenticate` challenge,
registers itself, and opens the login page.

By hand, with the dev server running:

```sh
CLIENT=$(curl -s -X POST http://localhost:8787/oauth/register -H 'content-type: application/json' \
  -d '{"client_name":"curl","redirect_uris":["http://127.0.0.1:3000/callback"],
       "grant_types":["authorization_code"],"response_types":["code"],
       "token_endpoint_auth_method":"none"}' | jq -r .client_id)

# PKCE S256 is mandatory, so mint a verifier and its challenge.
VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -binary -sha256 | base64 | tr '+/' '-_' | tr -d '=')

# Approve. A browser would GET this first and render the form; the POST is the submission.
# `scope` must include mcp:read or the MCP server answers 403.
CODE=$(curl -s -i -X POST "http://localhost:8787/authorize?response_type=code&client_id=$CLIENT\
&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback&scope=mcp%3Aread+mcp%3Awrite&state=demo\
&resource=https%3A%2F%2Flocalhost%3A8787%2Fmcp&code_challenge=$CHALLENGE&code_challenge_method=S256" \
  -d 'username=demo&action=approve' | sed -n 's/^[Ll]ocation:.*[?&]code=\([^&]*\).*/\1/p')

# `resource` must repeat here: it is what binds the token to the MCP resource.
TOKEN=$(curl -s -X POST http://localhost:8787/oauth/token -d grant_type=authorization_code \
  -d "code=$CODE" -d "client_id=$CLIENT" -d 'redirect_uri=http://127.0.0.1:3000/callback' \
  -d "code_verifier=$VERIFIER" -d 'resource=http://localhost:8787/mcp' | jq -r .access_token)

curl -s http://localhost:8787/mcp -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}'
```

`whoami` echoes the `userId` from the login form, the client id, and the granted scopes:
the clearest way to see what the token carried.

## Deploy

1. Create the KV namespace and put its id in `wrangler.jsonc` under
   `env.production.kv_namespaces`: `npx wrangler kv namespace create OAUTH_KV`.
2. Replace the placeholder domain in two places. `env.production.routes` attaches the
   custom domain, and `env.production.define.MCP_RESOURCE` must be `https://<your-host>/mcp`
   and match that route exactly: the resource string is compared strictly, with a lowercase
   scheme and host, no default port, and a significant trailing slash.
3. `npm run deploy` (`wrangler deploy --env production`).

The issuer is derived from the request origin, so it becomes `https://<your-host>` on its
own. Nothing else changes between local and production.

## Before production

- **Replace the login placeholder.** `src/login-page.ts` accepts any username and
  `src/authorize.ts` believes it. Put a real session behind it: a signed cookie, an
  upstream IdP such as GitHub or Google, or Cloudflare Access in front of `/authorize`.
  Once there is a session, the consent form also needs a CSRF token. See
  [docs/advanced-configuration.md](../../docs/advanced-configuration.md) and the
  upstream-federation demos in [cloudflare/ai](https://github.com/cloudflare/ai).
- **Decide a scope policy.** `grantableScopes()` only drops scopes this server never
  advertised, which is the floor rather than a policy: the provider publishes
  `scopesSupported` but never enforces it, so an unfiltered request would mint a token
  carrying anything a client asked for. Decide per user and per client what to grant.
- **Know what scope the handler can see.** `ctx.props` is the data stored on the _grant_,
  and this configuration exposes no effective token scope, so `src/mcp.ts` cannot tell that
  a client narrowed its token at the token endpoint. Treat the check there as a grant-level
  gate; a resource that needs per-token scope wants the split topology in
  [../separate-authorization-server](../separate-authorization-server), where the validator
  returns the token's own scope.
- **Set token lifetimes.** `accessTokenTTL`, `refreshTokenTTL`, and `clientRegistrationTTL`
  default to 1 hour, 30 days, and 90 days. Every MCP request is authorized on its own, so a
  short access token TTL is cheap.
- **Add observability.** Use the provider's `onError` hook to report OAuth failures rather
  than letting them disappear into a 401.
