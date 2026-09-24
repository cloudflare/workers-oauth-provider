# Split workers

The [README quick start](../../README.md#quick-start) as two deployable Workers:

- `auth-server/` — `OAuthAuthorizationServer`: discovery, token, registration, your `/authorize` page, and `validateToken` for resource Workers.
- `mcp-server/` — `OAuthResourceServer` for `https://mcp.example.com/mcp`, validating tokens over a Service Binding to `auth-server`.

`e2e.test.ts` runs both in workerd and walks an MCP client from the first `401` to an authorized call (`npx vitest run examples`). It also fails if this code and the README quick start drift apart.

To deploy your own: create a KV namespace and put its id in `auth-server/wrangler.jsonc`, replace the `example.com` hostnames, delete the `alias` lines, `npm install @cloudflare/workers-oauth-provider`, then `npx wrangler deploy` in each directory (auth-server first, since mcp-server binds to it).
