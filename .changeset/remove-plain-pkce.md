---
'@cloudflare/workers-oauth-provider': patch
---

The `allowPlainPKCE` option is removed; only S256 PKCE is accepted, as MCP requires. Passing `allowPlainPKCE: true` throws at construction instead of being silently ignored. An authorization code issued with a plain challenge before the upgrade is refused at the token endpoint with `invalid_grant`.
