---
'@cloudflare/workers-oauth-provider': patch
---

The implicit grant is removed, along with the `allowImplicitFlow` option. OAuth 2.1 dropped it and MCP requires the authorization code flow with PKCE. `response_type=token` is now always answered with `unsupported_response_type`, and passing `allowImplicitFlow: true` throws at construction instead of being silently ignored. Implicit grants were stored without an expiry, so each implicit authorization left a grant record in KV for good.
