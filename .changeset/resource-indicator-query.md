---
'@cloudflare/workers-oauth-provider': patch
---

Accept a resource indicator that names the protected resource's URL with extra query parameters. An MCP client configured with `https://mcp.example.com/mcp?mode=direct` sends that URL as `resource`; the protected route already covers it (it accepts the resource's tokens and points its 401 at the resource's metadata), but `/authorize` and `/token` rejected it with `invalid_target`. The value now maps to the configured resource, which stays the token audience. Path, port and the resource's own query parameters remain strict.
