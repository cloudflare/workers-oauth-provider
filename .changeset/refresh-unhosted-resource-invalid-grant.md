---
'@cloudflare/workers-oauth-provider': patch
---

A refresh of a grant bound to a resource the server no longer hosts now fails with `invalid_grant`, even when the request names that resource. MCP clients repeat their grant's `resource` on every refresh, so after a server dropped a resource (an `/sse` endpoint, or the bare origin a 0.x server advertised at its root metadata URL), those refreshes got `invalid_target`. The MCP SDKs throw on `invalid_target`, so the user stayed stuck until they removed the server. On `invalid_grant` they discard their tokens and sign the user in again. The description now says so: "The authorization grant is bound to a resource this server no longer serves. Authorize again."

A refresh of a valid grant that names a resource the server doesn't host still gets `invalid_target`. The resource is still checked before the `tokenExchangeCallback` runs or anything is written.
