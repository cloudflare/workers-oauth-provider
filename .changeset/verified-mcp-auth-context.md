---
'@cloudflare/workers-oauth-provider': patch
---

Attach verified metadata for provider-issued access tokens to the request `ExecutionContext` so compatible MCP SDK v2 integrations can populate standard `AuthInfo`. Existing `ctx.props` behavior is unchanged, and external-token resolvers remain props-only.
