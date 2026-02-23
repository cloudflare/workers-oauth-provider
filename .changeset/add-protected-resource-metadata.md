---
'@cloudflare/workers-oauth-provider': patch
---

Add `/.well-known/oauth-protected-resource` endpoint (RFC 9728) for OAuth 2.0 Protected Resource Metadata discovery, as required by the MCP authorization specification. The endpoint is always served with sensible defaults (request origin as resource and authorization server), and can be customized via the new `resourceMetadata` option.
