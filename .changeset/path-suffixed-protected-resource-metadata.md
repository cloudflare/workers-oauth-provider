---
'@cloudflare/workers-oauth-provider': patch
---

Support path-suffixed well-known URLs for OAuth Protected Resource Metadata (RFC 9728 §3.1). Resources with path components (e.g. `https://example.com/mcp`) now correctly serve metadata at `/.well-known/oauth-protected-resource/mcp` and return the derived resource identifier in the `resource` field.
