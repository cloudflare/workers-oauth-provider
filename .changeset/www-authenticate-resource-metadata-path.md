---
'@cloudflare/workers-oauth-provider': patch
---

Include the request path in the `resource_metadata` URL within `WWW-Authenticate` headers (RFC 9728 §5.1). API endpoints with path components (e.g. `/mcp`) now advertise the correct path-suffixed metadata URL so clients can discover the resource-specific metadata.
