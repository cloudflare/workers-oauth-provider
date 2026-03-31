---
'@cloudflare/workers-oauth-provider': minor
---

Path-aware resource URIs (RFC 9728):

- Support path-suffixed well-known URLs for OAuth Protected Resource Metadata (RFC 9728 §3.1). Resources with path components (e.g. `https://example.com/mcp`) now correctly serve metadata at `/.well-known/oauth-protected-resource/mcp` and return the derived resource identifier in the `resource` field.
- Include the request path in the `resource_metadata` URL within `WWW-Authenticate` headers (RFC 9728 §5.1). API endpoints with path components now advertise the correct path-suffixed metadata URL so clients can discover the resource-specific metadata.
- Add `resourceMatchOriginOnly` option for seamless migration. When enabled, resource downscoping validation compares only the origin (scheme + host + port) instead of exact URI matching, allowing grants issued before v0.4.0 (with origin-only resources) to work with path-aware resource requests without invalidating existing refresh tokens.
