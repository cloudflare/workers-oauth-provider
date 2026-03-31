---
'@cloudflare/workers-oauth-provider': minor
---

Add `resourceOriginMatching` option for seamless migration from origin-only to path-aware resource URIs. When enabled, resource downscoping validation compares only the origin (scheme + host + port) instead of exact URI matching, allowing grants issued before v0.4.0 (with origin-only resources) to work with path-aware resource requests without invalidating existing refresh tokens.
