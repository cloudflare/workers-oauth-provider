---
'@cloudflare/workers-oauth-provider': patch
---

Fix RFC 8707 path-aware audience validation for resource indicators with path components. Tokens with path-specific audiences (e.g., `https://example.com/api`) now correctly validate against matching request paths.
