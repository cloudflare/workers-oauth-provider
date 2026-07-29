---
'@cloudflare/workers-oauth-provider': patch
---

Return RFC-compliant `401 invalid_client` responses for malformed HTTP Basic client credentials, recognize the Basic scheme case-insensitively, and include the required Basic challenge on authentication failures.
