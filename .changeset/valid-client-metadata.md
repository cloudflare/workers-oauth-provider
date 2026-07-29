---
'@cloudflare/workers-oauth-provider': minor
---

Validate configured scopes and registered OAuth client capabilities. Dynamic registration now applies RFC 7591 defaults, rejects unsupported or inconsistent authentication, grant, and response types before storage, and applies the same capability checks to CIMD metadata.
