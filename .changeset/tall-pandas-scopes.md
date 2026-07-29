---
'@cloudflare/workers-oauth-provider': minor
---

Include protected resource scopes in bearer challenges for MCP scope selection and omit `offline_access` from challenges and RFC 9728 `scopes_supported`, since refresh-token issuance is an authorization server capability rather than a protected resource requirement.
