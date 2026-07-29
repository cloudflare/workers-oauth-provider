---
'@cloudflare/workers-oauth-provider': minor
---

Add token introspection endpoint (RFC 7662). Enable with `introspectionEndpoint`. Confidential clients only; returns `active: false` for tokens not owned by the requesting client.
