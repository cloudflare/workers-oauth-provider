---
'@cloudflare/workers-oauth-provider': minor
---

Add `enforceMcpRedirectUriSecurity` to restrict registered, programmatic, and CIMD redirect URIs to HTTPS or HTTP loopback addresses. This provides the redirect transport policy required by the MCP authorization security specification while preserving private-use URI schemes for non-MCP deployments by default.
