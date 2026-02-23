---
'@cloudflare/workers-oauth-provider': minor
---

Require strict single-use refresh tokens for public clients per OAuth 2.1 Section 4.3.1. Confidential clients retain the grace period for network resilience.
