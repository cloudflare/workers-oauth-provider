---
'@cloudflare/workers-oauth-provider': patch
---

Add RFC 8252 Section 7.3 compliance: allow any port for loopback redirect URIs (127.x.x.x, ::1) to support native apps that use ephemeral ports
