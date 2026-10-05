---
'@cloudflare/workers-oauth-provider': patch
---

The 1.x migration guide and the `migrate-to-1.0` skill explain that the configured resource must be the one existing grants carry. 0.x stored the path each client connected to, such as `https://mcp.example.com/mcp`, even under `resourceMatchOriginOnly`. Configuring a different value, including the bare origin, signs every user out: their refreshes fail with `invalid_target` or `invalid_grant`. The guide shows how to read the value from the 0.x deployment and from stored grants, and what to do when routes advertised different resources.
