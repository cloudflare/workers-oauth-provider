---
'@cloudflare/workers-oauth-provider': patch
---

fix: path-aware audience validation for RFC 8707 resource indicators. Include request pathname in `resourceServer` computation for both internal and external token validation. Replace strict equality in `audienceMatches()` with origin + path-prefix matching on path boundaries. Origin-only audiences (e.g. `https://example.com`) still match any path (backward compatible). Path-aware audiences (e.g. `https://example.com/api`) match the exact path and sub-paths (`/api/users`) but not partial matches (`/api-v2`).
