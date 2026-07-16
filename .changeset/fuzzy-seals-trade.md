---
'@cloudflare/workers-oauth-provider': patch
---

Allow EMA ID-JAG assertions to omit the optional `resource` claim, falling back to the provider's configured protected resource.
