---
'@cloudflare/workers-oauth-provider': patch
---

Fix apiHandler route matching when set to '/' to use exact match instead of prefix match, preventing it from matching all routes and breaking OAuth endpoints
