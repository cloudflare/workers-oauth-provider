---
'@cloudflare/workers-oauth-provider': patch
---

Validate refresh-token `resource` parameters before invoking callbacks, rotating refresh tokens, or writing grant state. Invalid or out-of-grant resource requests now return `invalid_target` without mutating the authorization grant.
