---
'@cloudflare/workers-oauth-provider': patch
---

Fail closed when ID-JAG assertions contain unsupported `authorization_details` or `cnf` authorization constraints. These claims now produce a generic `invalid_grant` response before replay reservation, mapping, or token storage.
