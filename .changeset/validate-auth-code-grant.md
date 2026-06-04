---
'@cloudflare/workers-oauth-provider': patch
---

Validate the authorization code and requesting client before acting on a grant during the authorization code exchange.

The `/token` authorization code grant now verifies the submitted code against the stored code hash and confirms the requesting client matches the grant's client before any single-use replay handling runs. The auth code hash is retained after exchange (alongside a used marker) so that a replayed code can be verified rather than acted upon based on its `userId:grantId` prefix alone. This ensures a code that does not match the one issued for a grant has no effect on that grant.
