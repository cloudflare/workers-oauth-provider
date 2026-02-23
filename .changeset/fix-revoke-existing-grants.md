---
'@cloudflare/workers-oauth-provider': patch
---

Add `revokeExistingGrants` option to `completeAuthorization()` to revoke existing grants for the same user+client before creating a new one, fixing infinite re-auth loops
