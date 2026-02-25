---
'@cloudflare/workers-oauth-provider': minor
---

Add `revokeExistingGrants` option to `completeAuthorization()` that revokes existing grants for the same user+client after creating a new one. Defaults to `true`, fixing infinite re-auth loops when props change between authorizations. Set to `false` to allow multiple concurrent grants per user+client.
