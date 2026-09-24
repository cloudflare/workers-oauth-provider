---
'@cloudflare/workers-oauth-provider': patch
---

`completeAuthorization()` rejects a `userId` containing `:`, as the enterprise-managed authorization mapper already did. `:` separates the parts of issued tokens and grant keys, so such a user's tokens could never be validated, and its grant keys (`grant:a:b:…`) matched another user's `grant:a:` prefix. `listUserGrants()` and the revocation of earlier grants now also skip those legacy keys, so a stored grant for user `a:b` never appears in, or is revoked by, user `a`'s operations.
