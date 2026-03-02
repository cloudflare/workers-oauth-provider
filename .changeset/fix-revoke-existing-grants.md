---
'@cloudflare/workers-oauth-provider': minor
---

Add `revokeExistingGrants` option to `completeAuthorization()` that revokes existing grants for the same user+client after creating a new one. Defaults to `true`, fixing infinite re-auth loops when props change between authorizations (issue #34). Set to `false` to allow multiple concurrent grants per user+client.

Revoke tokens and grant when an authorization code is reused, per RFC 6749 §10.5. This prevents authorization code replay attacks by invalidating all tokens issued from the first exchange.

**Breaking behavior change:** Previously, re-authorizing the same user+client created an additional grant, leaving old tokens valid. Now, old grants are revoked by default. If your application relies on multiple concurrent grants per user+client, set `revokeExistingGrants: false` to preserve the old behavior.
