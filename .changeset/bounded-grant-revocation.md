---
'@cloudflare/workers-oauth-provider': minor
---

Bound the KV work `completeAuthorization()` does to revoke a user's earlier grants for the same client.

Every grant key now carries its `clientId`, `resource` and `redirectUri` as KV key metadata, so the grants a new authorization replaces are found from `list()` alone. The cost is one `list()` per thousand grants the user has instead of one `get()` per grant, which exceeded a Worker's subrequest limit for a user with more than a few hundred grants on the paid plan, or a few dozen on the free plan.

Grants written before this version have no key metadata and are still read individually; `revokeExistingGrantsBatchSize` now bounds how many of those are read at once (default 50, maximum 1000) rather than the `list()` page size. A refresh rewrites its grant with metadata, so that share shrinks on its own. Nothing about tokens, refresh tokens or grant records changes, and no migration is needed.
