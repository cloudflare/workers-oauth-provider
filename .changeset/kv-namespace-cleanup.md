---
'@cloudflare/workers-oauth-provider': minor
---

Prevent unbounded KV namespace growth with TTL defaults, cascade deletes, and garbage collection.

**Default TTLs to prevent unbounded storage growth:**

- `refreshTokenTTL` now defaults to 30 days (previously infinite). Grants auto-expire via KV TTL. Set to `undefined` explicitly to restore the previous behavior of never expiring.
- `clientRegistrationTTL` (new option) defaults to 90 days. Dynamically registered clients (DCR) auto-expire. Clients created via `OAuthHelpers.createClient()` are not affected. Set to `undefined` for clients that never expire.

**`deleteClient()` now cascades to grants and tokens:**

Previously, deleting a client only removed the `client:{id}` record, leaving all associated grants and tokens orphaned in KV. Now `deleteClient()` scans all grants, revokes those belonging to the deleted client (which also deletes their tokens), and then deletes the client record.

**New `purgeExpiredData()` method for scheduled garbage collection:**

Defense-in-depth cleanup method designed to be called from a Cron Trigger. Processes records in configurable batches (default: 50) to stay within Cloudflare's subrequest limits. Performs two sweep phases: (1) grant sweep removes orphaned grants (client deleted) and expired grants, (2) token sweep removes orphaned tokens (grant deleted). Safe for CIMD clients — grants with URL-based client IDs are never incorrectly treated as orphaned. Available on both `OAuthHelpers` (via `env.OAUTH_PROVIDER.purgeExpiredData()`) and directly on `OAuthProvider` (via `oauthProvider.purgeExpiredData(env)`) for use in scheduled handlers without a request context.

**New exports:** `PurgeOptions`, `PurgeResult`
