---
'@cloudflare/workers-oauth-provider': minor
---

Add a pluggable storage backend via the `storage` option, with an opt-in
partitioned SQLite **Durable Object** provider alongside the default KV.

KV has no compare-and-swap and eventually-consistent reads, so two concurrent
`refresh_token` grants for the same grant both read, both rotate, and the last
write wins — orphaning the other's refresh token. When `tokenExchangeCallback`
redeems a single-use, rotating upstream token, this surfaces as recurring
`invalid_grant`. A Durable Object is single-threaded per instance, so routing
every operation for a grant to the same instance serializes the rotation and
removes the race.

- `storage: { type: 'kv' }` — default, behaviour-identical to today.
- `storage: { type: 'durable_object', partition: 'user' | 'grant' }` — routes
  grant/token values to a partitioned `OAuthStore` Durable Object (binding
  `OAUTH_DURABLE_OBJECT`), keeping `OAUTH_KV` as a cross-partition index for
  `list`/purge. Partition by `user` (default) so a user's grants and tokens are
  co-located and throughput scales with active users, rather than funnelling
  through a single global DO.

Consumers re-export `{ OAuthStore }` from their Worker entry and add the DO
binding plus a `new_sqlite_classes` migration. Existing KV deployments are
unaffected. See `docs/storage-providers.md`.
