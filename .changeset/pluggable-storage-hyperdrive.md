---
'@cloudflare/workers-oauth-provider': minor
---

Add a pluggable storage backend via the `storage` option, with an opt-in
**Hyperdrive (Postgres)** provider alongside the default KV.

KV has no compare-and-swap and eventually-consistent reads, so two concurrent
`refresh_token` grants for the same grant can read the same record, both rotate,
and the last write wins — orphaning the other's refresh token. When
`tokenExchangeCallback` redeems a single-use, rotating upstream token, this
surfaces as recurring `invalid_grant`. Postgres provides strongly-consistent
reads, so a refresh always reads the latest committed rotation, removing the
stale-read failure mode.

- `storage: { type: 'kv' }` — default, behaviour-identical to today.
- `storage: { type: 'hyperdrive', hyperdrive: env.HYPERDRIVE }` — stores
  clients, grants, and tokens in Postgres via a Cloudflare Hyperdrive binding,
  using a single KV-shaped table (`oauth_kv` by default). Lazily imports the
  `node-postgres` (`pg`) driver — an optional peer dependency — only on this
  path, or inject your own SQL `client` to control the driver/pool.

Requires the `nodejs_compat` flag and `pg@>8.16.3`. Existing KV deployments are
unaffected. See `docs/storage-providers.md`.
