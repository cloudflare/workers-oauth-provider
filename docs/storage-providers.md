# Pluggable storage providers (KV default, Hyperdrive/Postgres opt-in)

> Status: **draft / RFC**. The KV provider is the default and behaviour-identical
> to today. The Hyperdrive (Postgres) provider is opt-in and exists to fix a
> class of correctness bugs that KV cannot.

## Why

The provider stores three kinds of records in `OAUTH_KV`:

| Record | Key shape                            | Access pattern                         |
| ------ | ------------------------------------ | -------------------------------------- |
| client | `client:{clientId}`                  | read-heavy, rare writes                |
| grant  | `grant:{userId}:{grantId}`           | **read-modify-write** on every refresh |
| token  | `token:{userId}:{grantId}:{tokenId}` | write on issue, read on validate       |

The `refresh_token` grant does a **read-modify-write** of the grant record
(rotate refresh token, persist callback `newProps`). KV has:

- **no compare-and-swap**, and
- **eventually-consistent reads**.

So two concurrent refreshes of the same grant — two MCP sessions sharing one
refresh token, or a client retrying a lost response — can read the same grant,
both rotate, and the **last write wins**, orphaning the other's token. When the
provider's `tokenExchangeCallback` also redeems a **single-use, rotating
upstream** refresh token (i.e. the Worker is itself an OAuth client), this
surfaces as a steady stream of `invalid_grant`.

## Approach: a pluggable storage interface

We introduce a small `OAuthStorage` interface that mirrors the **subset of the
KV API** the provider already uses, so existing call sites change only from
`env.OAUTH_KV` to `getStorage(env)`:

```ts
interface OAuthStorage {
  get(key: string, opts?: { type: 'json' }): Promise<any>;
  put(key: string, value: string, opts?: { expirationTtl?: number; expiration?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  list(opts: { prefix: string; limit?: number; cursor?: string }): Promise<{
    keys: { name: string }[];
    list_complete: boolean;
    cursor?: string;
  }>;
}
```

- `KvStorage` — thin pass-through to `env.OAUTH_KV` (default; zero behaviour change).
- `HyperdriveStorage` — Postgres reached through a Cloudflare Hyperdrive binding.

## Hyperdrive / Postgres provider

Postgres gives **strongly-consistent reads**: a refresh that reads a grant
always observes the latest committed rotation. That removes the
eventually-consistent half of the problem outright — the failure mode where a
refresh reads a _stale_ grant simply cannot happen.

Data model is one KV-shaped table, so the provider's existing key conventions
work unchanged:

```sql
CREATE TABLE oauth_kv (
  key        TEXT PRIMARY KEY,
  value      TEXT   NOT NULL,
  expires_at BIGINT          -- Unix seconds, NULL = no expiry
);
```

- `get` — `SELECT … WHERE key = $1`, lazily reaping expired rows.
- `put` — `INSERT … ON CONFLICT (key) DO UPDATE` (upsert).
- `delete` — `DELETE … WHERE key = $1`.
- `list` — `WHERE key LIKE $1 … ORDER BY key LIMIT … OFFSET …`, cursor =
  numeric offset, matching KV's prefix + pagination semantics.

### Driver

`HyperdriveStorage` lazily imports **`node-postgres` (`pg`)** — the
Hyperdrive-recommended driver — only on this path, so KV-only consumers don't
pull it in. `pg` is an **optional peer dependency**. Alternatively, inject your
own `client` (any `{ query(text, params) }`) to control the driver/pool, which
is also how the tests run without a live database.

### Follow-up: fully serialized rotation

Strong reads remove the stale-read race. To _also_ serialize two refreshes that
read concurrently, a follow-up can add a transactional path:

```sql
BEGIN;
SELECT value FROM oauth_kv WHERE key = $1 FOR UPDATE;  -- row lock
-- rotate in app code …
UPDATE oauth_kv SET value = $2, expires_at = $3 WHERE key = $1;
COMMIT;
```

This needs the provider to expose the grant read-modify-write as a single
transactional unit (it currently does a separate `get` then `put`). Tracked
separately; this PR lays the storage seam it builds on.

## Configuration

```ts
new OAuthProvider({
  // default — unchanged, behaviour-identical to today:
  storage: { type: 'kv' },
});

new OAuthProvider({
  storage: { type: 'hyperdrive', hyperdrive: env.HYPERDRIVE },
  // or inject your own driver/pool:
  // storage: { type: 'hyperdrive', client: myPgClient },
  // optional: storage: { type: 'hyperdrive', hyperdrive: env.HYPERDRIVE, tableName: 'oauth_kv' },
});
```

`wrangler.jsonc`:

```jsonc
{
  "compatibility_flags": ["nodejs_compat"],
  "hyperdrive": [{ "binding": "HYPERDRIVE", "id": "<your-hyperdrive-id>" }],
}
```

and install the driver: `npm i pg@>8.16.3`.

## Migration / rollout

- Opt-in only. Existing deployments keep `type: 'kv'` and are untouched.
- New deployments (or those hitting the refresh race) set
  `type: 'hyperdrive'`, add the binding + `nodejs_compat`, install `pg`.
- The table is created on first use (`CREATE TABLE IF NOT EXISTS`); a future
  helper can import existing KV grants on first touch.

---

## Appendix: parked alternative — single-threaded Durable Object

An earlier draft backed the store with a **partitioned, single-threaded SQLite
Durable Object** (one instance per user; KV as a cross-partition index). A DO is
single-threaded per instance, so routing every operation for a grant to one
instance fully serializes the read-modify-write — fixing the race directly
rather than only removing stale reads.

It was parked in favour of Hyperdrive because:

- Many deployments already have/ want a Postgres system of record; Hyperdrive
  reuses it rather than introducing a second stateful primitive.
- No partition-vs-throughput tradeoff to reason about (a single global DO caps
  at one instance's throughput; partitioning adds a cross-partition index).
- Simpler operational model: one connection string, standard SQL tooling.

The DO design (partitioning by user, KV-as-index for `list`/purge) remains a
viable path if a Postgres dependency is undesirable, and is preserved in the
project history. The two share the same `OAuthStorage` seam, so either can be
added without touching provider logic.
