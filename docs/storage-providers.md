# Pluggable storage providers (KV default, Durable Object opt-in)

> Status: **draft / RFC**. This document describes a proposed storage-provider
> abstraction for `@cloudflare/workers-oauth-provider`. The KV provider is the
> default and is behaviour-identical to today. The Durable Object provider is
> opt-in and exists to fix a class of correctness bugs that KV cannot solve.

## Why

The provider stores three kinds of records in `OAUTH_KV`:

| Record | Key shape                            | Access pattern                         |
| ------ | ------------------------------------ | -------------------------------------- |
| client | `client:{clientId}`                  | read-heavy, rare writes                |
| grant  | `grant:{userId}:{grantId}`           | **read-modify-write** on every refresh |
| token  | `token:{userId}:{grantId}:{tokenId}` | write on issue, read on validate       |

The `refresh_token` grant does a **read-modify-write** of the grant record
(rotate refresh token, persist callback `newProps`, etc.). KV has:

- **no compare-and-swap**, and
- **eventually-consistent reads**.

So two concurrent refreshes of the same grant (two MCP sessions sharing one
refresh token, or a client retrying a lost response) both read the same grant,
both rotate, and the **last write wins** — orphaning the other's rotated token.
When the provider's `tokenExchangeCallback` also redeems a **single-use,
rotating upstream** refresh token (i.e. the Worker is itself an OAuth client),
this surfaces as a steady stream of `invalid_grant`. No amount of in-isolate
coalescing fixes it, because the racing requests land on different isolates.

A **Durable Object is single-threaded per instance**: all operations on one
instance run serially. If every operation for a given grant is routed to the
same DO, the read-modify-write is serialized and the race is gone.

## The catch: don't recreate the bottleneck

A **single** global DO would serialize _everything_ and cap the entire OAuth
surface at one DO's throughput (~hundreds of rps). That just moves the
bottleneck. So we **partition**.

### Partition by user (default)

DO instance name = `u:{userId}`. That instance owns **all of that user's
grants and tokens**. Properties:

- The refresh race is per-grant, and a grant lives under exactly one user, so
  it lives in exactly one DO → **rotation is serialized → bug fixed**.
- Throughput scales with the number of active users, not a global singleton.
- A user's grants+tokens are co-located → "revoke all my sessions" and
  per-user cleanup are single-DO operations.

### Why not partition by OAuth client

Tempting ("one DO per client, manage its lifecycle") but **wrong for the hot
path**: a popular client — e.g. the MCP server's own `client_id` — would funnel
_every user's_ refreshes through one DO, recreating the singleton cap. Client
_records_ are a different, read-heavy, low-write concern (see below). The
storage partition must follow the write-contention boundary, which is the user
(or the grant).

### Per-grant (optional, finer)

DO name = `g:{userId}:{grantId}`. Maximum parallelism, smallest blast radius.
Downside: a user's tokens are spread across grant-DOs, so per-user operations
fan out. Offered as a config knob; per-user is the sensible default.

## KV as the cross-partition tracker

`list({ prefix })` / purge / "revoke all grants for a client" span partitions.
DOs can't see each other's SQLite. So we keep **KV as a lightweight index**:

- On `put(key, …)` the DO provider also writes a tiny KV index entry for `key`
  (existence + TTL + owning partition). The **authoritative value lives in the
  DO**; KV holds only the key.
- `list({ prefix })` enumerates the KV index (same cursor/pagination semantics
  as today).
- `delete(key)` removes both.

This is the "KV as a tracker of DOs" model: hot, race-sensitive
read-modify-write happens in the owning DO (serialized, correct); cold
enumeration uses KV (eventually-consistent, which is fine for purge/admin).

Client records are read-heavy and low-write; they can stay in KV directly
(default) or be routed to a `clients` partition. The default keeps them in KV.

## Configuration

```ts
new OAuthProvider({
  // …
  // default — unchanged, behaviour-identical to today:
  storage: { type: 'kv' },
});

new OAuthProvider({
  // …
  storage: {
    type: 'durable_object',
    // partition strategy for grants+tokens; default 'user'
    partition: 'user', // | 'grant'
  },
});
```

The DO namespace binding is **hardcoded as `env.OAUTH_DURABLE_OBJECT`** and the
KV index uses the existing `env.OAUTH_KV`. Consumers add to `wrangler.jsonc`:

```jsonc
{
  "durable_objects": {
    "bindings": [{ "name": "OAUTH_DURABLE_OBJECT", "class_name": "OAuthStore" }],
  },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["OAuthStore"] }],
}
```

and re-export the DO class from their Worker entry:

```ts
export { OAuthStore } from '@cloudflare/workers-oauth-provider';
```

## Storage interface

The abstraction mirrors the **subset of the KV API** the provider already uses,
so existing call sites change only from `env.OAUTH_KV` to `getStorage(env)`:

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
- `DurableObjectStorage` — routes by key → partition DO for values, KV for the
  index. The DO persists to its own SQLite via `ctx.storage.sql` (no external
  deps added to the library).

## Migration / rollout

- Opt-in only. Existing deployments keep `type: 'kv'` and are untouched.
- New deployments (or those hitting the refresh race) set
  `type: 'durable_object'`, add the binding + migration, re-export `OAuthStore`.
- A future migration helper can lazily import KV grants into DOs on first touch.
