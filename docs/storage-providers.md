# Storage providers

The provider reads and writes every client, grant, access token, and replay
marker through a storage provider. Workers KV is the default and needs no
configuration or migration. The Durable Object SQLite provider serializes each
user's grants and tokens in one object and is the right choice when concurrent
code exchanges or refresh rotations for the same user must not race.

## Configuring the Durable Object provider

Export the storage class from your Worker, bind it as a SQLite-backed Durable
Object, and pass the binding to the provider:

```jsonc
// wrangler.jsonc
{
  "durable_objects": {
    "bindings": [{ "name": "OAUTH_STORAGE", "class_name": "OAuthStorageObject" }],
  },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["OAuthStorageObject"] }],
}
```

```ts
import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import {
  durableObjectSqliteStorage,
  OAuthStorageObject,
} from '@cloudflare/workers-oauth-provider/storage/durable-object';

export { OAuthStorageObject };

interface Env {
  OAUTH_STORAGE: DurableObjectNamespace<OAuthStorageObject>;
}

export default new OAuthProvider<Env>({
  // ...
  storage: durableObjectSqliteStorage<Env>({ binding: (env) => env.OAUTH_STORAGE }),
});
```

The explicit Workers KV form is `workersKvStorage<Env>({ binding: (env) => env.OAUTH_KV })`
from `@cloudflare/workers-oauth-provider/storage/kv`; omitting `storage` is equivalent.

## The store interface

`@cloudflare/workers-oauth-provider/storage` exports the contract. A provider is
`{ id, minimumTtlSeconds, open(env) }`; `open` resolves bindings from the Worker
environment and must be cheap, because the provider calls it per operation.
`minimumTtlSeconds` is the shortest token or grant lifetime the backend can
write; the provider rejects shorter TTLs before touching storage (60 for KV).

`open` returns an `OAuthStorage` with five stores. Records cross the boundary in
their canonical provider shapes (`ClientInfo`, `Grant`, `Token`); the adapter
owns only physical layout and expiry.

| Store          | Operations                                                                                           |
| -------------- | ---------------------------------------------------------------------------------------------------- |
| `clients`      | `get`, `put(client, expiresAt?)`, `deleteWithGrants` (cross-user cascade), `list`                    |
| `grants`       | `get`, `put(grant, expiresAt?)`, `listByUser`, optional `listByUserAndClient`, transitions, `revoke` |
| `accessTokens` | `get`, `put`, `delete`                                                                               |
| `replay`       | `reserve(key, expiresAt)` set-if-absent for one-time identifiers (EMA `jti`)                         |
| `maintenance`  | `purge` bounded global sweep of expired and orphaned records                                         |

`expiresAt` on a write is the record's physical lifetime. The provider still
checks logical expiry on every read, so a backend may keep a record past it.
Stores return records as stored and never hide an expired one.

### Grant transitions

Consuming an authorization code or rotating a refresh token is a transition:

1. `beginTransition({ grant, kind, credentialId, now, leaseTtlSeconds })` verifies the
   presented credential hash against the stored grant and returns `acquired` with a
   lease, or `invalid_credential`, `already_consumed`, `not_found`, or `busy`.
2. `commitTransition({ lease, grant, grantExpiresAt?, accessToken, now })` writes the
   successor grant and its first access token together, returning `committed` or
   `conflict` when the lease is no longer valid.
3. `abortTransition(lease)` releases an uncommitted lease.

The provider begins the transition only after every validation and the
`tokenExchangeCallback` have run, so a policy or callback failure leaves the
code or refresh token retryable.

### Optional operations

`grants.listByUserAndClient` lets `completeAuthorization()` replace a user's
earlier grants for one client without scanning every grant the user holds. When
absent the provider scans `listByUser` and filters. An adapter without a global
index throws `OAuthStorageError` with code `unsupported_operation` from
`clients.list`, `clients.deleteWithGrants`, and `maintenance.purge`, before any
I/O.

### Errors

`OAuthStorageError` carries `code` (`rate_limited`, `unsupported_operation`,
`invalid_configuration`) and `retryable`. At the token endpoint a retryable
failure becomes `temporarily_unavailable` with `Retry-After`. Any other backend
error propagates unchanged.

## Guarantees

### Workers KV

- Physical layout is the one in `storage-schema.md`: `client:{id}`, `grant:{userId}:{grantId}`,
  `token:{userId}:{grantId}:{hash}`, `enterprise-jti:{hash}`. Existing data is read as-is.
- Eventual read-after-write across locations and no compare-and-swap. A transition lease
  is advisory: `begin` and `commit` each verify the presented credential, but two concurrent
  exchanges of the same code or refresh token can both succeed.
- Native TTL with a 60-second minimum; near-expiry grant writes are clamped above it.
- `clients.list`, `clients.deleteWithGrants`, and `maintenance.purge` scan key prefixes.
- KV `429` responses surface as retryable `rate_limited` errors.

### Durable Object SQLite

- One object per user holds that user's grants, access tokens, transition leases, and
  fences; one object per registered client; replay markers in 256 shards. Object names are
  hashes of the routing key, so identifiers never appear in object metadata.
- Every command runs in one SQLite transaction with strong read-after-write. Transitions are
  fenced: a second `begin` for a leased credential returns `busy`, and a stale lease cannot
  commit.
- `listByUserAndClient` is served by a partial index on the user object.
- No minimum TTL. Expired records are deleted by each object's alarm; there are no migrations
  or schema versions because no deployed data predates this adapter.
- Unsupported, because there is no global index: `clients.list`, `clients.deleteWithGrants`,
  and `maintenance.purge` (`OAuthHelpers.listClients()`, `deleteClient()`, and
  `purgeExpiredData()`). Applications that need them keep their own client index.

## Testing

The KV adapter is unit-tested against an in-memory KV. The Durable Object
adapter is tested with `@cloudflare/vitest-pool-workers` against a real
SQLite-backed Durable Object in workerd (`npm run test:workers`).
