# Pluggable storage providers

**Status:** design RFC  
**Scope:** storage contract, capability negotiation, adapter boundaries, and compatibility policy  
**Out of scope:** implementing the adapters in this document  
**Research baselines:** `workers-oauth-provider@0.8.1` (`f8e3ddd`), `better-auth@1.6.23` plus main (`fd6b8c1`), and `pi-mono` (`9a0a8d7c`)

## Goal

Allow `@cloudflare/workers-oauth-provider` to run on several storage systems without reducing OAuth correctness to the lowest common denominator.

The first target backends are:

- Cloudflare Workers KV;
- SQLite in a Durable Object;
- Cloudflare D1;
- PostgreSQL through an application-supplied client, including Hyperdrive;
- Redis through an application-supplied client.

The provider must know what each backend guarantees. Features that need an atomic state transition must not silently run as a read followed by a write on a backend that cannot provide one.

This is a larger change than replacing `env.OAUTH_KV` with an interface. Storage behavior is part of the OAuth security model.

## Decision summary

1. The OAuth engine depends on a domain-specific storage contract, not a KV-shaped API and not a generic database query language.
2. A storage provider declares semantic capabilities. The OAuth engine checks them when a feature is enabled.
3. Security-sensitive state changes are serializable operation plans. The public contract does not expose `transaction(callback)` because callbacks cannot cross Durable Object RPC, D1, Redis, and remote adapter boundaries consistently.
4. The core package remains dependency-free. PostgreSQL and Redis adapters accept small client interfaces supplied by the application or an external adapter package.
5. Workers KV remains the backward-compatible default, but it is a compatibility backend. It cannot claim atomic authorization-code consumption, strict refresh-token rotation, atomic replay reservation, or immediate global revocation.
6. D1 and PostgreSQL are the first candidates for complete general-purpose adapters. Durable Object SQLite is the first candidate for serialized per-aggregate state. Redis can be complete only when the injected client supports atomic scripts or an equivalent primitive.
7. The core accepts one authoritative storage provider. Composite designs, such as Durable Objects plus KV indexes or PostgreSQL plus Redis caching, are implemented behind a provider rather than coordinated by the OAuth engine.
8. Every adapter must pass a shared conformance suite. Declaring a capability without passing its behavioral tests is a bug.

## Why the previous interface was insufficient

The previous proposal mirrored the Workers KV methods used by the current implementation:

```ts
interface OAuthStorage {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: PutOptions): Promise<void>;
  delete(key: string): Promise<void>;
  list(options: ListOptions): Promise<ListResult>;
}
```

That interface makes existing call sites easy to port, but it preserves the main problem:

```ts
const grant = await storage.get(key);
// validate and mutate grant
await storage.put(key, nextGrant);
```

A SQL adapter can execute those calls, but the operation is still not atomic. A Durable Object adapter can route both calls to one object, but an application callback between them can still race with another request. A Redis adapter can support atomic scripts, but the interface gives it no operation to implement atomically.

The interface also exposes current KV key shapes as the permanent public contract. That prevents SQL adapters from using ordinary tables and indexes without rebuilding a KV database on top of SQL.

The replacement contract describes OAuth records, queries, and guarded transitions. Each adapter chooses its physical schema.

## Design influences

### pi-ai and pi-agent

`pi-ai` separates three concepts:

- a model descriptor says which API and capabilities apply;
- an API provider normalizes provider-specific behavior into `stream` and `streamSimple`;
- `pi-agent` builds on the normalized interface rather than importing every model SDK.

Unsupported model features remain visible. For example, models declare supported input types and reasoning support. Provider-specific options do not become mandatory features of every provider.

The storage design follows the same pattern:

- `OAuthStorageProvider` identifies an adapter and declares its capabilities;
- `OAuthStorageConnection` normalizes backend behavior into OAuth operations;
- `OAuthProvider` uses only the normalized operations;
- optional OAuth features declare the storage capabilities they require.

Unlike `pi-ai`, this package does not need a process-global provider registry. One `OAuthProvider` uses one authoritative storage provider, so it should receive the provider explicitly in its options.

### Better Auth

Better Auth gets broad database support from a generic database adapter, schema transforms, and external adapter packages. Its adapter advertises data-shape capabilities such as JSON, dates, booleans, arrays, IDs, joins, and transactions. Better Auth also has a separate key-value `SecondaryStorage` interface.

The useful lessons are:

- adapter metadata should be explicit;
- the framework should normalize backend data types;
- driver integrations can live outside the core package;
- a conformance suite is necessary;
- atomic methods must be named in the contract.

The latest Better Auth adapter has added operations such as `consumeOne` and `incrementOne` because generic CRUD and a nominal transaction callback were not enough for single-use credentials and guarded updates. Its secondary storage is also adding optional atomic `getAndDelete` and `increment` methods.

`workers-oauth-provider` should not copy the full Better Auth query language. Better Auth has an extensible application schema and many plugins. This library owns a small, fixed OAuth schema. A domain-specific contract is smaller, easier to audit, and able to express whole OAuth transitions atomically.

## Storage families on Cloudflare

The adapter names must not imply guarantees that the underlying service does not have.

### Key-value

Workers KV is a globally distributed key-value service. It is not Redis. It has eventual cross-location visibility, last-write-wins concurrent updates, no compare-and-swap, no multi-key transaction, and a minimum expiration of 60 seconds.

A real Redis service may provide strong single-key ordering, `SET NX`, atomic counters, transactions, and Lua scripts. Redis and Workers KV therefore belong to the same broad data-model family but do not have the same capability profile.

### SQLite

Both D1 and SQLite-backed Durable Objects use SQLite, but their execution models differ:

- a Durable Object owns private, strongly consistent storage and provides a serialization boundary for one object;
- D1 is a managed database binding with global tables, SQL queries, transactional `batch()`, and session consistency controls.

They need separate adapters even if they share SQL fragments and record schemas.

### PostgreSQL and MySQL

Hyperdrive is connection pooling and optional query caching for an existing Postgres or MySQL database. It is not the database and it is not a SQL driver.

The application still supplies a driver such as `pg`, Postgres.js, or `mysql2`. The OAuth storage contract should accept a small driver-neutral connection factory instead of adding one of those packages as a runtime dependency.

Hyperdrive query caching must be disabled for the connection used by OAuth storage. Hyperdrive does not invalidate cached reads after writes and explicitly recommends a cache-disabled binding for authentication, sessions, and permissions.

PlanetScale currently offers both Postgres and MySQL. A PlanetScale Postgres database uses the Postgres adapter. PlanetScale MySQL requires a separate MySQL adapter. D1 uses the D1 adapter, not the Postgres adapter.

## Architectural layers

### OAuth engine

The existing authorization, token, registration, revocation, and helper code. It owns protocol validation, cryptography, record construction, and OAuth error mapping.

The engine must not contain SQL, Redis commands, Durable Object routing, or backend-specific retry logic.

### Storage provider

A configured backend implementation with a stable identity and static capability descriptor.

```ts
export interface OAuthStorageProvider<Env = Cloudflare.Env> {
  /** Stable adapter identifier, for example `cloudflare-kv` or `d1`. */
  readonly id: string;

  /** Storage contract version implemented by this provider. */
  readonly contractVersion: 1;

  /** Guarantees and query facilities available to the OAuth engine. */
  readonly capabilities: OAuthStorageCapabilities;

  /**
   * Opens request-scoped access to the backend.
   *
   * KV, D1, and Durable Object adapters may return lightweight wrappers.
   * A SQL adapter may acquire a client and release it from `close()`.
   */
  open(context: OAuthStorageOpenContext<Env>): Awaitable<OAuthStorageConnection>;
}

export interface OAuthStorageOpenContext<Env> {
  env: Env;
  executionContext?: ExecutionContext;
}
```

Capabilities are available before `open()` so constructor-time feature validation does not depend on an incoming request.

### Storage connection

A request-scoped normalized interface. The OAuth engine opens it once for a request or helper operation and closes it in `finally`.

`fetch()` opens one connection before routing an OAuth or protected API request and passes it through every internal helper on that request. `getOAuthApi()` opens and closes a connection around each public helper call. The provider does not memoize an opened SQL or Redis client by `env`; Cloudflare recommends creating Hyperdrive-backed clients inside request handling, and one transaction must stay on one acquired connection.

```ts
export interface OAuthStorageConnection {
  readonly clients: OAuthClientStore;
  readonly grants: OAuthGrantStore;
  readonly accessTokens: OAuthAccessTokenStore;
  readonly consents: OAuthConsentStore;
  readonly replay: OAuthReplayStore;
  readonly maintenance: OAuthMaintenanceStore;

  close?(): Awaitable<void>;
}
```

The nested interfaces group operations for readability. They do not imply separate physical stores.

### Adapter

The code that implements `OAuthStorageProvider` for one backend. Built-in adapters can live under package subpaths. External adapters implement the same public contract.

### Composite provider

A provider may use more than one service internally. For example, a Durable Object adapter may use D1 for global indexes, or a Postgres adapter may use Redis as a cache. It still presents one capability descriptor and one authoritative contract to the OAuth engine.

The core will not initially expose Better Auth-style `database` plus `secondaryStorage` options. Splitting authority between stores without backend-owned consistency rules would move race conditions into the core.

## Configuration API

The exact function names remain provisional, but the public shape should be provider objects rather than a string union interpreted by the OAuth engine.

### Default Workers KV

Omitting `storage` preserves the existing binding:

```ts
new OAuthProvider({
  // ...
});
```

The explicit form is:

```ts
import { workersKvStorage } from '@cloudflare/workers-oauth-provider/storage/kv';

new OAuthProvider({
  // ...
  storage: workersKvStorage<Env>({
    namespace: (env) => env.OAUTH_KV,
  }),
});
```

### D1

```ts
import { d1Storage } from '@cloudflare/workers-oauth-provider/storage/d1';

new OAuthProvider({
  // ...
  storage: d1Storage<Env>({
    database: (env) => env.OAUTH_DB,
  }),
});
```

### Durable Object SQLite

```ts
import { durableObjectStorage, OAuthStorageObject } from '@cloudflare/workers-oauth-provider/storage/durable-object';

export { OAuthStorageObject };

new OAuthProvider({
  // ...
  storage: durableObjectStorage<Env>({
    namespace: (env) => env.OAUTH_STORAGE,
    partition: 'grant',
  }),
});
```

A partitioned Durable Object adapter must state how it implements global queries. If no global index is configured, capabilities such as listing all clients, deleting a client with a cross-user cascade, and global purging are unavailable. The OAuth engine must not synthesize those queries by discovering object IDs.

### PostgreSQL

```ts
import { postgresStorage } from '@cloudflare/workers-oauth-provider/storage/postgres';

new OAuthProvider({
  // ...
  storage: postgresStorage<Env>({
    connect: async (env) => wrapPgClient(new Client(env.HYPERDRIVE_NO_CACHE.connectionString)),
  }),
});
```

`wrapPgClient` is application code or an external integration package. The core package defines the small connection interface but does not import `pg`, Postgres.js, Drizzle, Kysely, or another driver.

### Redis

```ts
import { redisStorage } from '@cloudflare/workers-oauth-provider/storage/redis';

new OAuthProvider({
  // ...
  storage: redisStorage<Env>({
    client: (env) => wrapRedisClient(env.REDIS),
  }),
});
```

A complete Redis adapter requires atomic script execution or an equivalent server-side primitive. A client that only exposes `get`, `set`, and `delete` can implement the compatibility profile but must not advertise strict transition capabilities.

### Custom provider

```ts
new OAuthProvider({
  // ...
  storage: myStorageProvider,
});
```

A custom provider does not need to register globally. It must implement contract version 1 and should pass the exported conformance suite.

## Canonical records

The storage contract uses versioned, backend-neutral records. Adapters may normalize these into tables or serialize them as JSON.

```ts
export interface StoredRecord {
  schemaVersion: 1;
  createdAt: number;
  expiresAt?: number;
}

export interface StoredClient extends StoredRecord, ClientInfo {
  revision: number;
}

export interface StoredGrant extends StoredRecord, Grant {
  /** Monotonically increases on every successful state transition. */
  revision: number;
}

export interface StoredAccessToken extends StoredRecord, Token {
  // Access-token records are immutable after creation.
}

export interface StoredConsent extends StoredRecord {
  userId: string;
  clientId: string;
  referenceId?: string;
  scope: string[];
  revision: number;
  updatedAt: number;
}

export interface GrantKey {
  userId: string;
  grantId: string;
}

export interface AccessTokenKey extends GrantKey {
  tokenId: string;
}
```

Rules:

- timestamps are Unix seconds at the storage boundary;
- every expiring record contains `expiresAt`, even when the backend also has native TTL;
- the OAuth engine checks logical expiry on reads;
- adapters must not return logically expired records;
- mutable records carry a revision for guarded transitions;
- adapters must preserve unknown fields from newer record schema versions when an update does not own those fields;
- raw authorization codes, access tokens, refresh tokens, client secrets, and replay JTIs never enter the storage contract;
- stored credential identifiers remain hashes as they are today.

Existing KV records without `schemaVersion` or `revision` are read as schema version 0 and revision 0 during migration. Writing a record upgrades it to the current version.

The exact record fields remain in the main OAuth implementation for auditability. Adapter-facing aliases should not create a second source of truth.

## Current operation mapping

The contract covers every current storage access without exposing current KV keys:

| Current behavior                                                                                | Storage operation                                                             |
| ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Look up a registered client                                                                     | `clients.get`                                                                 |
| DCR or helper client creation                                                                   | `clients.create`                                                              |
| Update a client                                                                                 | `clients.replace`                                                             |
| List clients                                                                                    | `clients.list`                                                                |
| Delete a client and its grants                                                                  | `clients.deleteWithGrants`                                                    |
| Start an authorization-code grant                                                               | `grants.create`                                                               |
| Exchange an authorization code                                                                  | `grants.beginTransition`, `grants.commitTransition`, `grants.abortTransition` |
| Refresh a token                                                                                 | `grants.beginTransition`, `grants.commitTransition`, `grants.abortTransition` |
| Issue a grant and immediate access token for implicit compatibility, client credentials, or EMA | `grants.create` with `accessToken`                                            |
| Validate or unwrap an access token                                                              | `accessTokens.get`                                                            |
| Issue a token exchange token on an existing grant                                               | `accessTokens.createForGrant`                                                 |
| Revoke one access token                                                                         | `accessTokens.delete`                                                         |
| Revoke a refresh token or grant                                                                 | `grants.revoke`                                                               |
| List a user's grants                                                                            | `grants.listByUser`                                                           |
| Enumerate a grant's access tokens                                                               | `accessTokens.listByGrant`                                                    |
| Reserve an EMA JTI                                                                              | `replay.reserve`                                                              |
| Purge expired or orphaned state                                                                 | `maintenance.purgeExpired` plus indexed domain queries                        |

Future persistent consent uses `consents`; it is included in contract version 1 because it is part of the Better Auth coverage roadmap. Device authorization and signing-key storage are not forced into this contract. Device state can add a versioned domain store later. OIDC signing keys use a separate signing-key provider because key custody and rotation are not ordinary OAuth record storage.

## Query contract

### Shared result types

```ts
export type CreateResult = 'created' | 'conflict';
export type ReplaceResult = 'updated' | 'conflict' | 'not_found';
export type DeleteResult = 'deleted' | 'conflict' | 'not_found';

export interface AbortGrantTransitionInput {
  lease: GrantTransitionLease;
}

export interface DeleteClientInput {
  clientId: string;
  expectedRevision?: number;
}

export type DeleteClientResult =
  | {
      status: 'deleted';
      deletedGrants: number;
      deletedAccessTokens: number;
    }
  | { status: 'conflict' }
  | { status: 'not_found' };

export interface RevokeGrantInput {
  grant: GrantKey;
  expectedRevision?: number;
}

export type RevokeGrantResult =
  | { status: 'revoked'; deletedAccessTokens: number }
  | { status: 'conflict' }
  | { status: 'not_found' };
```

### Clients

```ts
export interface OAuthClientStore {
  get(clientId: string): Promise<StoredClient | null>;

  create(input: { client: StoredClient }): Promise<'created' | 'conflict'>;

  replace(input: {
    clientId: string;
    expectedRevision: number;
    client: StoredClient;
  }): Promise<'updated' | 'conflict' | 'not_found'>;

  /**
   * Deletes the client and every grant and access token issued to it. A strong
   * implementation prevents a concurrent transition from recreating children
   * after deletion wins.
   */
  deleteWithGrants(input: DeleteClientInput): Promise<DeleteClientResult>;

  list(input: PageRequest): Promise<Page<StoredClient>>;
}
```

`create` is insert-if-absent. `replace` is compare-and-swap. An adapter must not implement either as an unguarded upsert while advertising strong client writes.

`deleteWithGrants` is one domain operation because the OAuth helper promises cascading deletion. SQL adapters can implement it with transactions and foreign keys. A partitioned adapter may need a global coordinator or may advertise only best-effort cascade semantics.

### Grants

```ts
export interface OAuthGrantStore {
  get(key: GrantKey): Promise<StoredGrant | null>;

  create(input: {
    grant: StoredGrant;
    /**
     * Present when a flow issues a grant and access token together, such as
     * client credentials or EMA. Strong adapters create both atomically.
     */
    accessToken?: StoredAccessToken;
  }): Promise<'created' | 'conflict'>;

  listByUser(input: { userId: string; page?: PageRequest }): Promise<Page<StoredGrant>>;

  listByClient(input: { clientId: string; page?: PageRequest }): Promise<Page<StoredGrant>>;

  beginTransition(input: BeginGrantTransitionInput): Promise<BeginGrantTransitionResult>;

  commitTransition(input: CommitGrantTransitionInput): Promise<CommitGrantTransitionResult>;

  abortTransition(input: AbortGrantTransitionInput): Promise<void>;

  revoke(input: RevokeGrantInput): Promise<RevokeGrantResult>;
}
```

### Access tokens

```ts
export interface OAuthAccessTokenStore {
  get(key: AccessTokenKey): Promise<StoredAccessToken | null>;

  /**
   * Creates a token only while the backing grant still exists at the expected
   * revision. This prevents token exchange from racing grant revocation.
   */
  createForGrant(input: {
    grant: GrantKey;
    expectedGrantRevision: number;
    token: StoredAccessToken;
  }): Promise<'created' | 'conflict' | 'grant_not_found'>;

  delete(input: { key: AccessTokenKey }): Promise<'deleted' | 'not_found'>;

  listByGrant(input: { grant: GrantKey; page?: PageRequest }): Promise<Page<StoredAccessToken>>;
}
```

Access-token creation is included in `commitTransition` for authorization-code and refresh-token exchanges. `createForGrant` covers token exchange on an existing grant. Flows that create a grant and immediately issue a token pass both records to `grants.create` so a strong adapter does not leave a grant without its initial token.

### Consents

```ts
export interface OAuthConsentStore {
  get(input: { userId: string; clientId: string; referenceId?: string }): Promise<StoredConsent | null>;

  replace(input: { consent: StoredConsent; expectedRevision?: number }): Promise<'created' | 'updated' | 'conflict'>;

  delete(input: {
    userId: string;
    clientId: string;
    referenceId?: string;
    expectedRevision?: number;
  }): Promise<'deleted' | 'conflict' | 'not_found'>;

  listByUser(input: { userId: string; page?: PageRequest }): Promise<Page<StoredConsent>>;
}
```

The tuple `(namespace, userId, clientId, referenceId)` is unique. Adapters normalize an omitted `referenceId` to a stable database value rather than relying on backend-specific `NULL` uniqueness behavior.

### Replay reservations

```ts
export interface OAuthReplayStore {
  reserve(input: { namespace: 'ema-jti' | string; keyHash: string; expiresAt: number }): Promise<'reserved' | 'exists'>;
}
```

`reserve` is an atomic set-if-absent operation. It supports EMA JTI replay prevention and future single-use identifiers. A get followed by a put does not satisfy the strong capability.

### Maintenance

```ts
export interface OAuthMaintenanceStore {
  purgeExpired(input: { limit: number; cursor?: string }): Promise<{
    deleted: number;
    cursor?: string;
    done: boolean;
  }>;
}
```

Maintenance is adapter-owned because a SQL database, Redis, KV, and partitioned Durable Objects have different cleanup and scan mechanics.

Provider-level cleanup that checks domain relationships may remain in the OAuth engine, but it should use supported indexed queries rather than a global key-prefix scan.

### Pagination

```ts
export interface PageRequest {
  limit?: number;
  cursor?: string;
}

export interface Page<T> {
  items: T[];
  cursor?: string;
}
```

Cursors are opaque adapter values. Callers must not parse them or move them between adapters.

## Atomic grant transitions

OAuth code consumption and refresh rotation are more than record updates. The transition may run `tokenExchangeCallback`, which can redeem a single-use upstream credential. A compare-and-swap only at final commit allows two requests to run that side effect concurrently.

The storage contract therefore has a begin, commit, and abort protocol with a lease and fencing token.

### Begin

```ts
export interface BeginGrantTransitionInput {
  grant: GrantKey;
  kind: 'authorization_code' | 'refresh_token';

  /** Hash of the presented authorization code or refresh token. */
  credentialId: string;

  /** Unique identifier for this attempt. */
  ownerId: string;

  /** Short timeout for a crashed request. */
  leaseTtlSeconds: number;

  now: number;
}

export type BeginGrantTransitionResult =
  | {
      status: 'acquired';
      grant: StoredGrant;
      lease: GrantTransitionLease;
    }
  | { status: 'busy'; retryAfterSeconds: number }
  | { status: 'invalid_credential' }
  | { status: 'already_consumed' }
  | { status: 'expired' }
  | { status: 'not_found' };

export interface GrantTransitionLease {
  grant: GrantKey;
  ownerId: string;
  /** Monotonic fencing token generated by storage. */
  fence: number;
  expectedRevision: number;
  expiresAt: number;
}
```

An acquired transition guarantees that another strong transition for the same grant cannot be acquired until this lease commits, aborts, or expires.

The fencing token prevents an expired lease holder from committing after a newer holder acquires the grant.

### Callback boundary

Before acquiring a lease, the OAuth engine may load a snapshot and reject obviously invalid client, redirect, scope, resource, and PKCE input. `beginTransition` remains the authority for the current credential and revision. After it succeeds, the engine validates the returned grant again, then:

1. unwraps the grant encryption key;
2. runs `tokenExchangeCallback` if configured;
3. constructs the complete next grant and access-token record;
4. calls `commitTransition`.

Do not hold a database transaction or row lock open while application code performs network I/O. The lease is the cross-backend serialization primitive.

The OAuth engine must cap callback time below the lease lifetime. A future lease renewal method can be added if real callbacks need longer execution.

The lease prevents concurrent callback execution for one grant. It cannot make an external side effect transactional. If an upstream server rotates its refresh token but the callback loses the response, local storage cannot determine the upstream result. The callback receives a stable idempotency key derived from the grant and presented credential, but an upstream service may not honor one. Applications that bridge a non-idempotent upstream must still define recovery behavior. The storage provider must not claim to solve ambiguous external failures.

### Commit

```ts
export interface CommitGrantTransitionInput {
  lease: GrantTransitionLease;
  now: number;
  grant: StoredGrant;
  accessToken: StoredAccessToken;
}

export type CommitGrantTransitionResult =
  | { status: 'committed' }
  | { status: 'lease_lost' }
  | { status: 'conflict' }
  | { status: 'expired' }
  | { status: 'not_found' };
```

A strong commit atomically:

- verifies the lease owner and fence;
- verifies the expected grant revision;
- writes the next grant revision;
- creates the access-token record;
- clears the lease.

Either both records commit or neither does.

### Abort

`abortTransition` clears the lease only when owner and fence still match. A failed callback calls abort in `finally`. A crashed request relies on lease expiry.

### Compatibility implementation

Workers KV cannot implement this protocol strongly. Its adapter may provide a best-effort implementation matching today's behavior, but its capability descriptor must say `best_effort`. Features that require strong transitions reject the adapter at construction.

## Capabilities

Capabilities describe externally observable guarantees. They do not expose implementation choices such as SQL dialect or Lua.

```ts
export type Guarantee = 'strong' | 'best_effort' | 'unsupported';

export interface OAuthStorageCapabilities {
  consistency: {
    /** Visibility of a successful write to a later independent request. */
    readAfterWrite: 'strong' | 'session' | 'eventual';
  };

  issuance: {
    /** Atomic creation of a grant and its first access token. */
    grantWithAccessToken: Guarantee;
    /** Guarded token creation on an existing active grant. */
    existingGrantAccessToken: Guarantee;
  };

  transitions: {
    authorizationCode: Guarantee;
    refreshToken: Guarantee;
  };

  replayReservation: Guarantee;

  revocation: {
    /** Visibility of access-token deletion to token validation. */
    accessToken: Guarantee;
    /** Atomic grant and child-token teardown. */
    grantCascade: Guarantee;
    /** Atomic client, grant, and token teardown across all users. */
    clientCascade: Guarantee;
  };

  queries: {
    listClients: boolean;
    grantsByUser: boolean;
    grantsByClient: boolean;
    tokensByGrant: boolean;
    consentsByUser: boolean;
    globalMaintenance: boolean;
  };

  expiration: {
    /** Correctness always uses `expiresAt`; this describes physical cleanup. */
    cleanup: 'native' | 'scheduled' | 'manual';
    minimumTtlSeconds: number;
  };
}
```

The capability object is deeply readonly at runtime. Built-in adapters define it in one exported descriptor used by tests and documentation.

### Why no generic `transactions: boolean`

A transaction callback has different meanings across adapters:

- a local SQL driver can invoke a JavaScript callback on one connection;
- D1 exposes transactional batches, not an arbitrary interactive callback;
- Durable Object RPC cannot transport a callback;
- Redis uses commands, transactions, or scripts;
- KV has none.

The OAuth engine needs atomic grant transitions and replay reservation, not a generic transaction badge. The contract names those guarantees directly.

## Feature requirements

Each OAuth feature declares its minimum storage requirements. Validation happens before requests are served.

```ts
interface StorageRequirement {
  capability: string;
  minimum: 'best_effort' | 'strong';
  consequence: 'warn' | 'reject';
}
```

### Compatibility negotiation

The package exports one pure resolver used by the constructor, tests, and documentation tooling:

```ts
export interface OAuthStorageCompatibilityReport {
  adapterId: string;
  contractVersion: 1;
  overall: 'full' | 'compatibility' | 'unavailable';
  features: Record<
    string,
    {
      status: 'full' | 'compatibility' | 'unavailable';
      reason?: string;
      missingCapabilities?: string[];
    }
  >;
}

export function resolveOAuthStorageCompatibility(input: {
  capabilities: OAuthStorageCapabilities;
  enabledFeatures: readonly string[];
}): OAuthStorageCompatibilityReport;
```

`OAuthProvider#getStorageCompatibility()` returns the static report without opening a database connection. Construction rejects enabled features marked `unavailable`, logs each compatibility warning once, and remains silent when the report is `full`.

Helper-only features, such as global purge or deleting a client with a cross-user cascade, may be absent from normal request handling. Those helpers throw a typed `unsupported_operation` only when called. Their status is still visible in the report.

The feature registry and built-in adapter descriptors are code. The published compatibility table is generated from those values or checked by a test, following the same principle as pi-ai's model descriptors.

Initial policy:

| OAuth feature                                            | Storage requirement                           | Compatibility behavior                                                   |
| -------------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------ |
| Grant plus initial token issuance                        | Best-effort or strong atomic issuance         | KV preserves current partial-write behavior; strict mode requires strong |
| Existing authorization-code flow                         | Best-effort code transition                   | Allowed on KV with documented race behavior                              |
| Strict authorization-code consumption                    | Strong code transition                        | Reject unsupported adapter                                               |
| Existing two-token refresh grace                         | Best-effort refresh transition                | Allowed on KV with documented stale-write behavior                       |
| Strict refresh rotation and replay detection             | Strong refresh transition                     | Reject unsupported adapter                                               |
| `tokenExchangeCallback` with serialized upstream refresh | Strong refresh transition                     | Warn in compatibility mode, require in strict mode                       |
| EMA JTI replay prevention                                | Strong replay reservation                     | Existing KV path is degraded; strict EMA must reject it                  |
| Client credentials                                       | Grant plus initial token issuance             | Compatibility on KV, full on strong planned adapters                     |
| RFC 8693 token exchange                                  | Guarded existing-grant token issuance         | Compatibility on KV, strict mode requires strong                         |
| Introspection                                            | Token read plus required consistency policy   | KV revocation visibility remains eventual                                |
| Immediate revocation                                     | Strong access-token revocation                | Reject or document bounded staleness                                     |
| Existing DCR with generated client IDs                   | Best-effort client create plus logical expiry | Available on KV with collision caveat                                    |
| Strict/custom-ID DCR create-if-absent                    | Strong client create                          | Reject unsupported adapter                                               |
| Device authorization                                     | Strong guarded state transition               | Reject unsupported adapter                                               |
| Storage-backed rate limiting                             | Strong atomic counter, future capability      | Reject unsupported adapter                                               |
| Persistent consent                                       | Unique create/update and indexed user query   | Adapter must declare `consentsByUser`                                    |
| Delete-client cascade                                    | Client cascade capability                     | Helper reports compatibility or unavailable based on adapter             |
| Global purge                                             | Global maintenance capability                 | Use adapter cleanup if available; otherwise disable                      |

The final feature registry should live in code and have tests. The documentation matrix must be generated from or checked against those declarations so it does not drift.

### Support states

User-facing compatibility uses three states:

- `full`: the adapter provides all required guarantees;
- `compatibility`: the operation is available with weaker consistency matching legacy behavior;
- `unavailable`: construction or the specific helper fails with a clear unsupported-feature error.

The provider must not silently turn `unavailable` into a scan, local mutex, or read-then-write fallback.

## Adapter specifications

### Workers KV adapter

Physical model:

- preserve the current keys and JSON values;
- use native expiration where the 60-second minimum permits it;
- preserve prefix list cursors;
- continue checking logical `expiresAt` in the OAuth engine.

Declared guarantees:

- eventual read-after-write across locations;
- best-effort code and refresh transitions;
- best-effort replay reservation;
- eventual access-token revocation;
- best-effort grant and client cascades;
- current list queries and global maintenance available;
- native expiration with a 60-second minimum.

The adapter is zero-migration and remains the default for backward compatibility.

### Durable Object SQLite adapter

Physical model:

- route each client record to `client:{clientId}`;
- route each grant and its access-token records to `grant:{grantId}` by default;
- route a user's consent records to `consent:{userId}`;
- route each replay reservation to a deterministic object derived from its namespace and hash;
- execute transition methods inside the owning grant object;
- use SQLite tables rather than emulating KV unless migration compatibility requires a temporary record table;
- use alarms or logical expiry for cleanup;
- never rely on discovering Durable Object IDs.

Grant partition options:

- `grant`: one aggregate per grant, smallest contention domain and natural transition boundary;
- `user`: one aggregate per user, easier per-user grant listing and revocation but a larger contention domain;
- custom fixed sharding can be considered later.

`grant` should be the default for transition correctness. It co-locates exactly the records needed for code exchange, refresh rotation, token validation, and grant revocation. Other record types use their own deterministic partitions and do not share this option.

Point operations do not require a global index. Global queries need a separate index strategy. Options include:

- a D1 index;
- a sharded catalog Durable Object;
- a KV best-effort index;
- no global query support.

The index choice changes query capabilities and must be part of the provider descriptor. A KV index must not upgrade cross-partition operations to `strong`.

Target guarantees:

- strong per-partition read-after-write;
- strong client create and compare-and-swap within one client object;
- strong grant transitions;
- strong consent operations and user consent listing;
- strong replay reservation when routed consistently;
- strong grant cascade within a partition;
- query capabilities depend on configured index and grant partition;
- scheduled cleanup.

### D1 adapter

Physical model:

- normalized tables for clients, grants, access tokens, consents, transition leases, replay reservations, and schema metadata;
- indexes for user, client, grant, and expiry queries;
- guarded SQL updates and transactional `batch()` operation plans;
- `withSession("first-primary")` when read replication is enabled on security-sensitive paths;
- logical expiry on every read plus indexed cleanup.

D1's `batch()` can make a fixed list of statements atomic. The adapter must structure transition plans so a failed guard cannot insert child records. Conformance tests, not the presence of `batch()`, determine whether strong transition capabilities may be declared.

Target guarantees:

- strong or session-consistent read-after-write on correctly configured paths;
- strong code and refresh transitions;
- strong replay reservation through a unique key;
- strong token and grant revocation;
- all indexed queries;
- scheduled or manual cleanup.

The D1 adapter has no runtime dependency outside Workers bindings.

### PostgreSQL adapter

The package defines a minimal injected client contract:

```ts
export interface PostgresConnectionFactory<Env> {
  connect(env: Env): Promise<PostgresConnection>;
}

export interface PostgresConnection {
  query<Row>(sql: string, parameters?: readonly unknown[]): Promise<{ rows: Row[]; rowCount: number }>;

  /** Runs all callback queries on one database connection. */
  transaction<Result>(callback: (transaction: PostgresTransaction) => Promise<Result>): Promise<Result>;

  close(): Awaitable<void>;
}

export interface PostgresTransaction {
  query<Row>(sql: string, parameters?: readonly unknown[]): Promise<{ rows: Row[]; rowCount: number }>;
}
```

The application or an external package adapts `pg`, Postgres.js, an ORM, or another driver to this contract.

Physical model:

- normalized tables and indexes, including consent uniqueness;
- transactions for grant transition commits and cascades;
- unique constraints for client creation and replay reservation;
- row revision and fenced transition lease columns;
- indexed logical expiry and cleanup.

Hyperdrive requirements:

- create the driver client inside request handling;
- use a cache-disabled Hyperdrive configuration for all OAuth queries;
- preserve one connection for each transaction;
- do not run OAuth reads through the default cached binding.

Target guarantees:

- strong read-after-write from the primary database connection;
- strong transitions, reservations, and revocation;
- all indexed queries;
- manual or scheduled cleanup.

The first adapter targets PostgreSQL. MySQL syntax, affected-row behavior, and locking differ enough to warrant a separate adapter.

### Redis adapter

The package defines a minimal command contract rather than depending on one Redis SDK:

```ts
export interface RedisClientFactory<Env> {
  connect(env: Env): Awaitable<RedisClient>;
}

export interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options?: RedisSetOptions): Promise<unknown>;
  del(...keys: string[]): Promise<number>;
  scan(cursor: string, options: RedisScanOptions): Promise<RedisScanPage>;

  /** Required for strong transitions and replay reservations. */
  eval<Result>(script: string, keys: readonly string[], arguments_: readonly string[]): Promise<Result>;

  close?(): Awaitable<void>;
}
```

Physical model:

- hashes or JSON strings for records;
- sets or sorted sets for user, client, grant, and expiry indexes;
- Lua scripts for fenced leases, transition commit, replay reservation, and cascades;
- native TTL where practical, with logical expiry retained in records.

Redis Cluster requires all keys touched by one atomic script to share a hash slot. Aggregate keys therefore need a stable hash tag based on grant ID. Global indexes are updated separately and may be eventually repairable rather than part of the grant transition.

Target guarantees with `eval` and correct key layout:

- strong aggregate read-after-write;
- strong grant transitions and replay reservation;
- strong per-grant revocation;
- indexed queries with repairable secondary indexes;
- native expiry.

Without atomic scripts, the adapter advertises compatibility guarantees only.

## Initial compatibility matrix

This table describes the intended profiles. An adapter does not earn a `full` cell until its conformance tests pass.

| Capability or feature           | Workers KV                | DO SQLite, grant partition            | D1                  | PostgreSQL            | Redis with scripts                      |
| ------------------------------- | ------------------------- | ------------------------------------- | ------------------- | --------------------- | --------------------------------------- |
| Point reads and writes          | Full, eventual visibility | Full, strong per record partition     | Full                | Full                  | Full                                    |
| List clients                    | Full, eventual            | Requires global index                 | Full target         | Full target           | Full target with index                  |
| Strong client create and update | Unavailable               | Full per client                       | Full target         | Full target           | Full target                             |
| Atomic grant plus initial token | Unavailable               | Full within grant                     | Full target         | Full target           | Full target                             |
| Guarded token exchange issue    | Unavailable               | Full within grant                     | Full target         | Full target           | Full target                             |
| Authorization-code flow         | Compatibility             | Full                                  | Full target         | Full target           | Full target                             |
| Strict single code consumption  | Unavailable               | Full                                  | Full target         | Full target           | Full target                             |
| Existing refresh grace          | Compatibility             | Full                                  | Full target         | Full target           | Full target                             |
| Strict refresh rotation         | Unavailable               | Full                                  | Full target         | Full target           | Full target                             |
| Serialized callback per grant   | Unavailable               | Full                                  | Full target         | Full target           | Full target                             |
| Atomic EMA replay reservation   | Unavailable               | Full when routed consistently         | Full target         | Full target           | Full target                             |
| Immediate token revocation      | Compatibility             | Full within grant                     | Full target         | Full target           | Full within grant                       |
| List grants by user             | Full, eventual            | Requires index or user partition      | Full target         | Full target           | Full target with index                  |
| List grants by client           | Full, eventual            | Requires global index                 | Full target         | Full target           | Full target with index                  |
| Delete-client cascade           | Compatibility             | Requires global coordinator and index | Full target         | Full target           | Compatibility or full with index repair |
| Persistent consent              | Planned compatibility     | Full by user                          | Full target         | Full target           | Full target with index                  |
| Native physical TTL             | Full, minimum 60 seconds  | Alarm cleanup                         | No, logical cleanup | No, logical cleanup   | Full                                    |
| Global purge                    | Full scan, eventual       | Requires global index                 | Full target         | Full target           | Indexed cleanup target                  |
| Runtime dependencies in core    | None                      | None                                  | None                | None, client injected | None, client injected                   |

A real Redis service without scripts moves strict transition and reservation cells to `unavailable`. A DO adapter using KV for its global index keeps global query and cascade cells in `compatibility` even though per-grant transitions are strong.

## Schema and migrations

SQL adapters use a storage metadata table:

```sql
CREATE TABLE oauth_storage_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
```

The adapter records:

- storage contract version;
- physical schema version;
- adapter ID;
- migration state when needed.

Migration policy:

- the package exports migration SQL or a small migration runner;
- production requests do not perform broad schema migrations automatically;
- an adapter validates schema compatibility when opened and returns a specific setup error;
- Durable Object constructors may run idempotent local DDL under `blockConcurrencyWhile`;
- KV uses record-level lazy migration;
- migrations are forward-only;
- rollback means deploying code that can still read the previous record version, not rewriting all records during a request.

The package should not add a general schema CLI in the first release. D1 and Postgres examples can use Wrangler and the application's existing migration system.

## Adapter conformance suite

Export a test harness from a package subpath:

```ts
import { defineOAuthStorageConformanceSuite } from '@cloudflare/workers-oauth-provider/storage/testing';

defineOAuthStorageConformanceSuite({
  provider,
  reset,
  createEnv,
});
```

The harness tests only capabilities the provider declares, plus baseline behavior required of every adapter.

### Baseline tests

- create, read, replace, and delete clients;
- conflict on duplicate create;
- revision guard on replace;
- create and read grants and access tokens;
- atomic grant plus initial-token creation when declared;
- consent uniqueness, replacement, deletion, and user listing;
- logical expiration filtering;
- pagination without duplicates or omissions;
- cursor opacity;
- record schema version handling;
- no raw secrets in stored records;
- connection cleanup after success and error.

### Strong transition tests

- 20 concurrent authorization-code begins produce one lease owner;
- only the lease owner can commit;
- a stale fencing token cannot commit after lease expiry and reacquisition;
- grant update and access-token insert commit together;
- injected token-insert failure rolls back the grant update;
- grant plus initial-token creation commits both records or neither;
- token exchange cannot create a token after a strong grant revocation wins;
- abort releases only the matching lease;
- 20 concurrent refresh attempts do not run the protected callback concurrently;
- previous and current refresh credential policy matches the configured OAuth mode.

### Replay tests

- 20 concurrent reservations for one JTI produce one `reserved` result;
- reservation expires logically and physically according to the adapter policy;
- two namespaces can reserve the same hash independently.

### Revocation tests

- access-token deletion follows the declared visibility guarantee;
- grant cascade removes every child token;
- a transition racing revocation cannot recreate an active grant or token after a strong revocation wins;
- delete-client cascade covers grants for more than one user when supported;
- a transition racing client deletion cannot recreate a child after a strong client cascade wins.

### Query tests

- list by user and client uses stable pagination;
- records do not leak across users, clients, or provider namespaces;
- global maintenance converges after repeated bounded calls;
- secondary indexes recover from an interrupted index update where the adapter documents repair.

### Backend-specific integration tests

Mocks are insufficient for capability claims. Each built-in adapter also needs tests against its real execution model:

- Miniflare or workerd for KV, D1, and Durable Objects;
- a real PostgreSQL service for transaction and lock behavior;
- a real Redis service for Lua atomicity and cluster key layout where supported.

## Error model

Storage errors are typed and backend-neutral:

```ts
export type OAuthStorageErrorCode =
  | 'unavailable'
  | 'timeout'
  | 'rate_limited'
  | 'conflict'
  | 'schema_mismatch'
  | 'unsupported_operation'
  | 'invalid_configuration'
  | 'internal';

export class OAuthStorageError extends Error {
  readonly code: OAuthStorageErrorCode;
  readonly retryable: boolean;
  readonly cause?: unknown;
}
```

Adapters retain backend errors as `cause` but must not expose SQL, connection strings, record contents, or credentials in OAuth responses.

The OAuth engine maps retryable failures during token issuance to `temporarily_unavailable` where the relevant OAuth endpoint permits it. Conflicts from guarded transitions map to the appropriate OAuth error, usually `invalid_grant`, without leaking which credential check failed.

## Namespacing and multi-tenancy

Every provider receives a namespace string, defaulting to `default`. Adapters include it in keys, table predicates, unique constraints, and partition names.

```ts
storage: d1Storage({
  database: (env) => env.OAUTH_DB,
  namespace: 'production',
});
```

This allows one physical database to host more than one authorization server without record collisions. It does not by itself provide tenant isolation. Applications that need hard tenant isolation should use separate bindings, databases, or adapter instances.

Changing a namespace after issuing tokens is a storage migration and invalidates lookup unless both namespaces are read during a planned migration.

## Observability

The provider may expose optional storage instrumentation hooks:

```ts
interface OAuthStorageInstrumentation {
  operationStarted?(event: StorageOperationStarted): void;
  operationFinished?(event: StorageOperationFinished): void;
}
```

Events include adapter ID, operation name, duration, result class, and retry count. They never include record values, raw tokens, hashes, SQL parameters, client secrets, or decrypted props.

Adapters should use Workers traces where available but must not require an observability dependency.

## Packaging

Proposed exports:

```text
@cloudflare/workers-oauth-provider
@cloudflare/workers-oauth-provider/storage
@cloudflare/workers-oauth-provider/storage/kv
@cloudflare/workers-oauth-provider/storage/d1
@cloudflare/workers-oauth-provider/storage/durable-object
@cloudflare/workers-oauth-provider/storage/postgres
@cloudflare/workers-oauth-provider/storage/redis
@cloudflare/workers-oauth-provider/storage/testing
```

Packaging rules:

- the main provider does not eagerly import optional adapters;
- each adapter is tree-shakeable through its own entrypoint;
- there are no new runtime dependencies in the core package;
- Postgres and Redis entrypoints depend only on injected public interfaces;
- external packages can provide driver wrappers or full providers;
- built-in adapter declarations must not leak Node-only types into the main package;
- the main OAuth protocol implementation can remain in `src/oauth-provider.ts` for security review;
- adapter implementations may require separate source files and entrypoints, which is an explicit change to the repository's current single-source-file rule and needs approval before implementation.

A future split into `@cloudflare/workers-oauth-provider-storage-*` packages remains possible. Start with subpath exports while the contract is evolving, unless package ownership or release cadence makes separate packages necessary.

## Rollout plan

### Phase 0: contract RFC

- agree on provider, connection, record, transition, and capability types;
- agree on feature requirements and support states;
- decide whether Durable Object global indexing is part of the first adapter;
- decide whether D1 or Durable Object SQLite is the first strong Cloudflare adapter;
- agree on package subpaths and the single-file architecture exception.

No production code changes in this phase.

### Phase 1: contract, KV adapter, and harness

- add public storage types;
- route existing behavior through the Workers KV provider;
- preserve current keys and records;
- add compatibility warnings based on declared capabilities;
- publish the conformance harness;
- keep all existing tests passing without semantic changes.

This phase proves the seam but does not claim to fix KV races.

### Phase 2: first strong adapter

Recommended order:

1. D1 for a complete, dependency-free, globally queryable Cloudflare database adapter.
2. Durable Object SQLite for serialized per-grant state and a documented global-index choice.

An alternative is to ship Durable Object SQLite first if the immediate priority is the upstream refresh race rather than broad client and grant administration.

### Phase 3: injected clients

- PostgreSQL adapter with a driver-neutral connection factory;
- Redis adapter with script-capable client injection;
- external examples for `pg`, Postgres.js, Hyperdrive, PlanetScale Postgres, and a supported Redis service;
- separate MySQL adapter only after its SQL and transaction behavior has dedicated tests.

### Phase 4: strict feature gates

- add strict authorization-code consumption;
- add strict refresh rotation and replay detection;
- require strong replay reservation for strict EMA;
- add device flow, persistent consent, and storage-backed rate limiting only on compatible providers;
- expose a stable compatibility report for operators.

## Open decisions

1. Should D1 or Durable Object SQLite be the first strong adapter?
2. Should the Durable Object adapter require D1 for global indexes, offer an optional KV compatibility index, or omit global queries initially?
3. Should the first Durable Object adapter use one object per client, one object per consent owner, and one object per grant as proposed, or use a smaller fixed shard set to reduce object count?
4. Should the PostgreSQL and Redis implementations ship as package subpaths or separate packages from the start?
5. Should strict storage guarantees be opt-in during one minor release and become the default in the next major release?
6. Should the transition lease support renewal in contract version 1, or should callbacks be constrained to a fixed maximum duration first?
7. Do we keep the current two-refresh-token grace policy on strong adapters, or introduce an idempotent result cache and family replay detection as a separate OAuth behavior change?
8. Should a provider with unsupported admin queries omit helper methods at the type level, or expose them and fail with `unsupported_operation` at runtime? Runtime capability checks are simpler, while conditional types would provide earlier feedback but complicate `OAuthHelpers`.

## Acceptance criteria for the design

The RFC is ready for implementation when:

- every current storage call maps to a named contract operation;
- authorization-code exchange and refresh-token exchange have complete transition semantics;
- callback serialization is addressed, not only final-write compare-and-swap;
- the limits of serializing non-idempotent external side effects are documented;
- grant plus initial-token issuance cannot partially commit on strong adapters;
- each planned adapter has an honest capability profile;
- the feature compatibility matrix has owners and tests;
- KV compatibility behavior remains available without being described as strongly consistent;
- Postgres and Redis integrations require no runtime dependency in the core package;
- D1, Durable Object, Hyperdrive, PlanetScale, and Workers KV are classified correctly;
- migration and schema versioning rules are clear;
- the conformance suite can prove every strong capability under concurrency;
- the source and package layout change has explicit maintainer approval.

## References

- [Better Auth adapter factory and capability configuration](https://github.com/better-auth/better-auth/tree/main/packages/core/src/db/adapter)
- [Better Auth `consumeOne` and `incrementOne` contract](https://github.com/better-auth/better-auth/blob/main/packages/core/src/db/adapter/index.ts)
- [Better Auth secondary storage atomic methods](https://github.com/better-auth/better-auth/blob/main/packages/core/src/db/type.ts)
- [pi-ai API provider registry](https://github.com/badlogic/pi-mono/blob/main/packages/ai/src/api-registry.ts)
- [pi-ai model capability descriptors](https://github.com/badlogic/pi-mono/blob/main/packages/ai/src/types.ts)
- [pi-agent's use of pi-ai's normalized interface](https://github.com/badlogic/pi-mono/blob/main/packages/agent/src/agent-loop.ts)
- [Workers KV consistency and concurrent writes](https://developers.cloudflare.com/kv/api/write-key-value-pairs/)
- [Durable Object SQLite storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
- [Durable Object concurrency guidance](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/)
- [D1 database API, transactional batches, and sessions](https://developers.cloudflare.com/d1/worker-api/d1-database/)
- [Hyperdrive query caching and authentication guidance](https://developers.cloudflare.com/hyperdrive/concepts/query-caching/)
- [Hyperdrive Postgres and MySQL driver setup](https://developers.cloudflare.com/hyperdrive/get-started/)
- [OAuth 2.1 draft 15](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15)
- [RFC 9700 refresh-token protection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14)
