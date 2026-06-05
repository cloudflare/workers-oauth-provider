/**
 * Storage abstraction for the OAuth provider.
 *
 * This intentionally mirrors the *subset* of the Cloudflare Workers KV API that
 * the provider already uses, so that swapping the backend is a matter of
 * replacing `env.OAUTH_KV` with `getStorage(env)` at each call site — nothing
 * else about the provider logic changes.
 *
 * Implementations:
 *  - `KvStorage`         — thin pass-through to `env.OAUTH_KV` (default).
 *  - `HyperdriveStorage` — backed by a Postgres database reached through a
 *                          Cloudflare Hyperdrive binding (opt-in). Gives
 *                          strongly-consistent reads, which KV cannot.
 *
 * See docs/storage-providers.md for the design rationale.
 */

/** A single key entry returned by {@link OAuthStorage.list}. */
export interface StorageListKey {
  name: string;
}

/** Result of a {@link OAuthStorage.list} call (KV-compatible shape). */
export interface StorageListResult {
  keys: StorageListKey[];
  list_complete: boolean;
  cursor?: string;
}

/** Options for {@link OAuthStorage.put} (KV-compatible subset). */
export interface StoragePutOptions {
  /** Relative TTL in seconds. */
  expirationTtl?: number;
  /** Absolute expiration as a Unix timestamp in seconds. */
  expiration?: number;
}

/** Options for {@link OAuthStorage.list} (KV-compatible subset). */
export interface StorageListOptions {
  prefix: string;
  limit?: number;
  cursor?: string;
}

/**
 * The minimal key/value surface the OAuth provider depends on.
 *
 * Semantics match Cloudflare Workers KV:
 *  - `get` with `{ type: 'json' }` parses JSON and returns `null` when absent.
 *  - `put` honours `expirationTtl` (relative seconds) or `expiration`
 *    (absolute Unix seconds); expired entries are not returned by `get`/`list`.
 *  - `list` is prefix-scoped and cursor-paginated.
 */
export interface OAuthStorage {
  get(key: string): Promise<string | null>;
  get(key: string, options: { type: 'json' }): Promise<any | null>;
  put(key: string, value: string, options?: StoragePutOptions): Promise<void>;
  delete(key: string): Promise<void>;
  list(options: StorageListOptions): Promise<StorageListResult>;
}

/**
 * Minimal async SQL client surface the Hyperdrive provider needs.
 *
 * Both `node-postgres` (`pg`) `Client`/`Pool` and a thin adapter over
 * `postgres.js` satisfy this. Exposing it lets consumers inject their own
 * driver/pool (and lets tests pass a fake), instead of the library taking a
 * hard dependency on a specific Postgres driver.
 */
export interface SqlQueryResult<Row = any> {
  rows: Row[];
}
export interface SqlClient {
  query<Row = any>(text: string, params?: unknown[]): Promise<SqlQueryResult<Row>>;
}

/**
 * The shape of a Cloudflare Hyperdrive binding we rely on. (Declared locally to
 * avoid a hard dependency on `@cloudflare/workers-types` Hyperdrive typings.)
 */
export interface HyperdriveLike {
  connectionString: string;
}

/**
 * Storage configuration accepted by `OAuthProviderOptions.storage`.
 *
 * Defaults to `{ type: 'kv' }`, which is behaviour-identical to today.
 */
export type StorageConfig =
  | { type: 'kv' }
  | {
      /**
       * Postgres reached via a Cloudflare Hyperdrive binding.
       *
       * Provide the Hyperdrive binding as `hyperdrive` and the provider will
       * create a `node-postgres` client per request (Hyperdrive pools the
       * underlying connections). Alternatively, inject your own `client`
       * (any {@link SqlClient}) to control the driver/pool yourself.
       */
      type: 'hyperdrive';
      /** The Hyperdrive binding (e.g. `env.HYPERDRIVE`). */
      hyperdrive?: HyperdriveLike;
      /**
       * Optional pre-constructed SQL client. When provided, takes precedence
       * over `hyperdrive` and the built-in `pg` driver is not imported.
       */
      client?: SqlClient;
      /** Table name for the key/value store. Defaults to `oauth_kv`. */
      tableName?: string;
    };
