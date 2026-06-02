/**
 * Storage abstraction for the OAuth provider.
 *
 * This intentionally mirrors the *subset* of the Cloudflare Workers KV API that
 * the provider already uses, so that swapping the backend is a matter of
 * replacing `env.OAUTH_KV` with `getStorage(env)` at each call site — nothing
 * else about the provider logic changes.
 *
 * Implementations:
 *  - `KvStorage`            — thin pass-through to `env.OAUTH_KV` (default).
 *  - `DurableObjectStorage` — routes values to a partitioned, single-threaded
 *                             SQLite Durable Object and keeps KV as an index.
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

/** Partition strategy for the Durable Object provider (grants + tokens). */
export type DurableObjectPartition = 'user' | 'grant';

/**
 * Storage configuration accepted by `OAuthProviderOptions.storage`.
 *
 * Defaults to `{ type: 'kv' }`, which is behaviour-identical to today.
 */
export type StorageConfig =
  | { type: 'kv' }
  | {
      type: 'durable_object';
      /**
       * How to partition the single-threaded value store for grants+tokens.
       * `'user'` (default) co-locates a user's grants+tokens in one DO so the
       * refresh-token read-modify-write is serialized; throughput scales with
       * the number of active users. `'grant'` is finer-grained.
       */
      partition?: DurableObjectPartition;
    };
