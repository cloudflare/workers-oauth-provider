/**
 * Storage abstraction for the OAuth provider.
 *
 * The provider persists clients, grants, and tokens through this small
 * interface. By default it uses Workers KV (`env.OAUTH_KV`), unchanged. To use
 * any other backend (Postgres via Hyperdrive, D1, Durable Objects, a test
 * double, …) you implement `OAuthStorage` and pass it as `storage`.
 *
 * You pass an `OAuthStorage` **instance**. Build it with the Worker `env`
 * imported from `cloudflare:workers`, which is available at module scope:
 *
 * ```ts
 * import { env } from 'cloudflare:workers';
 *
 * export default new OAuthProvider({
 *   storage: new MyStorage(env.MY_BINDING),
 * });
 * ```
 *
 * The interface intentionally mirrors the *subset* of the Workers KV API the
 * provider already used, so implementations are small and the semantics are
 * familiar. See docs/storage-providers.md for a worked Postgres example and a
 * migration guide.
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
 *
 * Keys follow the provider's existing conventions (`client:{id}`,
 * `grant:{userId}:{grantId}`, `token:{userId}:{grantId}:{tokenId}`), so a
 * single key/value table or namespace is enough — no per-type modelling needed.
 */
export interface OAuthStorage {
  get(key: string): Promise<string | null>;
  get(key: string, options: { type: 'json' }): Promise<any | null>;
  put(key: string, value: string, options?: StoragePutOptions): Promise<void>;
  delete(key: string): Promise<void>;
  list(options: StorageListOptions): Promise<StorageListResult>;
}


