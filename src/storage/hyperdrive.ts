/**
 * Hyperdrive (Postgres) storage provider — opt-in.
 *
 * Backs clients, grants, and tokens with a Postgres database reached through a
 * Cloudflare Hyperdrive binding. Unlike KV, Postgres offers
 * **strongly-consistent reads**, so a refresh that reads a grant always sees
 * the latest committed rotation — removing the eventually-consistent half of
 * the concurrent-refresh `invalid_grant` problem. (Fully serializing the
 * read-modify-write across concurrent refreshes is a follow-up that layers a
 * transactional `SELECT … FOR UPDATE` path on top of this same table.)
 *
 * Data model: one KV-shaped table so the provider's existing key conventions
 * (`client:`, `grant:{userId}:`, `token:…`) work unchanged.
 *
 *   CREATE TABLE oauth_kv (
 *     key        TEXT PRIMARY KEY,
 *     value      TEXT   NOT NULL,
 *     expires_at BIGINT          -- Unix seconds, NULL = no expiry
 *   );
 *
 * See docs/storage-providers.md.
 */

import type {
  HyperdriveLike,
  OAuthStorage,
  SqlClient,
  StorageListOptions,
  StorageListResult,
  StoragePutOptions,
} from './types';

const DEFAULT_TABLE = 'oauth_kv';

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function resolveExpiry(options?: StoragePutOptions): number | null {
  if (options?.expiration !== undefined) return options.expiration;
  if (options?.expirationTtl !== undefined) return nowSeconds() + options.expirationTtl;
  return null;
}

/** Validate the table name is a bare identifier (it is interpolated, not bound). */
function assertSafeTableName(name: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new TypeError(`Invalid storage tableName: ${JSON.stringify(name)}`);
  }
}

/** Escape `%`, `_`, `\` for a LIKE prefix match. */
function escapeLikePrefix(prefix: string): string {
  return prefix.replace(/([%_\\])/g, '\\$1');
}

/**
 * Lazily create a `node-postgres` client from a Hyperdrive connection string.
 * `pg` is an optional peer dependency — only imported when this path is used.
 */
async function createPgClient(connectionString: string): Promise<SqlClient> {
  let pg: any;
  try {
    // Non-literal specifier so TypeScript doesn't require `pg` types at build
    // time — it's an optional peer dependency resolved only on this path.
    const moduleName = 'pg';
    pg = await import(/* @vite-ignore */ moduleName);
  } catch {
    throw new Error(
      "storage.type 'hyperdrive' requires the 'pg' package. Install it " +
        "(`npm i pg@>8.16.3`) and enable the 'nodejs_compat' compatibility flag, " +
        'or pass your own `client` in the storage config.'
    );
  }
  const Client = pg.Client ?? pg.default?.Client;
  const client = new Client({ connectionString });
  await client.connect();
  return client as SqlClient;
}

export class HyperdriveStorage implements OAuthStorage {
  readonly #table: string;
  readonly #injectedClient?: SqlClient;
  readonly #hyperdrive?: HyperdriveLike;
  #clientPromise?: Promise<SqlClient>;
  #schemaReady?: Promise<void>;

  constructor(config: { hyperdrive?: HyperdriveLike; client?: SqlClient; tableName?: string }) {
    this.#table = config.tableName ?? DEFAULT_TABLE;
    assertSafeTableName(this.#table);
    this.#injectedClient = config.client;
    this.#hyperdrive = config.hyperdrive;
    if (!this.#injectedClient && !this.#hyperdrive) {
      throw new TypeError("storage.type 'hyperdrive' requires either a `hyperdrive` binding or a `client`.");
    }
  }

  #client(): Promise<SqlClient> {
    if (this.#injectedClient) return Promise.resolve(this.#injectedClient);
    if (!this.#clientPromise) {
      this.#clientPromise = createPgClient(this.#hyperdrive!.connectionString);
    }
    return this.#clientPromise;
  }

  /** Create the table on first use (idempotent). */
  async #ensureSchema(client: SqlClient): Promise<void> {
    if (!this.#schemaReady) {
      this.#schemaReady = (async () => {
        await client.query(
          `CREATE TABLE IF NOT EXISTS ${this.#table} (
             key TEXT PRIMARY KEY,
             value TEXT NOT NULL,
             expires_at BIGINT
           )`
        );
      })();
    }
    return this.#schemaReady;
  }

  async #ready(): Promise<SqlClient> {
    const client = await this.#client();
    await this.#ensureSchema(client);
    return client;
  }

  get(key: string): Promise<string | null>;
  get(key: string, options: { type: 'json' }): Promise<any | null>;
  async get(key: string, options?: { type: 'json' }): Promise<any> {
    const client = await this.#ready();
    const res = await client.query<{ value: string; expires_at: string | number | null }>(
      `SELECT value, expires_at FROM ${this.#table} WHERE key = $1 LIMIT 1`,
      [key]
    );
    const row = res.rows[0];
    if (!row) return null;
    if (row.expires_at !== null && Number(row.expires_at) <= nowSeconds()) {
      // Lazily reap the expired row.
      await client.query(`DELETE FROM ${this.#table} WHERE key = $1`, [key]);
      return null;
    }
    return options?.type === 'json' ? JSON.parse(row.value) : row.value;
  }

  async put(key: string, value: string, options?: StoragePutOptions): Promise<void> {
    const client = await this.#ready();
    const expiresAt = resolveExpiry(options);
    await client.query(
      `INSERT INTO ${this.#table} (key, value, expires_at) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
      [key, value, expiresAt]
    );
  }

  async delete(key: string): Promise<void> {
    const client = await this.#ready();
    await client.query(`DELETE FROM ${this.#table} WHERE key = $1`, [key]);
  }

  async list(options: StorageListOptions): Promise<StorageListResult> {
    const client = await this.#ready();
    const limit = options.limit ?? 1000;
    const offset = options.cursor ? Number.parseInt(options.cursor, 10) || 0 : 0;
    const likePrefix = escapeLikePrefix(options.prefix) + '%';
    const res = await client.query<{ key: string }>(
      `SELECT key FROM ${this.#table}
       WHERE key LIKE $1 ESCAPE '\\'
         AND (expires_at IS NULL OR expires_at > $2)
       ORDER BY key
       LIMIT $3 OFFSET $4`,
      [likePrefix, nowSeconds(), limit + 1, offset]
    );
    const rows = res.rows;
    const hasMore = rows.length > limit;
    const keys = rows.slice(0, limit).map((r) => ({ name: r.key }));
    return {
      keys,
      list_complete: !hasMore,
      cursor: hasMore ? String(offset + limit) : undefined,
    };
  }
}
