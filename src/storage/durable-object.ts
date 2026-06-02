/**
 * Durable Object storage provider (opt-in).
 *
 * Fixes the refresh-token read-modify-write race that KV cannot: a Durable
 * Object instance is single-threaded, so routing every operation for a grant to
 * the same instance serializes rotation. We partition by user (default) so we
 * don't recreate a global-singleton throughput cap, and we keep KV as a
 * cross-partition index for `list`/purge. See docs/storage-providers.md.
 *
 * Value of record  ── lives in the owning partition DO (authoritative, serialized)
 * Key existence     ── mirrored into KV so prefix `list` works across partitions
 *
 * Client records (read-heavy, low-write) stay in KV directly.
 */

import { DurableObject } from 'cloudflare:workers';

import type {
  DurableObjectPartition,
  OAuthStorage,
  StorageListOptions,
  StorageListResult,
  StoragePutOptions,
} from './types';

/** Marker value stored in the KV index for DO-backed keys. */
const INDEX_MARKER = '1';

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Resolve the absolute expiry (Unix seconds) from KV-style put options. */
function resolveExpiry(options?: StoragePutOptions): number | null {
  if (options?.expiration !== undefined) return options.expiration;
  if (options?.expirationTtl !== undefined) return nowSeconds() + options.expirationTtl;
  return null;
}

/**
 * Single-threaded SQLite-backed key/value store. One instance per partition
 * (e.g. `u:{userId}`). Holds the authoritative value for grant/token records.
 *
 * Consumers re-export this from their Worker entry and bind it as
 * `OAUTH_DURABLE_OBJECT` with a `new_sqlite_classes` migration.
 */
export class OAuthStore extends DurableObject {
  #initialized = false;

  #init(): void {
    if (this.#initialized) return;
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS kv (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        expires_at INTEGER
      );`
    );
    this.#initialized = true;
  }

  /** Read a value, treating expired rows as absent (and lazily reaping them). */
  async get(key: string): Promise<string | null> {
    this.#init();
    const cursor = this.ctx.storage.sql.exec<{ value: string; expires_at: number | null }>(
      'SELECT value, expires_at FROM kv WHERE key = ? LIMIT 1',
      key
    );
    const row = cursor.toArray()[0];
    if (!row) return null;
    if (row.expires_at !== null && row.expires_at <= nowSeconds()) {
      this.ctx.storage.sql.exec('DELETE FROM kv WHERE key = ?', key);
      return null;
    }
    return row.value;
  }

  /** Upsert a value with an optional absolute expiry (Unix seconds). */
  async put(key: string, value: string, expiresAt: number | null): Promise<void> {
    this.#init();
    this.ctx.storage.sql.exec(
      `INSERT INTO kv (key, value, expires_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at`,
      key,
      value,
      expiresAt
    );
    await this.#scheduleCleanup(expiresAt);
  }

  /** Delete a value. */
  async delete(key: string): Promise<void> {
    this.#init();
    this.ctx.storage.sql.exec('DELETE FROM kv WHERE key = ?', key);
  }

  /**
   * Atomic read-modify-write helper exposed for callers (e.g. refresh-token
   * rotation) that want the whole compare/update cycle serialized inside the
   * DO. The DO's single-threaded model guarantees no interleaving.
   */
  async getForUpdate(key: string): Promise<string | null> {
    return this.get(key);
  }

  async #scheduleCleanup(expiresAt: number | null): Promise<void> {
    if (expiresAt === null) return;
    const current = await this.ctx.storage.getAlarm();
    if (current === null) {
      await this.ctx.storage.setAlarm(expiresAt * 1000);
    }
  }

  /** Reap expired rows and re-arm the alarm if anything still has an expiry. */
  async alarm(): Promise<void> {
    this.#init();
    this.ctx.storage.sql.exec('DELETE FROM kv WHERE expires_at IS NOT NULL AND expires_at <= ?', nowSeconds());
    const next = this.ctx.storage.sql
      .exec<{ next: number | null }>('SELECT MIN(expires_at) AS next FROM kv WHERE expires_at IS NOT NULL')
      .toArray()[0];
    if (next?.next != null) {
      await this.ctx.storage.setAlarm(next.next * 1000);
    }
  }
}

/** Minimal binding shape we depend on (avoids leaking full generics). */
interface OAuthStoreNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): {
    get(key: string): Promise<string | null>;
    put(key: string, value: string, expiresAt: number | null): Promise<void>;
    delete(key: string): Promise<void>;
  };
}

/**
 * Routes operations to the right backend:
 *  - `grant:`/`token:` keys → owning partition DO (value) + KV index (key)
 *  - everything else (e.g. `client:`) → KV directly
 *  - all `list` → KV (it holds every key: client values + grant/token index)
 */
export class DurableObjectStorage implements OAuthStorage {
  readonly #kv: KVNamespace;
  readonly #ns: OAuthStoreNamespace;
  readonly #partition: DurableObjectPartition;

  constructor(kv: KVNamespace, ns: OAuthStoreNamespace, partition: DurableObjectPartition) {
    this.#kv = kv;
    this.#ns = ns;
    this.#partition = partition;
  }

  /** True for keys whose authoritative value lives in a partition DO. */
  #isDoBacked(key: string): boolean {
    return key.startsWith('grant:') || key.startsWith('token:');
  }

  /**
   * Map a key to its partition DO name.
   *  grant:{userId}:{grantId}
   *  token:{userId}:{grantId}:{tokenId}
   * Both carry `{userId}` as the second segment and `{grantId}` as the third.
   */
  #partitionName(key: string): string {
    const parts = key.split(':');
    const userId = parts[1] ?? '';
    if (this.#partition === 'grant') {
      const grantId = parts[2] ?? '';
      return `g:${userId}:${grantId}`;
    }
    return `u:${userId}`;
  }

  #stub(key: string) {
    return this.#ns.get(this.#ns.idFromName(this.#partitionName(key)));
  }

  get(key: string): Promise<string | null>;
  get(key: string, options: { type: 'json' }): Promise<any | null>;
  async get(key: string, options?: { type: 'json' }): Promise<any> {
    if (!this.#isDoBacked(key)) {
      return options?.type === 'json' ? this.#kv.get(key, { type: 'json' }) : this.#kv.get(key);
    }
    const raw = await this.#stub(key).get(key);
    if (raw === null) return null;
    return options?.type === 'json' ? JSON.parse(raw) : raw;
  }

  async put(key: string, value: string, options?: StoragePutOptions): Promise<void> {
    if (!this.#isDoBacked(key)) {
      return this.#kv.put(key, value, options);
    }
    const expiresAt = resolveExpiry(options);
    // Authoritative value into the partition DO …
    await this.#stub(key).put(key, value, expiresAt);
    // … and a lightweight index entry into KV so prefix `list` works.
    await this.#kv.put(key, INDEX_MARKER, options);
  }

  async delete(key: string): Promise<void> {
    if (!this.#isDoBacked(key)) {
      return this.#kv.delete(key);
    }
    await this.#stub(key).delete(key);
    await this.#kv.delete(key);
  }

  async list(options: StorageListOptions): Promise<StorageListResult> {
    // KV holds every key: client values directly, plus grant/token index keys.
    const result = await this.#kv.list(options);
    return {
      keys: result.keys.map((k) => ({ name: k.name })),
      list_complete: result.list_complete,
      cursor: 'cursor' in result ? (result as { cursor?: string }).cursor : undefined,
    };
  }
}
