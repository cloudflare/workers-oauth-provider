import { describe, it, expect } from 'vitest';
import { KvStorage } from '../src/storage';
import { resolveStorage } from '../src/storage/index';
import type { OAuthStorage, StorageListOptions } from '../src/storage';

/**
 * A complete, ~40-line example `OAuthStorage` backed by an in-memory Map.
 * Doubles as documentation: this is all someone needs to write to bring their
 * own backend. (A real implementation would issue SQL/HTTP instead.)
 */
class MemoryStorage implements OAuthStorage {
  rows = new Map<string, { value: string; expiresAt: number | null }>();

  #live(key: string) {
    const row = this.rows.get(key);
    if (!row) return null;
    if (row.expiresAt !== null && row.expiresAt <= Math.floor(Date.now() / 1000)) {
      this.rows.delete(key);
      return null;
    }
    return row;
  }

  get(key: string): Promise<string | null>;
  get(key: string, options: { type: 'json' }): Promise<any | null>;
  async get(key: string, options?: { type: 'json' }): Promise<any> {
    const row = this.#live(key);
    if (!row) return null;
    return options?.type === 'json' ? JSON.parse(row.value) : row.value;
  }

  async put(
    key: string,
    value: string,
    options?: { expirationTtl?: number; expiration?: number }
  ): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt =
      options?.expiration ?? (options?.expirationTtl != null ? now + options.expirationTtl : null);
    this.rows.set(key, { value, expiresAt });
  }

  async delete(key: string): Promise<void> {
    this.rows.delete(key);
  }

  async list(options: StorageListOptions) {
    const now = Math.floor(Date.now() / 1000);
    const all = [...this.rows.entries()]
      .filter(([k, r]) => k.startsWith(options.prefix) && (r.expiresAt === null || r.expiresAt > now))
      .map(([k]) => k)
      .sort();
    const limit = options.limit ?? 1000;
    const offset = options.cursor ? Number.parseInt(options.cursor, 10) || 0 : 0;
    const page = all.slice(offset, offset + limit);
    const hasMore = offset + limit < all.length;
    return {
      keys: page.map((name) => ({ name })),
      list_complete: !hasMore,
      cursor: hasMore ? String(offset + limit) : undefined,
    };
  }
}

/** In-memory KV with the subset of the API KvStorage uses. */
function makeKv() {
  const store = new Map<string, string>();
  return {
    store,
    async get(key: string, opts?: { type: 'json' }) {
      const v = store.get(key);
      if (v === undefined) return null;
      return opts?.type === 'json' ? JSON.parse(v) : v;
    },
    async put(key: string, value: string) {
      store.set(key, value);
    },
    async delete(key: string) {
      store.delete(key);
    },
    async list({ prefix }: { prefix: string }) {
      const keys = [...store.keys()]
        .filter((k: string) => k.startsWith(prefix))
        .map((name: string) => ({ name }));
      return { keys, list_complete: true };
    },
  };
}

describe('OAuthStorage contract (MemoryStorage example)', () => {
  it('get/put/delete round-trips with JSON', async () => {
    const s = new MemoryStorage();
    expect(await s.get('grant:u1:g1')).toBeNull();
    await s.put('grant:u1:g1', JSON.stringify({ a: 1 }));
    expect(await s.get('grant:u1:g1', { type: 'json' })).toEqual({ a: 1 });
    await s.delete('grant:u1:g1');
    expect(await s.get('grant:u1:g1')).toBeNull();
  });

  it('honours TTL and treats expired entries as absent', async () => {
    const s = new MemoryStorage();
    await s.put('token:u1:g1:t1', 'v', { expirationTtl: -5 });
    expect(await s.get('token:u1:g1:t1')).toBeNull();
  });

  it('list is prefix-scoped, ordered, paginated', async () => {
    const s = new MemoryStorage();
    for (let i = 0; i < 3; i++) await s.put(`grant:u:${i}`, '{}');
    await s.put('client:abc', '{}');
    const page1 = await s.list({ prefix: 'grant:', limit: 2 });
    expect(page1.keys.map((k) => k.name)).toEqual(['grant:u:0', 'grant:u:1']);
    expect(page1.list_complete).toBe(false);
    const page2 = await s.list({ prefix: 'grant:', limit: 2, cursor: page1.cursor });
    expect(page2.keys.map((k) => k.name)).toEqual(['grant:u:2']);
    expect(page2.list_complete).toBe(true);
  });
});

describe('resolveStorage', () => {
  it('defaults to KvStorage over env.OAUTH_KV', () => {
    expect(resolveStorage(undefined, { OAUTH_KV: makeKv() })).toBeInstanceOf(KvStorage);
  });

  it('default path requires the OAUTH_KV binding', () => {
    expect(() => resolveStorage(undefined, {})).toThrow(/OAUTH_KV/);
  });

  it('accepts a factory and calls it with env', () => {
    const env = { MY_BINDING: 'x' };
    let seen: any;
    const s = resolveStorage((e: any) => {
      seen = e;
      return new MemoryStorage();
    }, env);
    expect(s).toBeInstanceOf(MemoryStorage);
    expect(seen).toBe(env);
  });

  it('memoizes custom storage by factory and env', () => {
    const env = { OAUTH_KV: makeKv() };
    let calls = 0;
    const provider = () => {
      calls++;
      return new MemoryStorage();
    };
    const a = resolveStorage(provider, env);
    const b = resolveStorage(provider, env);
    expect(a).toBe(b);
    expect(calls).toBe(1);
  });

  it('does not share memoized storage across different factories', () => {
    const env = { OAUTH_KV: makeKv() };
    const a = resolveStorage(() => new MemoryStorage(), env);
    const b = resolveStorage(() => new MemoryStorage(), env);
    expect(a).not.toBe(b);
  });

  it('memoizes the default KV wrapper per env', () => {
    const env = { OAUTH_KV: makeKv() };
    const a = resolveStorage(undefined, env);
    const b = resolveStorage(undefined, env);
    expect(a).toBe(b);
  });
});
