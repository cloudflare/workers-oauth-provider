import { describe, it, expect, beforeEach } from 'vitest';
import { HyperdriveStorage, KvStorage } from '../src/storage';
import { resolveStorage } from '../src/storage/index';
import type { SqlClient } from '../src/storage';

/**
 * In-memory fake Postgres client implementing exactly the statements
 * HyperdriveStorage issues. Backed by a Map keyed on `key`.
 */
class FakeSql implements SqlClient {
  rows = new Map<string, { value: string; expires_at: number | null }>();
  queries: string[] = [];

  async query<Row = any>(text: string, params: unknown[] = []): Promise<{ rows: Row[] }> {
    const q = text.replace(/\s+/g, ' ').trim();
    this.queries.push(q);

    if (q.startsWith('CREATE TABLE')) return { rows: [] };

    if (q.startsWith('SELECT value, expires_at FROM')) {
      const row = this.rows.get(params[0] as string);
      return { rows: row ? [row as unknown as Row] : [] };
    }

    if (q.startsWith('INSERT INTO')) {
      const [key, value, expiresAt] = params as [string, string, number | null];
      this.rows.set(key, { value, expires_at: expiresAt ?? null });
      return { rows: [] };
    }

    if (q.startsWith('DELETE FROM')) {
      this.rows.delete(params[0] as string);
      return { rows: [] };
    }

    if (q.startsWith('SELECT key FROM')) {
      const [likePrefix, now, limit, offset] = params as [string, number, number, number];
      const prefix = likePrefix.replace(/\\([%_\\])/g, '$1').replace(/%$/, '');
      const matched = [...this.rows.entries()]
        .filter(([k, r]) => k.startsWith(prefix) && (r.expires_at === null || r.expires_at > now))
        .map(([k]) => k)
        .sort();
      const page = matched.slice(offset, offset + limit);
      return { rows: page.map((key) => ({ key }) as unknown as Row) };
    }

    throw new Error('Unhandled SQL in fake: ' + q);
  }
}

describe('HyperdriveStorage', () => {
  let sql: FakeSql;
  let storage: HyperdriveStorage;

  beforeEach(() => {
    sql = new FakeSql();
    storage = new HyperdriveStorage({ client: sql });
  });

  it('get/put/delete round-trips with JSON', async () => {
    expect(await storage.get('grant:u1:g1')).toBeNull();
    await storage.put('grant:u1:g1', JSON.stringify({ a: 1 }));
    expect(await storage.get('grant:u1:g1', { type: 'json' })).toEqual({ a: 1 });
    expect(await storage.get('grant:u1:g1')).toBe('{"a":1}');
    await storage.delete('grant:u1:g1');
    expect(await storage.get('grant:u1:g1')).toBeNull();
  });

  it('creates the schema once (idempotent)', async () => {
    await storage.put('client:abc', '{}');
    await storage.get('client:abc');
    await storage.list({ prefix: 'client:' });
    const creates = sql.queries.filter((q) => q.startsWith('CREATE TABLE'));
    expect(creates).toHaveLength(1);
  });

  it('honours expirationTtl and treats expired rows as absent', async () => {
    await storage.put('token:u1:g1:t1', 'v', { expirationTtl: -5 });
    expect(await storage.get('token:u1:g1:t1')).toBeNull();
    // expired row is reaped
    expect(sql.rows.has('token:u1:g1:t1')).toBe(false);
  });

  it('honours absolute expiration', async () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    await storage.put('token:u1:g1:t1', 'v', { expiration: future });
    expect(await storage.get('token:u1:g1:t1')).toBe('v');
    expect(sql.rows.get('token:u1:g1:t1')!.expires_at).toBe(future);
  });

  it('a read after a write sees the latest value (strong consistency)', async () => {
    await storage.put('grant:u1:g1', JSON.stringify({ rotation: 1 }));
    const a = await storage.get('grant:u1:g1', { type: 'json' });
    await storage.put('grant:u1:g1', JSON.stringify({ rotation: a.rotation + 1 }));
    const b = await storage.get('grant:u1:g1', { type: 'json' });
    expect(b.rotation).toBe(2);
  });

  it('list is prefix-scoped, ordered, and excludes expired entries', async () => {
    await storage.put('grant:u1:g1', '{}');
    await storage.put('grant:u2:g2', '{}');
    await storage.put('client:abc', '{}');
    await storage.put('grant:u3:gx', '{}', { expirationTtl: -1 }); // expired
    const grants = await storage.list({ prefix: 'grant:' });
    expect(grants.keys.map((k) => k.name)).toEqual(['grant:u1:g1', 'grant:u2:g2']);
    expect(grants.list_complete).toBe(true);
    expect(grants.cursor).toBeUndefined();
  });

  it('list paginates with a cursor', async () => {
    for (let i = 0; i < 5; i++) await storage.put(`grant:u:${i}`, '{}');
    const page1 = await storage.list({ prefix: 'grant:', limit: 2 });
    expect(page1.keys.map((k) => k.name)).toEqual(['grant:u:0', 'grant:u:1']);
    expect(page1.list_complete).toBe(false);
    expect(page1.cursor).toBe('2');

    const page2 = await storage.list({ prefix: 'grant:', limit: 2, cursor: page1.cursor });
    expect(page2.keys.map((k) => k.name)).toEqual(['grant:u:2', 'grant:u:3']);
    expect(page2.list_complete).toBe(false);

    const page3 = await storage.list({ prefix: 'grant:', limit: 2, cursor: page2.cursor });
    expect(page3.keys.map((k) => k.name)).toEqual(['grant:u:4']);
    expect(page3.list_complete).toBe(true);
    expect(page3.cursor).toBeUndefined();
  });

  it('rejects an unsafe tableName', () => {
    expect(() => new HyperdriveStorage({ client: sql, tableName: 'oauth; DROP TABLE x' })).toThrow(
      /Invalid storage tableName/
    );
  });

  it('uses a custom tableName in queries', async () => {
    const custom = new HyperdriveStorage({ client: sql, tableName: 'oauth_data' });
    await custom.put('client:abc', '{}');
    expect(sql.queries.some((q) => q.includes('INSERT INTO oauth_data'))).toBe(true);
  });

  it('requires either a hyperdrive binding or a client', () => {
    expect(() => new HyperdriveStorage({})).toThrow(/requires either a `hyperdrive` binding or a `client`/);
  });
});

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
      const keys = [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name }));
      return { keys, list_complete: true };
    },
  };
}

describe('resolveStorage factory', () => {
  it('defaults to KV', () => {
    expect(resolveStorage(undefined, { OAUTH_KV: makeKv() })).toBeInstanceOf(KvStorage);
  });

  it('explicit kv is KvStorage', () => {
    expect(resolveStorage({ type: 'kv' }, { OAUTH_KV: makeKv() })).toBeInstanceOf(KvStorage);
  });

  it('kv path requires the OAUTH_KV binding', () => {
    expect(() => resolveStorage({ type: 'kv' }, {})).toThrow(/OAUTH_KV/);
  });

  it('hyperdrive builds a HyperdriveStorage from a binding', () => {
    const s = resolveStorage({ type: 'hyperdrive', hyperdrive: { connectionString: 'postgres://localhost/db' } }, {});
    expect(s).toBeInstanceOf(HyperdriveStorage);
  });

  it('hyperdrive builds a HyperdriveStorage from an injected client', () => {
    const s = resolveStorage({ type: 'hyperdrive', client: new FakeSql() }, {});
    expect(s).toBeInstanceOf(HyperdriveStorage);
  });

  it('hyperdrive without binding or client throws', () => {
    expect(() => resolveStorage({ type: 'hyperdrive' }, {})).toThrow(
      /requires either a `hyperdrive` binding or a `client`/
    );
  });
});
