import { describe, it, expect, beforeEach, vi } from 'vitest';
import { OAuthStore, DurableObjectStorage, KvStorage } from '../src/storage';
import { resolveStorage } from '../src/storage/index';

/**
 * Minimal in-memory stand-in for `ctx.storage.sql` that understands exactly the
 * statements OAuthStore issues. Backed by a Map so behaviour is deterministic.
 */
class MockSql {
  rows = new Map<string, { value: string; expires_at: number | null }>();

  exec<T = any>(query: string, ...args: any[]): { toArray(): T[] } {
    const q = query.replace(/\s+/g, ' ').trim();

    if (q.startsWith('CREATE TABLE')) return { toArray: () => [] as T[] };

    if (q.startsWith('SELECT value, expires_at FROM kv WHERE key')) {
      const row = this.rows.get(args[0]);
      return { toArray: () => (row ? [row as unknown as T] : []) };
    }

    if (q.startsWith('SELECT MIN(expires_at)')) {
      let min: number | null = null;
      for (const r of this.rows.values()) {
        if (r.expires_at != null) min = min === null ? r.expires_at : Math.min(min, r.expires_at);
      }
      return { toArray: () => [{ next: min } as unknown as T] };
    }

    if (q.startsWith('INSERT INTO kv')) {
      const [key, value, expiresAt] = args;
      this.rows.set(key, { value, expires_at: expiresAt ?? null });
      return { toArray: () => [] as T[] };
    }

    if (q.startsWith('DELETE FROM kv WHERE expires_at IS NOT NULL AND expires_at <=')) {
      const cutoff = args[0];
      for (const [k, r] of this.rows) if (r.expires_at != null && r.expires_at <= cutoff) this.rows.delete(k);
      return { toArray: () => [] as T[] };
    }

    if (q.startsWith('DELETE FROM kv WHERE key')) {
      this.rows.delete(args[0]);
      return { toArray: () => [] as T[] };
    }

    throw new Error('Unhandled SQL in mock: ' + q);
  }
}

class MockDurableObjectState {
  storage: any;
  constructor() {
    const sql = new MockSql();
    let alarm: number | null = null;
    this.storage = {
      sql,
      getAlarm: async () => alarm,
      setAlarm: async (t: number) => {
        alarm = t;
      },
    };
  }
}

/** A namespace whose instances are real OAuthStore objects, keyed by name. */
function makeNamespace() {
  const instances = new Map<string, OAuthStore>();
  const created: string[] = [];
  return {
    created,
    instances,
    idFromName(name: string) {
      return { name } as any;
    },
    get(id: any) {
      const name = id.name as string;
      if (!instances.has(name)) {
        created.push(name);
        instances.set(name, new OAuthStore(new MockDurableObjectState() as any, {} as any));
      }
      return instances.get(name)!;
    },
  };
}

/** In-memory KV with the subset of the API the adapter uses. */
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

describe('OAuthStore (SQLite DO)', () => {
  it('get/put/delete round-trips', async () => {
    const store = new OAuthStore(new MockDurableObjectState() as any, {} as any);
    expect(await store.get('grant:u1:g1')).toBeNull();
    await store.put('grant:u1:g1', '{"a":1}', null);
    expect(await store.get('grant:u1:g1')).toBe('{"a":1}');
    await store.delete('grant:u1:g1');
    expect(await store.get('grant:u1:g1')).toBeNull();
  });

  it('treats expired rows as absent', async () => {
    const store = new OAuthStore(new MockDurableObjectState() as any, {} as any);
    const past = Math.floor(Date.now() / 1000) - 5;
    await store.put('token:u1:g1:t1', 'v', past);
    expect(await store.get('token:u1:g1:t1')).toBeNull();
  });
});

describe('DurableObjectStorage routing', () => {
  let kv: ReturnType<typeof makeKv>;
  let ns: ReturnType<typeof makeNamespace>;
  let storage: DurableObjectStorage;

  beforeEach(() => {
    kv = makeKv();
    ns = makeNamespace();
    storage = new DurableObjectStorage(kv as any, ns as any, 'user');
  });

  it('routes client records to KV directly (no DO)', async () => {
    await storage.put('client:abc', '{"clientId":"abc"}');
    expect(ns.created).toHaveLength(0);
    expect(await storage.get('client:abc', { type: 'json' })).toEqual({ clientId: 'abc' });
    expect(kv.store.get('client:abc')).toBe('{"clientId":"abc"}');
  });

  it('routes grant value to DO and a KV index entry', async () => {
    await storage.put('grant:u1:g1', '{"id":"g1"}');
    // value lives in the DO …
    expect(await storage.get('grant:u1:g1', { type: 'json' })).toEqual({ id: 'g1' });
    // … and KV holds only the index marker (so list works), not the value
    expect(kv.store.get('grant:u1:g1')).toBe('1');
  });

  it("co-locates a user's grant + tokens in ONE partition DO (user strategy)", async () => {
    await storage.put('grant:u1:g1', '{}');
    await storage.put('token:u1:g1:t1', '{}');
    await storage.put('token:u1:g1:t2', '{}');
    // all three keys for user u1 route to the same DO instance name
    expect(new Set(ns.created)).toEqual(new Set(['u:u1']));
  });

  it('different users get different partitions', async () => {
    await storage.put('grant:u1:g1', '{}');
    await storage.put('grant:u2:g9', '{}');
    expect(new Set(ns.created)).toEqual(new Set(['u:u1', 'u:u2']));
  });

  it('grant partition strategy isolates each grant', async () => {
    const perGrant = new DurableObjectStorage(makeKv() as any, ns as any, 'grant');
    await perGrant.put('grant:u1:g1', '{}');
    await perGrant.put('grant:u1:g2', '{}');
    expect(new Set(ns.created)).toEqual(new Set(['g:u1:g1', 'g:u1:g2']));
  });

  it('a second read sees the first write on the same partition (no split-brain)', async () => {
    // This is the property KV cannot guarantee: routing both ops to the same
    // single-threaded DO means the second observer sees the first writer.
    await storage.put('grant:u1:g1', JSON.stringify({ rotation: 1 }));
    const a = await storage.get('grant:u1:g1', { type: 'json' });
    await storage.put('grant:u1:g1', JSON.stringify({ rotation: a.rotation + 1 }));
    const b = await storage.get('grant:u1:g1', { type: 'json' });
    expect(b.rotation).toBe(2);
    // only one partition was ever touched for this grant
    expect(ns.created).toEqual(['u:u1']);
  });

  it('list enumerates from the KV index across partitions', async () => {
    await storage.put('grant:u1:g1', '{}');
    await storage.put('grant:u2:g2', '{}');
    await storage.put('client:abc', '{}');
    const grants = await storage.list({ prefix: 'grant:' });
    expect(grants.keys.map((k) => k.name).sort()).toEqual(['grant:u1:g1', 'grant:u2:g2']);
  });

  it('delete removes both DO value and KV index', async () => {
    await storage.put('grant:u1:g1', '{}');
    await storage.delete('grant:u1:g1');
    expect(await storage.get('grant:u1:g1')).toBeNull();
    expect(kv.store.has('grant:u1:g1')).toBe(false);
  });
});

describe('resolveStorage factory', () => {
  it('defaults to KV', () => {
    const kv = makeKv();
    const s = resolveStorage(undefined, { OAUTH_KV: kv });
    expect(s).toBeInstanceOf(KvStorage);
  });

  it('explicit kv is KvStorage', () => {
    const kv = makeKv();
    expect(resolveStorage({ type: 'kv' }, { OAUTH_KV: kv })).toBeInstanceOf(KvStorage);
  });

  it('durable_object requires the DO binding', () => {
    const kv = makeKv();
    expect(() => resolveStorage({ type: 'durable_object' }, { OAUTH_KV: kv })).toThrow(/OAUTH_DURABLE_OBJECT/);
  });

  it('durable_object also requires the KV index binding', () => {
    const ns = makeNamespace();
    expect(() => resolveStorage({ type: 'durable_object' }, { OAUTH_DURABLE_OBJECT: ns })).toThrow(/OAUTH_KV/);
  });

  it('durable_object builds a DurableObjectStorage when both bindings present', () => {
    const kv = makeKv();
    const ns = makeNamespace();
    const s = resolveStorage({ type: 'durable_object' }, { OAUTH_KV: kv, OAUTH_DURABLE_OBJECT: ns });
    expect(s).toBeInstanceOf(DurableObjectStorage);
  });

  it('missing KV on the kv path throws a helpful error', () => {
    expect(() => resolveStorage({ type: 'kv' }, {})).toThrow(/OAUTH_KV/);
  });
});
