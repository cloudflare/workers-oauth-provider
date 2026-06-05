# Storage providers

The OAuth provider persists clients, grants, and tokens through a small
`OAuthStorage` interface. By default it uses Workers KV (`env.OAUTH_KV`),
unchanged. To use another backend — Postgres via Hyperdrive, D1, Durable
Objects, a test double — implement the interface and pass an instance as
`storage`.

## The blessed setup

Use the canonical module-scope Worker export, and import bindings with
`cloudflare:workers` when you need them at construction time:

```ts
import { env } from 'cloudflare:workers';
import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import { PostgresStorage } from './postgres-storage';

export default new OAuthProvider({
  apiRoute: '/mcp',
  apiHandler: MyApiHandler,
  defaultHandler: MyAuthHandler,
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/token',

  storage: new PostgresStorage(env.HYPERDRIVE),
});
```

If you omit `storage`, the provider keeps using `env.OAUTH_KV`.

## The interface

```ts
interface OAuthStorage {
  get(key: string): Promise<string | null>;
  get(key: string, opts: { type: 'json' }): Promise<any | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number; expiration?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  list(opts: { prefix: string; limit?: number; cursor?: string }): Promise<{
    keys: { name: string }[];
    list_complete: boolean;
    cursor?: string;
  }>;
}
```

Semantics match the subset of Workers KV the provider already used:

- `get(key, { type: 'json' })` parses JSON and returns `null` when absent or
  expired.
- `put` honours `expirationTtl` (relative seconds) or `expiration` (absolute Unix
  seconds); expired entries must not be returned by `get`/`list`.
- `list` is prefix-scoped and cursor-paginated.

The provider only uses these key shapes, so one key/value table or namespace is
enough:

```
client:{clientId}
grant:{userId}:{grantId}
token:{userId}:{grantId}:{tokenId}
```

## Worked example: Postgres via Hyperdrive

This is intentionally just example code. The OAuth provider does not ship a
Postgres dependency or built-in Hyperdrive backend.

```ts
import { Client } from 'pg';
import type { OAuthStorage } from '@cloudflare/workers-oauth-provider';

// CREATE TABLE oauth_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at BIGINT);

export class PostgresStorage implements OAuthStorage {
  #connStr: string;
  #client?: Promise<Client>;

  constructor(hyperdrive: { connectionString: string }) {
    this.#connStr = hyperdrive.connectionString;
  }

  #db() {
    if (!this.#client) {
      this.#client = (async () => {
        const c = new Client({ connectionString: this.#connStr });
        await c.connect();
        return c;
      })();
    }
    return this.#client;
  }

  async get(key: string): Promise<string | null>;
  async get(key: string, opts: { type: 'json' }): Promise<any | null>;
  async get(key: string, opts?: { type: 'json' }) {
    const db = await this.#db();
    const now = Math.floor(Date.now() / 1000);
    const { rows } = await db.query(
      'SELECT value FROM oauth_kv WHERE key = $1 AND (expires_at IS NULL OR expires_at > $2)',
      [key, now]
    );
    if (!rows[0]) return null;
    return opts?.type === 'json' ? JSON.parse(rows[0].value) : rows[0].value;
  }

  async put(key: string, value: string, opts?: { expirationTtl?: number; expiration?: number }) {
    const db = await this.#db();
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = opts?.expiration ?? (opts?.expirationTtl != null ? now + opts.expirationTtl : null);
    await db.query(
      `INSERT INTO oauth_kv (key, value, expires_at) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
      [key, value, expiresAt]
    );
  }

  async delete(key: string) {
    const db = await this.#db();
    await db.query('DELETE FROM oauth_kv WHERE key = $1', [key]);
  }

  async list(opts: { prefix: string; limit?: number; cursor?: string }) {
    const db = await this.#db();
    const now = Math.floor(Date.now() / 1000);
    const limit = opts.limit ?? 1000;
    const offset = opts.cursor ? parseInt(opts.cursor, 10) || 0 : 0;
    const like = opts.prefix.replace(/([%_\\])/g, '\\$1') + '%';
    const { rows } = await db.query(
      `SELECT key FROM oauth_kv
       WHERE key LIKE $1 ESCAPE '\\' AND (expires_at IS NULL OR expires_at > $2)
       ORDER BY key LIMIT $3 OFFSET $4`,
      [like, now, limit + 1, offset]
    );
    const hasMore = rows.length > limit;
    return {
      keys: rows.slice(0, limit).map((r: { key: string }) => ({ name: r.key })),
      list_complete: !hasMore,
      cursor: hasMore ? String(offset + limit) : undefined,
    };
  }
}
```

Usage:

```ts
import { env } from 'cloudflare:workers';
import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import { PostgresStorage } from './postgres-storage';

export default new OAuthProvider({
  // …
  storage: new PostgresStorage(env.HYPERDRIVE),
});
```

## Why use a strongly-consistent store?

KV has no compare-and-swap and has eventually-consistent reads. During a
`refresh_token` exchange, two concurrent refreshes of the same grant can read the
same old grant, both rotate, and the last write wins. If your callback also
redeems a single-use upstream refresh token, this can surface as `invalid_grant`.

Postgres gives strongly-consistent reads, so a refresh sees the latest committed
grant rotation and avoids the stale-read class of failures.

## Migration guide

Existing deployments need no changes — KV remains the default.

To move to a custom backend:

1. Implement `OAuthStorage` for your backend.
2. Import `env` from `cloudflare:workers` in your Worker module.
3. Pass an instance: `storage: new MyStorage(env.MY_BINDING)`.
4. Backfill if needed. Key shapes are unchanged, so KV entries can be copied
   verbatim into a single key/value table, or you can write a temporary dual-read
   storage wrapper during cutover.

### Migrating from per-request construction

If you currently construct the provider inside `fetch`:

```ts
export default {
  fetch(request, env, ctx) {
    return new OAuthProvider({
      /* options */
      storage: new MyStorage(env.MY_BINDING),
    }).fetch(request, env, ctx);
  },
};
```

prefer the module-scope singleton:

```ts
import { env } from 'cloudflare:workers';

export default new OAuthProvider({
  /* options */
  storage: new MyStorage(env.MY_BINDING),
});
```

Handlers still receive the per-request `(request, env, ctx)` arguments. The
storage object should open connections lazily in its methods, not perform I/O in
its constructor.
