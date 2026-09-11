import { env as testEnv, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { OAuthProvider, type Grant, type OAuthHelpers, type Token } from '../../../src/oauth-provider';
import {
  durableObjectSqliteStorage,
  storageObjectName,
  type OAuthStorageObject,
} from '../../../src/storage/durable-object';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);

function now(): number {
  return Math.floor(Date.now() / 1000);
}

function grant(overrides: Partial<Grant> = {}): Grant {
  return {
    id: 'grant-1',
    clientId: 'client-1',
    userId: 'user-1',
    scope: ['read'],
    metadata: {},
    encryptedProps: 'ciphertext',
    createdAt: now(),
    refreshTokenId: HASH_A,
    refreshTokenWrappedKey: 'wrapped-refresh',
    expiresAt: now() + 3600,
    ...overrides,
  };
}

function token(overrides: Partial<Token> = {}): Token {
  return {
    id: HASH_B,
    grantId: 'grant-1',
    userId: 'user-1',
    createdAt: now(),
    expiresAt: now() + 3600,
    audience: 'https://example.com/api/',
    scope: ['read'],
    wrappedEncryptionKey: 'wrapped-access',
    grant: { clientId: 'client-1', scope: ['read'], encryptedProps: 'ciphertext' },
    ...overrides,
  };
}

/** Each test gets its own user so state never leaks between tests. */
let sequence = 0;
function user(): string {
  return `user-${Date.now()}-${sequence++}`;
}

interface StorageEnv {
  OAUTH_STORAGE: DurableObjectNamespace<OAuthStorageObject>;
}
const env = testEnv as unknown as StorageEnv;
const provider = durableObjectSqliteStorage<StorageEnv>({ binding: (e) => e.OAUTH_STORAGE });
const storage = provider.open(env);

async function userStub(userId: string) {
  return env.OAUTH_STORAGE.getByName(await storageObjectName({ kind: 'user', key: userId }));
}

describe('Durable Object SQLite storage adapter', () => {
  it("stores each user's grants and tokens in that user's object", async () => {
    const userId = user();
    // Build each fixture once: they carry now()-based timestamps, so a second fixture built
    // for the comparison could straddle a second boundary.
    const storedGrant = grant({ userId });
    const storedToken = token({ userId });
    await storage.grants.put(storedGrant, now() + 600);
    await storage.accessTokens.put(storedToken);
    expect(await storage.grants.get({ userId, grantId: 'grant-1' })).toEqual(storedGrant);
    expect(await storage.accessTokens.get({ userId, grantId: 'grant-1', tokenId: HASH_B })).toEqual(storedToken);
    expect(await storage.accessTokens.get({ userId: 'someone-else', grantId: 'grant-1', tokenId: HASH_B })).toBeNull();

    const kinds = await runInDurableObject(await userStub(userId), (_instance: OAuthStorageObject, state) =>
      state.storage.sql
        .exec<{ kind: string; expires_at: number | null }>('SELECT kind, expires_at FROM records ORDER BY kind')
        .toArray()
    );
    expect(kinds.map((row) => row.kind)).toEqual(['grant', 'token']);
    expect(kinds[0]!.expires_at).toBeGreaterThan(now());
  });

  it('serializes code exchange with a fenced lease', async () => {
    const userId = user();
    const key = { userId, grantId: 'grant-1' };
    await storage.grants.put(
      grant({ userId, authCodeId: HASH_A, authCodeWrappedKey: 'wrapped-code', refreshTokenId: undefined })
    );
    const begin = (credentialId: string) =>
      storage.grants.beginTransition({
        grant: key,
        kind: 'authorization_code',
        credentialId,
        now: now(),
        leaseTtlSeconds: 30,
      });

    expect(await begin(HASH_B)).toEqual({ status: 'invalid_credential' });
    const first = await begin(HASH_A);
    expect(first.status).toBe('acquired');
    if (first.status !== 'acquired') throw new Error('unreachable');
    expect(await begin(HASH_A)).toEqual({ status: 'busy', retryAfterSeconds: expect.any(Number) });

    const consumed = grant({ userId, authCodeId: HASH_A, refreshTokenId: HASH_C, refreshTokenWrappedKey: 'wrapped' });
    expect(
      await storage.grants.commitTransition({
        lease: first.lease,
        grant: consumed,
        grantExpiresAt: consumed.expiresAt,
        accessToken: token({ userId }),
        now: now(),
      })
    ).toEqual({ status: 'committed' });
    // A stale lease can no longer commit, and the code is spent.
    expect(
      await storage.grants.commitTransition({
        lease: first.lease,
        grant: consumed,
        accessToken: token({ userId }),
        now: now(),
      })
    ).toEqual({ status: 'conflict' });
    expect(await begin(HASH_A)).toEqual({ status: 'already_consumed' });
    expect(await storage.grants.get(key)).toEqual(consumed);
  });

  it('releases an aborted lease so the credential can be presented again', async () => {
    const userId = user();
    const key = { userId, grantId: 'grant-1' };
    await storage.grants.put(grant({ userId }));
    const begin = () =>
      storage.grants.beginTransition({
        grant: key,
        kind: 'refresh_token',
        credentialId: HASH_A,
        now: now(),
        leaseTtlSeconds: 30,
      });
    const first = await begin();
    if (first.status !== 'acquired') throw new Error('unreachable');
    await storage.grants.abortTransition(first.lease);
    expect((await begin()).status).toBe('acquired');
  });

  it('revokes a grant together with its tokens and reserves replay markers once', async () => {
    const userId = user();
    await storage.grants.put(grant({ userId }));
    await storage.accessTokens.put(token({ userId }));
    await storage.accessTokens.put(token({ userId, id: HASH_C }));
    await storage.grants.revoke({ userId, grantId: 'grant-1' });
    expect(await storage.grants.get({ userId, grantId: 'grant-1' })).toBeNull();
    expect(await storage.accessTokens.get({ userId, grantId: 'grant-1', tokenId: HASH_C })).toBeNull();

    const marker = `${userId}-${HASH_A}`;
    expect(await storage.replay.reserve(marker, now() + 60)).toBe('reserved');
    expect(await storage.replay.reserve(marker, now() + 60)).toBe('exists');
  });

  it('rejects operations that need a global index before any I/O', async () => {
    await expect(storage.clients.list()).rejects.toMatchObject({ code: 'unsupported_operation' });
    await expect(storage.clients.deleteWithGrants('client-1')).rejects.toMatchObject({ code: 'unsupported_operation' });
    await expect(
      storage.maintenance.purge({
        batchSize: 1,
        purgeOrphanedGrants: true,
        purgeExpiredGrants: true,
        purgeOrphanedTokens: true,
      })
    ).rejects.toMatchObject({ code: 'unsupported_operation' });
  });

  it("lists one client's grants for a user through the grants_client index", async () => {
    const userId = user();
    for (const [id, clientId] of [
      ['grant-a', 'client-1'],
      ['grant-b', 'client-2'],
      ['grant-c', 'client-1'],
    ] as const) {
      await storage.grants.put(grant({ userId, id, clientId }));
    }
    const first = await storage.grants.listByUserAndClient!(userId, 'client-1', { limit: 1 });
    expect(first.items.map((item) => item.id)).toEqual(['grant-a']);
    const rest = await storage.grants.listByUserAndClient!(userId, 'client-1', { cursor: first.cursor });
    expect(rest.items.map((item) => item.id)).toEqual(['grant-c']);
    expect(rest.cursor).toBeUndefined();
    expect((await storage.grants.listByUser(userId)).items).toHaveLength(3);

    const plan = await runInDurableObject(await userStub(userId), (_instance: OAuthStorageObject, state) =>
      state.storage.sql
        .exec<{
          detail: string;
        }>(
          "EXPLAIN QUERY PLAN SELECT key FROM records WHERE kind = 'grant' AND json_extract(value, '$.clientId') = ? AND key > ? ORDER BY key",
          'client-1',
          ''
        )
        .toArray()
    );
    expect(plan.map((row) => row.detail).join(' ')).toContain('grants_client');
  });

  it("replaces a user's earlier grant for the same client through the provider", async () => {
    interface Env extends StorageEnv {
      OAUTH_PROVIDER?: OAuthHelpers | null;
    }
    const userId = user();
    const redirectUri = 'https://client.example/callback';
    const oauth = new OAuthProvider<Env>({
      apiRoute: '/api/',
      apiHandler: { fetch: async () => new Response('api') },
      defaultHandler: {
        async fetch(request, e) {
          if (new URL(request.url).pathname !== '/authorize') return new Response('default');
          const parsed = await e.OAUTH_PROVIDER!.parseAuthRequest(request);
          const completed = await e.OAUTH_PROVIDER!.completeAuthorization({
            request: parsed,
            userId,
            metadata: {},
            scope: parsed.scope,
            props: { userId },
          });
          return Response.redirect(completed.redirectTo);
        },
      },
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      resourceMetadata: { resource: 'https://example.com/api/' },
      storage: durableObjectSqliteStorage<Env>({ binding: (e) => e.OAUTH_STORAGE }),
    });
    const testEnv: Env = { ...env, OAUTH_PROVIDER: null };
    const ctx = {
      waitUntil() {},
      passThroughOnException() {},
      props: {},
      exports: {},
      tracing: {},
    } as unknown as ExecutionContext;

    await oauth.fetch(new Request('https://example.com/'), testEnv, ctx);
    const client = await testEnv.OAUTH_PROVIDER!.createClient({
      redirectUris: [redirectUri],
      tokenEndpointAuthMethod: 'none',
    });
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('v'.repeat(64)));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const authorize = () =>
      oauth.fetch(
        new Request(
          `https://example.com/authorize?response_type=code&client_id=${client.clientId}` +
            `&redirect_uri=${encodeURIComponent(redirectUri)}&scope=read&code_challenge=${challenge}&code_challenge_method=S256`
        ),
        testEnv,
        ctx
      );

    expect((await authorize()).status).toBe(302);
    const first = await testEnv.OAUTH_PROVIDER!.listUserGrants(userId);
    expect(first.items).toHaveLength(1);
    expect((await authorize()).status).toBe(302);
    const second = await testEnv.OAUTH_PROVIDER!.listUserGrants(userId);
    expect(second.items).toHaveLength(1);
    expect(second.items[0]!.id).not.toBe(first.items[0]!.id);
  });
});
