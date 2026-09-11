import { describe, expect, it, vi } from 'vitest';
import type { Grant, Token } from '../../src/oauth-provider';
import { workersKvStorage } from '../../src/storage/kv';
import { MockKV } from '../test-helpers';

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

function open() {
  const kv = new MockKV();
  const storage = workersKvStorage<{ OAUTH_KV: MockKV }>({ binding: (env) => env.OAUTH_KV as never }).open({
    OAUTH_KV: kv,
  });
  return { kv, storage };
}

describe('Workers KV storage adapter', () => {
  it('preserves the documented physical key layout', async () => {
    const { kv, storage } = open();
    await storage.clients.put({ clientId: 'client-1', redirectUris: [], tokenEndpointAuthMethod: 'none' });
    await storage.grants.put(grant(), now() + 600);
    await storage.accessTokens.put(token());
    await storage.replay.reserve(HASH_C, now() + 30);

    const keys = (await kv.list({ prefix: '' })).keys.map((key) => key.name).sort();
    expect(keys).toEqual([
      'client:client-1',
      `enterprise-jti:${HASH_C}`,
      'grant:user-1:grant-1',
      `token:user-1:grant-1:${HASH_B}`,
    ]);
    expect(await storage.grants.get({ userId: 'user-1', grantId: 'grant-1' })).toEqual(grant());
    expect(await storage.accessTokens.get({ userId: 'user-1', grantId: 'grant-1', tokenId: HASH_B })).toEqual(token());
  });

  it('clamps grant expirations and floors replay markers above the KV minimum', async () => {
    const { kv, storage } = open();
    const put = vi.spyOn(kv, 'put');
    await storage.grants.put(grant({ expiresAt: now() + 10 }), now() + 10);
    expect(put.mock.calls[0]![2]).toEqual({ expiration: expect.any(Number) });
    expect((put.mock.calls[0]![2] as { expiration: number }).expiration).toBeGreaterThanOrEqual(now() + 60);

    await storage.replay.reserve(HASH_C, now() + 5);
    expect(put.mock.calls[1]![2]).toEqual({ expirationTtl: 60 });
    expect(await storage.replay.reserve(HASH_C, now() + 5)).toBe('exists');
  });

  it('verifies the presented credential at begin and again at commit', async () => {
    const { storage } = open();
    await storage.grants.put(
      grant({ authCodeId: HASH_A, authCodeWrappedKey: 'wrapped-code', refreshTokenId: undefined })
    );
    const key = { userId: 'user-1', grantId: 'grant-1' };
    const begin = (credentialId: string) =>
      storage.grants.beginTransition({
        grant: key,
        kind: 'authorization_code',
        credentialId,
        now: now(),
        leaseTtlSeconds: 30,
      });

    expect(await begin(HASH_B)).toEqual({ status: 'invalid_credential' });
    const acquired = await begin(HASH_A);
    expect(acquired.status).toBe('acquired');
    if (acquired.status !== 'acquired') throw new Error('unreachable');

    const consumed = grant({ authCodeId: HASH_A, refreshTokenId: HASH_C, refreshTokenWrappedKey: 'wrapped' });
    expect(
      await storage.grants.commitTransition({
        lease: acquired.lease,
        grant: consumed,
        grantExpiresAt: consumed.expiresAt,
        accessToken: token(),
        now: now(),
      })
    ).toEqual({ status: 'committed' });
    expect(await begin(HASH_A)).toEqual({ status: 'already_consumed' });
    expect(
      await storage.grants.commitTransition({
        lease: acquired.lease,
        grant: consumed,
        accessToken: token(),
        now: now(),
      })
    ).toEqual({ status: 'conflict' });
    expect(
      await storage.grants.beginTransition({
        grant: { userId: 'user-1', grantId: 'missing' },
        kind: 'refresh_token',
        credentialId: HASH_A,
        now: now(),
        leaseTtlSeconds: 30,
      })
    ).toEqual({ status: 'not_found' });
  });

  it('accepts the current or previous refresh token only while its wrapped key is present', async () => {
    const { storage } = open();
    await storage.grants.put(grant({ previousRefreshTokenId: HASH_B }));
    const begin = (credentialId: string) =>
      storage.grants.beginTransition({
        grant: { userId: 'user-1', grantId: 'grant-1' },
        kind: 'refresh_token',
        credentialId,
        now: now(),
        leaseTtlSeconds: 30,
      });
    expect((await begin(HASH_A)).status).toBe('acquired');
    expect(await begin(HASH_B)).toEqual({ status: 'invalid_credential' });
    expect(await begin(HASH_C)).toEqual({ status: 'invalid_credential' });
  });

  it('revokes a grant with every token under it and deletes a client with its grants and exchanged tokens', async () => {
    const { kv, storage } = open();
    await storage.clients.put({ clientId: 'client-1', redirectUris: [], tokenEndpointAuthMethod: 'none' });
    await storage.grants.put(grant());
    await storage.grants.put(grant({ id: 'grant-2', clientId: 'client-2' }));
    await storage.accessTokens.put(token());
    await storage.accessTokens.put(
      token({ id: HASH_C, grantId: 'grant-2', grant: { clientId: 'client-2', scope: [], encryptedProps: 'x' } })
    );
    await storage.accessTokens.put(
      token({ id: HASH_A, grantId: 'grant-2', grant: { clientId: 'client-1', scope: [], encryptedProps: 'x' } })
    );

    await storage.clients.deleteWithGrants('client-1');
    const keys = (await kv.list({ prefix: '' })).keys.map((key) => key.name).sort();
    expect(keys).toEqual(['grant:user-1:grant-2', `token:user-1:grant-2:${HASH_C}`]);

    await storage.grants.revoke({ userId: 'user-1', grantId: 'grant-2' });
    expect((await kv.list({ prefix: '' })).keys).toHaveLength(0);
  });

  it("lists a user's grants and registered clients with cursors", async () => {
    const { storage } = open();
    for (const id of ['a', 'b', 'c']) await storage.grants.put(grant({ id }));
    await storage.grants.put(grant({ id: 'd', userId: 'user-2' }));
    await storage.clients.put({ clientId: 'client-1', redirectUris: [], tokenEndpointAuthMethod: 'none' });

    const first = await storage.grants.listByUser('user-1', { limit: 2 });
    expect(first.items.map((item) => item.id)).toEqual(['a', 'b']);
    const rest = await storage.grants.listByUser('user-1', { cursor: first.cursor });
    expect(rest.items.map((item) => item.id)).toEqual(['c']);
    expect(rest.cursor).toBeUndefined();
    expect(storage.grants.listByUserAndClient).toBeUndefined();
    expect((await storage.clients.list()).items.map((client) => client.clientId)).toEqual(['client-1']);
  });

  it('purges expired grants and tokens orphaned by a missing grant or client', async () => {
    const { kv, storage } = open();
    await storage.clients.put({ clientId: 'client-1', redirectUris: [], tokenEndpointAuthMethod: 'none' });
    await storage.grants.put(grant({ id: 'live' }));
    await storage.grants.put(grant({ id: 'orphan', clientId: 'gone' }));
    await storage.accessTokens.put(token({ id: HASH_A, grantId: 'live' }));
    await storage.accessTokens.put(token({ id: HASH_B, grantId: 'missing' }));
    await storage.accessTokens.put(
      token({ id: HASH_C, grantId: 'live', grant: { clientId: 'gone', scope: [], encryptedProps: 'x' } })
    );

    const result = await storage.maintenance.purge({
      batchSize: 50,
      purgeOrphanedGrants: true,
      purgeExpiredGrants: true,
      purgeOrphanedTokens: true,
    });
    expect(result).toEqual({ grantsChecked: 2, grantsPurged: 1, tokensChecked: 3, tokensPurged: 2, done: true });
    const keys = (await kv.list({ prefix: '' })).keys.map((key) => key.name).sort();
    expect(keys).toEqual(['client:client-1', 'grant:user-1:live', `token:user-1:live:${HASH_A}`]);
  });

  it('maps KV rate limiting to a retryable storage error and passes other failures through', async () => {
    const { kv, storage } = open();
    kv.put = vi.fn(async () => {
      throw new Error('KV PUT failed: 429 Too Many Requests');
    });
    await expect(storage.grants.put(grant())).rejects.toMatchObject({ code: 'rate_limited', retryable: true });
    kv.put = vi.fn(async () => {
      throw new Error('KV PUT failed: 500 Internal Error');
    });
    await expect(storage.grants.put(grant())).rejects.toThrow('KV PUT failed: 500 Internal Error');
  });
});
