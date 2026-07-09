import { beforeEach, describe, expect, it } from 'vitest';
import { OAuthProvider } from '../../../src/oauth-provider';
import {
  beginGrantTransitionInput,
  commitGrantTransitionInput,
  compareAndSwapConsentInput,
  createClientInput,
  createOAuthStorageOpenContext,
  createStoredClient,
  createStoredConsent,
  createStoredGrant,
  issueAccessTokenInput,
  issueGrantInput,
  transitionOwnerId,
  type OAuthStorageConnection,
  type StorageGrant,
} from '../../../src/storage';
import {
  REDIS_NAMESPACE_CAS_SCRIPT,
  REDIS_STORAGE_CAPABILITIES,
  redisStorage,
  type RedisStorageClient,
} from '../../../src/storage/redis';
import { DIGEST_A, DIGEST_B, DIGEST_C, storedAccessToken, storedClient, storedGrant } from '../fixtures';

class RedisState {
  readonly values = new Map<string, string>();
  evaluations = 0;
  forcedConflicts = 0;
  failNextEval: Error | undefined;
  nextEvalResult: unknown | undefined;
}

class FakeRedisClient implements RedisStorageClient {
  closed = false;
  constructor(private readonly state: RedisState) {}
  async get(key: string): Promise<string | null> {
    return this.state.values.get(key) ?? null;
  }
  async eval(script: string, keys: readonly string[], args: readonly string[]): Promise<unknown> {
    this.state.evaluations++;
    expect(script).toBe(REDIS_NAMESPACE_CAS_SCRIPT);
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^\{oauth:/);
    if (this.state.failNextEval) {
      const error = this.state.failNextEval;
      this.state.failNextEval = undefined;
      throw error;
    }
    if (this.state.nextEvalResult !== undefined) {
      const result = this.state.nextEvalResult;
      this.state.nextEvalResult = undefined;
      return result;
    }
    if (this.state.forcedConflicts > 0) {
      this.state.forcedConflicts--;
      return 0;
    }
    const current = this.state.values.get(keys[0]!);
    const absentExpected = args[0] === '0';
    if ((absentExpected && current !== undefined) || (!absentExpected && current !== args[1])) return 0;
    this.state.values.set(keys[0]!, args[2]!);
    return 1;
  }
  close(): void {
    this.closed = true;
  }
}

function pendingGrant(): ReturnType<typeof createStoredGrant> {
  const value: StorageGrant = {
    ...storedGrant().value,
    expiresAt: undefined,
    refreshTokenId: undefined,
    authCodeId: DIGEST_A,
    authCodeWrappedKey: 'wrapped-code',
  };
  return createStoredGrant(value, {
    schemaVersion: 1,
    revision: 0,
    createdAt: 100,
    expiresAt: 700,
  });
}

describe('Redis storage adapter', () => {
  let state: RedisState;
  let now: number;
  let connection: OAuthStorageConnection;

  beforeEach(async () => {
    state = new RedisState();
    now = 100;
    const provider = redisStorage<{ client: RedisStorageClient }>({
      client: (env) => env.client,
      now: () => now,
      randomId: () => crypto.randomUUID(),
    });
    connection = await provider.open(
      createOAuthStorageOpenContext({
        provider,
        env: { client: new FakeRedisClient(state) },
        operationId: 'redis-test',
        kind: 'request',
      })
    );
  });

  it('advertises a complete strict profile with one atomic namespace key', () => {
    expect(REDIS_STORAGE_CAPABILITIES.transitions).toEqual({
      authorizationCode: 'strong',
      refreshToken: 'strong',
    });
    const storage = redisStorage<{ client: RedisStorageClient }>({ client: (env) => env.client });
    expect(
      () =>
        new OAuthProvider({
          apiRoute: '/api/',
          apiHandler: { fetch: async () => new Response('api') },
          defaultHandler: { fetch: async () => new Response('default') },
          authorizeEndpoint: '/authorize',
          tokenEndpoint: '/token',
          storage,
          storageGuarantees: 'strict',
        })
    ).not.toThrow();
  });

  it('executes CRUD, replacement, cascades, consent, replay, pagination, and cleanup', async () => {
    await connection.clients.create(createClientInput(storedClient(0)));
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
        grant: storedGrant(0, { id: 'old-grant' }),
        accessToken: storedAccessToken(0, { grantId: 'old-grant' }),
      })
    );
    const replacement = createStoredGrant(
      { ...storedGrant().value, id: 'new-grant' },
      { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
    );
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
          grant: replacement,
          replaceExistingUserClientGrants: true,
        })
      )
    ).toEqual({ status: 'created' });
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'old-grant' })).toBeNull();
    expect((await connection.clients.list({ limit: 1 })).items).toHaveLength(1);
    expect((await connection.grants.listByUser({ userId: 'user-1' })).items).toHaveLength(1);

    const token = storedAccessToken(0, { grantId: 'new-grant' });
    expect(
      await connection.accessTokens.createForGrant(
        issueAccessTokenInput({
          grant: { userId: 'user-1', grantId: 'new-grant' },
          expectedGrantRevision: 0,
          token,
        })
      )
    ).toEqual({ status: 'created' });
    expect(
      (await connection.accessTokens.listByGrant({ grant: { userId: 'user-1', grantId: 'new-grant' } })).items
    ).toHaveLength(1);

    const consent = createStoredConsent(
      { userId: 'user-1', clientId: 'client-1', scope: ['read'], updatedAt: 100 },
      { schemaVersion: 1, revision: 0, createdAt: 100 }
    );
    expect(await connection.consents.compareAndSwap(compareAndSwapConsentInput({ consent }))).toEqual({
      status: 'created',
    });
    expect((await connection.consents.listByUser({ userId: 'user-1' })).items).toHaveLength(1);
    expect(
      await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_B, expiresAt: 300 })
    ).toEqual({ status: 'reserved' });
    expect(
      await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_B, expiresAt: 300 })
    ).toEqual({ status: 'exists' });

    expect(await connection.clients.deleteWithGrants({ clientId: 'client-1' })).toEqual({
      status: 'deleted',
      deletedGrants: 1,
      deletedAccessTokens: 1,
    });
    now = 400;
    expect(
      await connection.maintenance.purge({
        now,
        limit: 100,
        purgeExpiredGrants: true,
        purgeOrphanedGrants: true,
        purgeOrphanedTokens: true,
      })
    ).toMatchObject({ done: true });
  });

  it('serializes 20 transition contenders, persists fences, and rejects stale commits', async () => {
    await connection.grants.issue(
      issueGrantInput({ client: { kind: 'external', clientId: 'client-1' }, grant: pendingGrant() })
    );
    const attempts = await Promise.all(
      Array.from({ length: 20 }, async (_, index) =>
        connection.grants.beginTransition(
          await beginGrantTransitionInput({
            namespace: 'default',
            grant: { userId: 'user-1', grantId: 'grant-1' },
            kind: 'authorization_code',
            credentialId: DIGEST_A,
            ownerId: transitionOwnerId(`owner-${index}`),
            leaseTtlSeconds: 30,
            now,
          })
        )
      )
    );
    const acquired = attempts.filter((result) => result.status === 'acquired');
    expect(acquired).toHaveLength(1);
    expect(attempts.filter((result) => result.status === 'busy')).toHaveLength(19);
    const first = acquired[0]!;
    if (first.status !== 'acquired') throw new Error('expected lease');
    const nextGrant = createStoredGrant(
      {
        ...pendingGrant().value,
        authCodeWrappedKey: undefined,
        refreshTokenId: DIGEST_C,
        refreshTokenWrappedKey: 'wrapped-refresh',
        expiresAt: 500,
      },
      { schemaVersion: 1, revision: 1, createdAt: 100, expiresAt: 500 }
    );
    expect(
      await connection.grants.commitTransition(
        commitGrantTransitionInput({
          lease: first.lease,
          now: 110,
          grant: nextGrant,
          accessToken: storedAccessToken(0),
        })
      )
    ).toEqual({ status: 'committed' });
    now = 200;
    const second = await connection.grants.beginTransition(
      await beginGrantTransitionInput({
        namespace: 'default',
        grant: first.lease.grant,
        kind: 'refresh_token',
        credentialId: DIGEST_C,
        ownerId: transitionOwnerId('new-owner'),
        leaseTtlSeconds: 30,
        now,
      })
    );
    expect(second.status).toBe('acquired');
    if (second.status !== 'acquired') throw new Error('expected second lease');
    expect(second.lease.fence).toBeGreaterThan(first.lease.fence);
  });

  it('retries CAS conflicts without partial state and normalizes script failures', async () => {
    state.forcedConflicts = 3;
    expect(await connection.clients.create(createClientInput(storedClient(0)))).toEqual({ status: 'created' });
    expect(state.evaluations).toBe(4);
    state.failNextEval = new Error('secret redis failure');
    await expect(
      connection.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
          grant: storedGrant(0),
        })
      )
    ).rejects.toMatchObject({ code: 'internal', message: 'OAuth storage operation failed (internal)' });
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' })).toBeNull();
  });

  it('reuses logically expired identifiers and replay reservations', async () => {
    const expiredClient = createStoredClient(storedClient().value, {
      schemaVersion: 1,
      revision: 0,
      createdAt: 50,
      expiresAt: 90,
    });
    expect(await connection.clients.create(createClientInput(expiredClient))).toEqual({ status: 'created' });
    expect(await connection.clients.create(createClientInput(storedClient(0)))).toEqual({ status: 'created' });

    expect(
      await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_A, expiresAt: 101 })
    ).toEqual({ status: 'reserved' });
    now = 102;
    expect(
      await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_A, expiresAt: 200 })
    ).toEqual({ status: 'reserved' });
  });

  it('bounds replay cleanup and rejects malformed persisted state and EVAL results', async () => {
    for (const [index, digest] of [DIGEST_A, DIGEST_B, DIGEST_C].entries()) {
      await connection.replay.reserve({
        reservationNamespace: 'cleanup',
        keyHash: digest,
        expiresAt: 101 + index,
      });
    }
    now = 200;
    expect(
      await connection.maintenance.purge({
        now,
        limit: 1,
        purgeExpiredGrants: false,
        purgeOrphanedGrants: false,
        purgeOrphanedTokens: false,
      })
    ).toMatchObject({ done: false });
    expect(
      await connection.maintenance.purge({
        now,
        limit: 1,
        purgeExpiredGrants: false,
        purgeOrphanedGrants: false,
        purgeOrphanedTokens: false,
      })
    ).toMatchObject({ done: false });
    expect(
      await connection.maintenance.purge({
        now,
        limit: 1,
        purgeExpiredGrants: false,
        purgeOrphanedGrants: false,
        purgeOrphanedTokens: false,
      })
    ).toMatchObject({ done: true });

    state.nextEvalResult = 2;
    await expect(connection.clients.create(createClientInput(storedClient(0)))).rejects.toMatchObject({
      code: 'internal',
    });

    const physicalKey = [...state.values.keys()][0]!;
    state.values.set(physicalKey, JSON.stringify({ schemaVersion: 1, generation: 0, clients: null }));
    await expect(connection.clients.get('client-1')).rejects.toMatchObject({
      code: 'schema_mismatch',
      operation: 'storage.decode',
    });
    state.values.set(physicalKey, '{not-json');
    await expect(connection.clients.get('client-1')).rejects.toMatchObject({ code: 'schema_mismatch' });
  });

  it('isolates namespace keys, validates schema versions, and rejects after close', async () => {
    const otherProvider = redisStorage<{ client: RedisStorageClient }>({
      client: (env) => env.client,
      namespace: 'other',
      now: () => now,
    });
    const other = await otherProvider.open(
      createOAuthStorageOpenContext({
        provider: otherProvider,
        env: { client: new FakeRedisClient(state) },
        operationId: 'other',
        kind: 'request',
      })
    );
    await connection.clients.create(createClientInput(storedClient(0)));
    expect(await other.clients.get('client-1')).toBeNull();
    const otherKey = [...state.values.keys()].find((key) => key.includes('other'));
    expect(otherKey).toBeUndefined();
    await other.clients.create(createClientInput(storedClient(0)));
    expect([...state.values.keys()]).toHaveLength(2);
    await connection.close();
    await expect(connection.clients.get('client-1')).rejects.toMatchObject({ code: 'unavailable' });
    await other.close();
  });
});
