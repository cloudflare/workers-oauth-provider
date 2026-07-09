import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  beginGrantTransitionInput,
  commitGrantTransitionInput,
  createClientInput,
  createOAuthStorageOpenContext,
  createStoredGrant,
  issueGrantInput,
  transitionOwnerId,
  type OAuthStorageConnection,
  type StorageGrant,
} from '../../../src/storage';
import { redisStorage } from '../../../src/storage/redis';
import { DIGEST_A, DIGEST_C, storedAccessToken, storedClient, storedGrant } from '../fixtures';
import { RespRedisClient } from './resp-client';

const enabled = process.env.RUN_REDIS_INTEGRATION === '1';
const host = process.env.REDIS_HOST ?? '127.0.0.1';
const port = Number(process.env.REDIS_PORT ?? 56379);
const suite = enabled ? describe : describe.skip;

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

suite('Redis adapter against a real Redis server', () => {
  let client: RespRedisClient;
  let now: number;
  let connection: OAuthStorageConnection;

  beforeAll(async () => {
    client = await RespRedisClient.connect(host, port);
    await client.flush();
    now = 100;
    const provider = redisStorage<{ REDIS: RespRedisClient }>({
      client: (env) => env.REDIS,
      now: () => now,
      randomId: () => crypto.randomUUID(),
    });
    connection = await provider.open(
      createOAuthStorageOpenContext({
        provider,
        env: { REDIS: client },
        operationId: 'redis-integration',
        kind: 'request',
      })
    );
  });

  afterAll(async () => {
    await connection?.close();
  });

  it('executes the real CAS script for composite mutations', async () => {
    expect(await connection.clients.create(createClientInput(storedClient(0)))).toEqual({ status: 'created' });
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
          grant: storedGrant(0),
          accessToken: storedAccessToken(0),
        })
      )
    ).toEqual({ status: 'created' });
    expect((await connection.clients.list()).items).toHaveLength(1);
    expect((await connection.grants.listByUser({ userId: 'user-1' })).items).toHaveLength(1);
    expect(
      (await connection.accessTokens.listByGrant({ grant: { userId: 'user-1', grantId: 'grant-1' } })).items
    ).toHaveLength(1);
  });

  it('allows one of 20 real Redis transition contenders and commits atomically', async () => {
    await connection.grants.revoke({ grant: { userId: 'user-1', grantId: 'grant-1' } });
    await connection.grants.issue(
      issueGrantInput({ client: { kind: 'external', clientId: 'client-1' }, grant: pendingGrant() })
    );
    const contenderConnections = await Promise.all(
      Array.from({ length: 20 }, async (_, index) => {
        const contenderClient = await RespRedisClient.connect(host, port);
        const contenderProvider = redisStorage<{ REDIS: RespRedisClient }>({
          client: (env) => env.REDIS,
          now: () => now,
          randomId: () => `lease-${index}`,
        });
        return contenderProvider.open(
          createOAuthStorageOpenContext({
            provider: contenderProvider,
            env: { REDIS: contenderClient },
            operationId: `redis-contender-${index}`,
            kind: 'request',
          })
        );
      })
    );
    const attempts = await Promise.all(
      contenderConnections.map(async (contender, index) =>
        contender.grants.beginTransition(
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
    const winner = acquired[0]!;
    if (winner.status !== 'acquired') throw new Error('expected lease');
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
          lease: winner.lease,
          now: 110,
          grant: nextGrant,
          accessToken: storedAccessToken(0),
        })
      )
    ).toEqual({ status: 'committed' });
    expect((await connection.grants.get(winner.lease.grant))?.metadata.revision).toBe(1);
    await Promise.all(contenderConnections.map((contender) => contender.close()));
  });
});
