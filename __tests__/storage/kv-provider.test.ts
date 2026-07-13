import { beforeEach, describe, expect, it } from 'vitest';
import {
  beginGrantTransitionInput,
  commitGrantTransitionInput,
  createClientInput,
  createOAuthStorageOpenContext,
  createStoredClient,
  createStoredGrant,
  issueAccessTokenInput,
  issueGrantInput,
  replaceClientInput,
  transitionOwnerId,
  type OAuthStorageConnection,
  type StorageGrant,
} from '../../src/storage';
import { WORKERS_KV_STORAGE_CAPABILITIES, workersKvStorage } from '../../src/storage/kv';
import { DIGEST_A, DIGEST_C, storedAccessToken, storedClient, storedGrant } from './fixtures';
import { MockKvNamespace } from './helpers/mock-kv';

interface TestEnv {
  readonly OAUTH_KV: KVNamespace;
}

function pendingGrant(id = 'grant-1', userId = 'user-1') {
  const value: StorageGrant = {
    ...storedGrant().value,
    id,
    userId,
    expiresAt: undefined,
    refreshTokenId: undefined,
    authCodeId: DIGEST_A,
    authCodeWrappedKey: 'wrapped-code-key',
  };
  return createStoredGrant(value, {
    schemaVersion: 1,
    revision: 0,
    createdAt: value.createdAt,
    expiresAt: value.createdAt + 600,
  });
}

describe('Workers KV storage provider', () => {
  let kv: MockKvNamespace;
  let connection: OAuthStorageConnection;

  beforeEach(async () => {
    kv = new MockKvNamespace();
    const provider = workersKvStorage<TestEnv>({
      binding: (env) => env.OAUTH_KV,
      now: () => kv.now,
    });
    const context = createOAuthStorageOpenContext({
      provider,
      env: { OAUTH_KV: kv.asNamespace() },
      operationId: 'test-request',
      kind: 'request',
    });
    connection = await provider.open(context);
  });

  it('validates provider configuration and the complete KV binding surface', async () => {
    expect(() => workersKvStorage(undefined as never)).toThrow(TypeError);
    expect(() => workersKvStorage({ binding: (env: TestEnv) => env.OAUTH_KV, now: 123 as never })).toThrow(TypeError);

    const missingDelete = workersKvStorage<TestEnv>({
      binding: () => ({ get() {}, put() {}, list() {} }) as never,
    });
    expect(() =>
      missingDelete.open(
        createOAuthStorageOpenContext({
          provider: missingDelete,
          env: { OAUTH_KV: kv.asNamespace() },
          operationId: 'bad-binding',
          kind: 'request',
        })
      )
    ).toThrowError(expect.objectContaining({ code: 'invalid_configuration', operation: 'storage.open' }));

    const throwing = workersKvStorage<TestEnv>({
      binding: () => {
        throw new Error('secret binding failure');
      },
    });
    expect(() =>
      throwing.open(
        createOAuthStorageOpenContext({
          provider: throwing,
          env: { OAUTH_KV: kv.asNamespace() },
          operationId: 'throwing-binding',
          kind: 'request',
        })
      )
    ).toThrowError(expect.objectContaining({ code: 'invalid_configuration', operation: 'storage.open' }));
  });

  it('advertises only legacy-compatible eventual and best-effort guarantees', () => {
    expect(WORKERS_KV_STORAGE_CAPABILITIES).toMatchObject({
      consistency: { readAfterWrite: 'eventual' },
      transitions: { authorizationCode: 'best_effort', refreshToken: 'best_effort' },
      replayReservation: 'best_effort',
      revocation: { accessToken: 'best_effort', grantCascade: 'best_effort', clientCascade: 'best_effort' },
      expiration: { cleanup: 'native', minimumTtlSeconds: 60 },
    });
    expect(Object.isFrozen(WORKERS_KV_STORAGE_CAPABILITIES)).toBe(true);
  });

  it('creates, reads, replaces, and lists clients using exact legacy JSON and keys', async () => {
    const expiringClient = createStoredClient(storedClient().value, {
      schemaVersion: 1,
      revision: 0,
      createdAt: 100,
      expiresAt: 1000,
    });
    expect(await connection.clients.create(createClientInput(expiringClient))).toEqual({ status: 'created' });
    expect(kv.writes[0]).toEqual({
      key: 'client:client-1',
      value: JSON.stringify(expiringClient.value),
      options: { expirationTtl: 900 },
    });
    expect(await connection.clients.create(createClientInput(expiringClient))).toEqual({ status: 'conflict' });
    expect((await connection.clients.get('client-1'))?.value).toEqual(expiringClient.value);

    const replacement = createStoredClient(
      { ...storedClient().value, clientName: 'Updated' },
      { schemaVersion: 1, revision: 1, createdAt: 100, expiresAt: 1100 }
    );
    expect(await connection.clients.replace(replaceClientInput('client-1', 0, replacement))).toEqual({
      status: 'updated',
    });
    expect(kv.writes[kv.writes.length - 1]?.options).toEqual({ expirationTtl: 1000 });
    expect((await connection.clients.list()).items.map((client) => client.value.clientName)).toEqual(['Updated']);
  });

  it('uses a collision-safe prefix only outside the default namespace', async () => {
    const provider = workersKvStorage<TestEnv>({
      binding: (env) => env.OAUTH_KV,
      namespace: 'tenant:one',
      now: () => kv.now,
    });
    const namespaced = await provider.open(
      createOAuthStorageOpenContext({
        provider,
        env: { OAUTH_KV: kv.asNamespace() },
        operationId: 'tenant-request',
        kind: 'request',
      })
    );
    await namespaced.clients.create(createClientInput(storedClient()));
    expect(kv.writes[0].key).toBe('oauth:tenant%3Aone:client:client-1');
  });

  it('issues a pending authorization grant with the exact legacy TTL', async () => {
    const grant = pendingGrant();
    const result = await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'external', clientId: 'client-1' },
        grant,
      })
    );

    expect(result).toEqual({ status: 'created' });
    expect(kv.writes[0]).toEqual({
      key: 'grant:user-1:grant-1',
      value: JSON.stringify(grant.value),
      options: { expirationTtl: 600 },
    });
    expect((await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' }))?.value).toEqual(grant.value);
  });

  it('issues a grant and access token in legacy write order and reports conflicts', async () => {
    const grant = storedGrant(0);
    const token = storedAccessToken(0);
    const plan = issueGrantInput({
      client: { kind: 'external', clientId: 'client-1' },
      grant,
      accessToken: token,
    });

    expect(await connection.grants.issue(plan)).toEqual({ status: 'created' });
    expect(kv.writes.map((write) => write.key)).toEqual([
      'grant:user-1:grant-1',
      `token:user-1:grant-1:${token.value.id}`,
    ]);
    expect(kv.writes[0].options).toEqual({ expiration: 500 });
    expect(kv.writes[1].options).toEqual({ expirationTtl: 190 });
    expect(await connection.grants.issue(plan)).toEqual({ status: 'conflict' });
  });

  it('documents partial grant state when a best-effort initial token write fails', async () => {
    kv.failPutAt = { attempt: 2, error: new Error('second write failed') };
    const grant = storedGrant(0);
    const token = storedAccessToken(0);

    await expect(
      connection.grants.issue(
        issueGrantInput({
          client: { kind: 'external', clientId: 'client-1' },
          grant,
          accessToken: token,
        })
      )
    ).rejects.toMatchObject({ code: 'internal', operation: 'grants.issue' });
    expect(kv.entries.has('grant:user-1:grant-1')).toBe(true);
    expect(kv.entries.has(`token:user-1:grant-1:${token.value.id}`)).toBe(false);
    expect(WORKERS_KV_STORAGE_CAPABILITIES.issuance.grantWithAccessToken).toBe('best_effort');
  });

  it('does not fail successful issuance when best-effort replacement cleanup fails', async () => {
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'external', clientId: 'client-1' },
        grant: storedGrant(0, { id: 'old-grant' }),
      })
    );
    kv.failNextDelete = new Error('cleanup failed');

    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'external', clientId: 'client-1' },
          grant: storedGrant(0, { id: 'new-grant' }),
          replaceExistingUserClientGrants: true,
        })
      )
    ).toEqual({ status: 'created' });
    expect(kv.entries.has('grant:user-1:new-grant')).toBe(true);
  });

  it('guards registered-client issuance with the observed legacy revision', async () => {
    await connection.clients.create(createClientInput(storedClient()));
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'client-1', expectedRevision: 1 },
          grant: storedGrant(0),
        })
      )
    ).toEqual({ status: 'client_conflict' });
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'missing', expectedRevision: 0 },
          grant: createStoredGrant(
            { ...storedGrant().value, clientId: 'missing' },
            { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
          ),
        })
      )
    ).toEqual({ status: 'client_not_found' });
  });

  it('supports guarded token-exchange issuance and token CRUD as best effort', async () => {
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'external', clientId: 'client-1' },
        grant: storedGrant(0),
      })
    );
    const token = storedAccessToken(0);
    const plan = issueAccessTokenInput({
      grant: { userId: 'user-1', grantId: 'grant-1' },
      expectedGrantRevision: 0,
      token,
    });

    expect(await connection.accessTokens.createForGrant(plan)).toEqual({ status: 'created' });
    expect(await connection.accessTokens.createForGrant(plan)).toEqual({ status: 'conflict' });
    expect(
      (
        await connection.accessTokens.get({
          userId: 'user-1',
          grantId: 'grant-1',
          tokenId: token.value.id,
        })
      )?.value
    ).toEqual(token.value);
    expect(
      (
        await connection.accessTokens.listByGrant({
          grant: { userId: 'user-1', grantId: 'grant-1' },
        })
      ).items
    ).toHaveLength(1);
    expect(
      await connection.accessTokens.delete({
        key: { userId: 'user-1', grantId: 'grant-1', tokenId: token.value.id },
      })
    ).toEqual({ status: 'deleted' });
    expect(
      await connection.accessTokens.delete({
        key: { userId: 'user-1', grantId: 'grant-1', tokenId: token.value.id },
      })
    ).toEqual({ status: 'not_found' });
  });

  it('performs the best-effort authorization-code transition and detects reuse', async () => {
    await connection.grants.issue(
      issueGrantInput({ client: { kind: 'external', clientId: 'client-1' }, grant: pendingGrant() })
    );
    const begin = await beginGrantTransitionInput({
      namespace: 'default',
      grant: { userId: 'user-1', grantId: 'grant-1' },
      kind: 'authorization_code',
      credentialId: DIGEST_A,
      ownerId: transitionOwnerId('owner-1'),
      leaseTtlSeconds: 60,
      now: 100,
    });
    const acquired = await connection.grants.beginTransition(begin);
    expect(acquired.status).toBe('acquired');
    if (acquired.status !== 'acquired') throw new Error('Expected acquired transition');

    const nextGrant = createStoredGrant(
      {
        ...pendingGrant().value,
        authCodeWrappedKey: undefined,
        refreshTokenId: DIGEST_C,
        refreshTokenWrappedKey: 'wrapped-refresh-key',
        expiresAt: 500,
      },
      { schemaVersion: 1, revision: 1, createdAt: 100, expiresAt: 500 }
    );
    const commit = commitGrantTransitionInput({
      lease: acquired.lease,
      now: 110,
      grant: nextGrant,
      accessToken: storedAccessToken(0),
    });
    expect(await connection.grants.commitTransition(commit)).toEqual({ status: 'committed' });
    expect(kv.writes.slice(-2).map((write) => write.key)).toEqual([
      'grant:user-1:grant-1',
      `token:user-1:grant-1:${storedAccessToken().value.id}`,
    ]);

    const replay = await connection.grants.beginTransition(
      await beginGrantTransitionInput({
        ...begin,
        namespace: 'default',
        ownerId: transitionOwnerId('owner-2'),
        now: 120,
      })
    );
    expect(replay).toEqual({ status: 'already_consumed' });
  });

  it('accepts current and previous refresh credentials only with matching wrapped keys', async () => {
    const grant = createStoredGrant(
      {
        ...storedGrant().value,
        refreshTokenId: DIGEST_A,
        refreshTokenWrappedKey: 'current-key',
        previousRefreshTokenId: DIGEST_C,
        previousRefreshTokenWrappedKey: 'previous-key',
      },
      { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
    );
    await connection.grants.issue(issueGrantInput({ client: { kind: 'external', clientId: 'client-1' }, grant }));

    for (const credentialId of [DIGEST_A, DIGEST_C]) {
      const result = await connection.grants.beginTransition(
        await beginGrantTransitionInput({
          namespace: 'default',
          grant: { userId: 'user-1', grantId: 'grant-1' },
          kind: 'refresh_token',
          credentialId,
          ownerId: transitionOwnerId(`owner-${credentialId[0]}`),
          leaseTtlSeconds: 60,
          now: 100,
        })
      );
      expect(result.status).toBe('acquired');
    }
  });

  it('does not pretend advisory KV transition leases exclude concurrent contenders', async () => {
    await connection.grants.issue(
      issueGrantInput({ client: { kind: 'external', clientId: 'client-1' }, grant: pendingGrant() })
    );
    const inputs = await Promise.all(
      ['owner-1', 'owner-2'].map((ownerId) =>
        beginGrantTransitionInput({
          namespace: 'default',
          grant: { userId: 'user-1', grantId: 'grant-1' },
          kind: 'authorization_code',
          credentialId: DIGEST_A,
          ownerId: transitionOwnerId(ownerId),
          leaseTtlSeconds: 60,
          now: 100,
        })
      )
    );

    const results = await Promise.all(inputs.map((input) => connection.grants.beginTransition(input)));
    expect(results.map((result) => result.status)).toEqual(['acquired', 'acquired']);
    expect(WORKERS_KV_STORAGE_CAPABILITIES.transitions.authorizationCode).toBe('best_effort');
  });

  it('fills list-by-client pages across nonmatching physical KV pages', async () => {
    kv.pageSizeCap = 1;
    for (const [id, clientId] of [
      ['grant-1', 'other'],
      ['grant-2', 'client-1'],
      ['grant-3', 'other'],
      ['grant-4', 'client-1'],
    ] as const) {
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'external', clientId },
          grant: createStoredGrant(
            { ...storedGrant().value, id, clientId },
            { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
          ),
        })
      );
    }

    const page = await connection.grants.listByClient({ clientId: 'client-1', page: { limit: 2 } });
    expect(page.items.map((grant) => grant.value.id)).toEqual(['grant-2', 'grant-4']);
    expect(page.cursor).toBeUndefined();
  });

  it('cascades orphan grants even when the client record is already missing', async () => {
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'external', clientId: 'client-1' },
        grant: storedGrant(0),
        accessToken: storedAccessToken(0),
      })
    );
    expect(await connection.clients.deleteWithGrants({ clientId: 'client-1' })).toEqual({
      status: 'deleted',
      deletedGrants: 1,
      deletedAccessTokens: 1,
    });
    expect([...kv.entries.keys()]).toEqual([]);
  });

  it('lists and deletes all client grants and tokens across KV pages', async () => {
    kv.pageSizeCap = 2;
    await connection.clients.create(createClientInput(storedClient()));
    for (let index = 1; index <= 3; index++) {
      const grant = storedGrant(0, { id: `grant-${index}` });
      const token = storedAccessToken(0, { grantId: `grant-${index}`, id: DIGEST_C });
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'external', clientId: 'client-1' },
          grant,
          accessToken: token,
        })
      );
    }

    expect(await connection.clients.deleteWithGrants({ clientId: 'client-1' })).toEqual({
      status: 'deleted',
      deletedGrants: 3,
      deletedAccessTokens: 3,
    });
    expect([...kv.entries.keys()]).toEqual([]);
  });

  it('uses a best-effort legacy replay marker with a physically safe TTL', async () => {
    expect(
      await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_A, expiresAt: 101 })
    ).toEqual({ status: 'reserved' });
    expect(kv.writes[0]).toEqual({
      key: `enterprise-jti:${DIGEST_A}`,
      value: '1',
      options: { expirationTtl: 65 },
    });
    expect(
      await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_A, expiresAt: 101 })
    ).toEqual({ status: 'exists' });
    await expect(
      connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_C, expiresAt: 100 })
    ).rejects.toMatchObject({ code: 'conflict', operation: 'replay.reserve' });
  });

  it('rejects unsupported consent operations before any KV I/O and honors close', async () => {
    const operations = [
      () => connection.consents.get({ userId: 'user-1', clientId: 'client-1' }),
      () => connection.consents.compareAndSwap({} as never),
      () => connection.consents.delete({ userId: 'user-1', clientId: 'client-1' }),
      () => connection.consents.listByUser({ userId: 'user-1' }),
    ];
    for (const operation of operations) {
      await expect(operation()).rejects.toMatchObject({ code: 'unsupported_operation' });
    }
    expect(kv.writes).toHaveLength(0);
    expect(kv.deletes).toHaveLength(0);

    await connection.close();
    for (const operation of operations) {
      await expect(operation()).rejects.toMatchObject({ code: 'unavailable' });
    }
  });

  it('purges multiple physical pages without invalidating continuation cursors', async () => {
    kv.pageSizeCap = 1;
    for (let index = 1; index <= 3; index++) {
      const grant = { ...storedGrant().value, id: `expired-${index}`, expiresAt: 90 };
      const token = { ...storedAccessToken().value, grantId: `expired-${index}`, id: DIGEST_C };
      kv.seed(`grant:user-1:expired-${index}`, grant);
      kv.seed(`token:user-1:expired-${index}:${DIGEST_C}`, token);
    }

    let done = false;
    let grantsPurged = 0;
    while (!done) {
      const result = await connection.maintenance.purge({
        now: 100,
        limit: 1,
        purgeOrphanedGrants: true,
        purgeExpiredGrants: true,
        purgeOrphanedTokens: true,
      });
      grantsPurged += result.grantsPurged;
      done = result.done;
    }
    expect(grantsPurged).toBe(3);
    expect([...kv.entries.keys()]).toEqual([]);
  });

  it('hides logically expired records even when their physical KV row remains', async () => {
    kv.now = 400;
    const expired = storedAccessToken().value;
    kv.seed(`token:user-1:grant-1:${expired.id}`, expired);
    expect(await connection.accessTokens.get({ userId: 'user-1', grantId: 'grant-1', tokenId: expired.id })).toBeNull();
  });

  it('normalizes and redacts KV errors', async () => {
    kv.failNextPut = new Error('KV PUT failed: 429 Too Many Requests: secret-key');
    await expect(connection.clients.create(createClientInput(storedClient()))).rejects.toMatchObject({
      code: 'rate_limited',
      retryable: true,
      operation: 'clients.create',
      message: 'OAuth storage operation failed (rate_limited)',
    });

    kv.failNextPut = new Error('backend leaked secret-key');
    await expect(connection.clients.create(createClientInput(storedClient()))).rejects.toMatchObject({
      code: 'internal',
      message: 'OAuth storage operation failed (internal)',
    });

    kv.failNextGet = new Error('KV GET failed: 429');
    await expect(connection.clients.get('client-1')).rejects.toMatchObject({ code: 'rate_limited' });
    kv.failNextList = new Error('KV LIST failed: 429');
    await expect(connection.clients.list()).rejects.toMatchObject({ code: 'rate_limited' });
    kv.seed(`token:user-1:grant-1:${DIGEST_A}`, storedAccessToken(0, { id: DIGEST_A }).value);
    kv.failNextDelete = new Error('KV DELETE failed: 429');
    await expect(
      connection.accessTokens.delete({ key: { userId: 'user-1', grantId: 'grant-1', tokenId: DIGEST_A } })
    ).rejects.toMatchObject({ code: 'rate_limited' });
  });

  it('rejects operations after close', async () => {
    await connection.close();
    await connection.close();
    await expect(connection.clients.get('client-1')).rejects.toMatchObject({
      code: 'unavailable',
      operation: 'clients.get',
    });
  });
});
