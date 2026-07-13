import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  beginGrantTransitionInput,
  commitGrantTransitionInput,
  compareAndSwapConsentInput,
  createClientInput,
  createOAuthStorageOpenContext,
  createStoredConsent,
  createStoredGrant,
  issueAccessTokenInput,
  issueGrantInput,
  replaceClientInput,
  transitionOwnerId,
  type OAuthStorageConnection,
  type StorageGrant,
} from '../../../src/storage';
import { migratePostgresStorage, postgresStorage, type PostgresClientFactory } from '../../../src/storage/postgres';
import { DIGEST_A, DIGEST_B, DIGEST_C, storedAccessToken, storedClient, storedGrant } from '../fixtures';
import { PostgresWireClient } from './wire-client';

const enabled = process.env.RUN_POSTGRES_INTEGRATION === '1';
const host = process.env.POSTGRES_HOST ?? '127.0.0.1';
const port = Number(process.env.POSTGRES_PORT ?? 55432);

interface Env {
  readonly factory: PostgresClientFactory<Env>;
}

function pendingGrant(id = 'grant-1'): ReturnType<typeof createStoredGrant> {
  const value: StorageGrant = {
    ...storedGrant().value,
    id,
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

async function connect(): Promise<PostgresWireClient> {
  return PostgresWireClient.connect({ host, port });
}

const suite = enabled ? describe : describe.skip;
suite('PostgreSQL adapter against a real server', () => {
  let admin: PostgresWireClient;
  let now: number;
  let factory: PostgresClientFactory<Env>;
  let provider: ReturnType<typeof postgresStorage<Env>>;

  beforeAll(async () => {
    admin = await connect();
    await admin.query(
      'DROP TABLE IF EXISTS oauth_access_tokens,oauth_consents,oauth_replay_reservations,oauth_grants,oauth_clients,oauth_storage_schema CASCADE'
    );
    const concurrentMigrator = await connect();
    await Promise.all([migratePostgresStorage(admin), migratePostgresStorage(concurrentMigrator)]);
    concurrentMigrator.release();
    now = 100;
    factory = { acquire: () => connect() };
    provider = postgresStorage<Env>({ clientFactory: factory, now: () => now, randomId: () => crypto.randomUUID() });
  });

  afterAll(() => admin?.release());

  async function open(namespace = 'default'): Promise<OAuthStorageConnection> {
    const selected =
      namespace === 'default'
        ? provider
        : postgresStorage<Env>({
            clientFactory: factory,
            namespace,
            now: () => now,
            randomId: () => crypto.randomUUID(),
          });
    return selected.open(
      createOAuthStorageOpenContext({
        provider: selected,
        env: { factory },
        operationId: `postgres-${namespace}`,
        kind: 'request',
      })
    );
  }

  it('tracks migration versions, reruns idempotently, and rejects newer schemas', async () => {
    await migratePostgresStorage(admin);
    expect(
      (await admin.query<{ version: number }>('SELECT version FROM oauth_storage_schema WHERE id=1')).rows[0]?.version
    ).toBe(1);
    await admin.query('UPDATE oauth_storage_schema SET version=99 WHERE id=1');
    await expect(migratePostgresStorage(admin)).rejects.toMatchObject({ code: 'schema_mismatch' });
    await admin.query('UPDATE oauth_storage_schema SET version=1 WHERE id=1');
  });

  it('executes CRUD, registered/external issue, replacement, pagination, consent, and replay', async () => {
    const connection = await open();
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
    const replacement = createStoredGrant(
      { ...storedGrant().value, id: 'replacement' },
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
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' })).toBeNull();

    const external = createStoredGrant(
      { ...storedGrant().value, id: 'external', clientId: 'https://client.example/meta' },
      { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
    );
    expect(
      await connection.grants.issue(
        issueGrantInput({ client: { kind: 'external', clientId: external.value.clientId }, grant: external })
      )
    ).toEqual({ status: 'created' });
    expect((await connection.grants.listByClient({ clientId: external.value.clientId })).items).toHaveLength(1);

    const consent = createStoredConsent(
      { userId: 'user-1', clientId: 'client-1', scope: ['read'], updatedAt: 100 },
      { schemaVersion: 1, revision: 0, createdAt: 100 }
    );
    expect(await connection.consents.compareAndSwap(compareAndSwapConsentInput({ consent }))).toEqual({
      status: 'created',
    });
    expect(
      await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_B, expiresAt: 300 })
    ).toEqual({ status: 'reserved' });
    expect(
      await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_B, expiresAt: 300 })
    ).toEqual({ status: 'exists' });
    await connection.close();
  });

  it('executes client, token, consent, cascade, and maintenance operations', async () => {
    const connection = await open('crud');
    await connection.clients.create(createClientInput(storedClient(0)));
    expect(await connection.clients.replace(replaceClientInput('client-1', 0, storedClient(1)))).toEqual({
      status: 'updated',
    });
    expect((await connection.clients.list()).items).toHaveLength(1);
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: 'client-1', expectedRevision: 1 },
        grant: storedGrant(0),
      })
    );
    const token = storedAccessToken(0);
    expect(
      await connection.accessTokens.createForGrant(
        issueAccessTokenInput({
          grant: { userId: 'user-1', grantId: 'grant-1' },
          expectedGrantRevision: 0,
          token,
        })
      )
    ).toEqual({ status: 'created' });
    expect(
      await connection.accessTokens.get({ userId: 'user-1', grantId: 'grant-1', tokenId: token.value.id })
    ).not.toBeNull();
    expect(
      (await connection.accessTokens.listByGrant({ grant: { userId: 'user-1', grantId: 'grant-1' } })).items
    ).toHaveLength(1);
    expect(
      await connection.accessTokens.delete({
        key: { userId: 'user-1', grantId: 'grant-1', tokenId: token.value.id },
      })
    ).toEqual({ status: 'deleted' });

    const consent = createStoredConsent(
      { userId: 'user-1', clientId: 'client-1', scope: ['read'], updatedAt: 100 },
      { schemaVersion: 1, revision: 0, createdAt: 100 }
    );
    await connection.consents.compareAndSwap(compareAndSwapConsentInput({ consent }));
    expect(await connection.consents.get({ userId: 'user-1', clientId: 'client-1' })).not.toBeNull();
    expect((await connection.consents.listByUser({ userId: 'user-1' })).items).toHaveLength(1);
    expect(await connection.consents.delete({ userId: 'user-1', clientId: 'client-1' })).toEqual({
      status: 'deleted',
    });
    expect(await connection.grants.revoke({ grant: { userId: 'user-1', grantId: 'grant-1' } })).toEqual({
      status: 'revoked',
      deletedAccessTokens: 0,
    });

    const expired = createStoredGrant(
      { ...storedGrant().value, id: 'expired', clientId: 'external', createdAt: 50, expiresAt: 90 },
      { schemaVersion: 1, revision: 0, createdAt: 50, expiresAt: 90 }
    );
    await connection.grants.issue(
      issueGrantInput({ client: { kind: 'external', clientId: 'external' }, grant: expired })
    );
    expect(
      await connection.maintenance.purge({
        now: 100,
        limit: 10,
        purgeExpiredGrants: true,
        purgeOrphanedGrants: true,
        purgeOrphanedTokens: true,
      })
    ).toMatchObject({ grantsPurged: 1, done: true });
    await connection.close();
  });

  it('paginates composite grant and consent keys without skipping duplicates', async () => {
    const connection = await open('pagination');
    for (const userId of ['user-a', 'user-b']) {
      const grant = createStoredGrant(
        { ...storedGrant().value, id: 'same-grant-id', userId, clientId: 'external-client' },
        { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
      );
      await connection.grants.issue(
        issueGrantInput({ client: { kind: 'external', clientId: 'external-client' }, grant })
      );
      const consent = createStoredConsent(
        { userId: 'consent-user', clientId: `client-${userId}`, referenceId: 'same', scope: ['read'], updatedAt: 100 },
        { schemaVersion: 1, revision: 0, createdAt: 100 }
      );
      await connection.consents.compareAndSwap(compareAndSwapConsentInput({ consent }));
    }
    const firstGrant = await connection.grants.listByClient({ clientId: 'external-client', page: { limit: 1 } });
    const secondGrant = await connection.grants.listByClient({
      clientId: 'external-client',
      page: { limit: 1, cursor: firstGrant.cursor },
    });
    expect([...firstGrant.items, ...secondGrant.items]).toHaveLength(2);
    const firstConsent = await connection.consents.listByUser({ userId: 'consent-user', page: { limit: 1 } });
    const secondConsent = await connection.consents.listByUser({
      userId: 'consent-user',
      page: { limit: 1, cursor: firstConsent.cursor },
    });
    expect([...firstConsent.items, ...secondConsent.items]).toHaveLength(2);
    await connection.close();
  });

  it('serializes transition contenders and rolls back a failed commit on the same session', async () => {
    const seed = await open();
    await seed.grants.issue(
      issueGrantInput({
        client: { kind: 'external', clientId: 'client-1' },
        grant: pendingGrant('transition'),
      })
    );
    await seed.close();
    const contenders = await Promise.all(Array.from({ length: 20 }, () => open()));
    const results = await Promise.all(
      contenders.map(async (connection, index) =>
        connection.grants.beginTransition(
          await beginGrantTransitionInput({
            namespace: 'default',
            grant: { userId: 'user-1', grantId: 'transition' },
            kind: 'authorization_code',
            credentialId: DIGEST_A,
            ownerId: transitionOwnerId(`owner-${index}`),
            leaseTtlSeconds: 30,
            now,
          })
        )
      )
    );
    expect(results.filter((result) => result.status === 'acquired')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'busy')).toHaveLength(19);
    const winnerIndex = results.findIndex((result) => result.status === 'acquired');
    const acquired = results[winnerIndex]!;
    if (acquired.status !== 'acquired') throw new Error('expected acquired');
    const nextGrant = createStoredGrant(
      {
        ...pendingGrant('transition').value,
        authCodeWrappedKey: undefined,
        refreshTokenId: DIGEST_C,
        refreshTokenWrappedKey: 'wrapped-refresh',
        expiresAt: 500,
      },
      { schemaVersion: 1, revision: 1, createdAt: 100, expiresAt: 500 }
    );
    const commit = commitGrantTransitionInput({
      lease: acquired.lease,
      now: 110,
      grant: nextGrant,
      accessToken: storedAccessToken(0, { grantId: 'transition' }),
    });

    await admin.query(
      `CREATE OR REPLACE FUNCTION oauth_fail_token() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected token failure'; END $$`
    );
    await admin.query(
      `CREATE TRIGGER oauth_fail_token BEFORE INSERT ON oauth_access_tokens FOR EACH ROW EXECUTE FUNCTION oauth_fail_token()`
    );
    await expect(contenders[winnerIndex]!.grants.commitTransition(commit)).rejects.toMatchObject({ code: 'internal' });
    await admin.query('DROP TRIGGER oauth_fail_token ON oauth_access_tokens');
    const verify = await open();
    expect((await verify.grants.get(acquired.lease.grant))?.metadata.revision).toBe(0);
    await verify.close();
    expect(await contenders[winnerIndex]!.grants.commitTransition(commit)).toEqual({ status: 'committed' });
    await Promise.all(contenders.map((connection) => connection.close()));
  });

  it('serializes registered issue against client deletion and leaves no grant after deletion wins', async () => {
    const setup = await open();
    await setup.clients.create(createClientInput(storedClient(0)));
    await setup.close();
    const issuer = await open();
    const deleter = await open();
    const grant = createStoredGrant(
      { ...storedGrant().value, id: 'race-grant' },
      { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
    );
    const [issued, deleted] = await Promise.all([
      issuer.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
          grant,
        })
      ),
      deleter.clients.deleteWithGrants({ clientId: 'client-1' }),
    ]);
    expect(['created', 'client_not_found']).toContain(issued.status);
    expect(['deleted', 'not_found']).toContain(deleted.status);
    const verify = await open();
    expect(await verify.clients.get('client-1')).toBeNull();
    expect(await verify.grants.get({ userId: 'user-1', grantId: 'race-grant' })).toBeNull();
    await Promise.all([issuer.close(), deleter.close(), verify.close()]);
  });
});
