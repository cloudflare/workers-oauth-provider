import { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
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
  transitionOwnerId,
  type OAuthStorageConnection,
  type StorageGrant,
} from '../../../src/storage';
import {
  durableObjectSqliteStorage,
  OAuthStorageObject,
  type OAuthStorageObjectNamespace,
} from '../../../src/storage/durable-object';
import { DIGEST_A, DIGEST_B, DIGEST_C, storedAccessToken, storedClient, storedGrant } from '../fixtures';

class Cursor<T> implements Iterable<T> {
  constructor(private readonly rows: T[]) {}
  one(): T {
    if (this.rows.length !== 1) throw new Error(`Expected one row, got ${this.rows.length}`);
    return this.rows[0]!;
  }
  toArray(): T[] {
    return this.rows;
  }
  [Symbol.iterator](): Iterator<T> {
    return this.rows[Symbol.iterator]();
  }
}

class SqliteState {
  readonly database = new DatabaseSync(':memory:');
  readonly alarms: number[] = [];
  failTransactionExecAt: number | undefined;
  private transactionExecCount = 0;
  private inTransaction = false;

  readonly storage = {
    sql: {
      exec: <T = Record<string, unknown>>(query: string, ...bindings: unknown[]): Cursor<T> => {
        if (this.inTransaction) {
          this.transactionExecCount++;
          if (this.failTransactionExecAt === this.transactionExecCount) {
            this.failTransactionExecAt = undefined;
            throw new Error('injected SQLite effect failure');
          }
        }
        const rows = this.database.prepare(query).all(...bindings) as unknown as T[];
        return new Cursor(rows);
      },
    },
    transactionSync: <T>(callback: () => T): T => {
      this.database.exec('BEGIN IMMEDIATE');
      this.inTransaction = true;
      this.transactionExecCount = 0;
      try {
        const result = callback();
        this.database.exec('COMMIT');
        return result;
      } catch (error) {
        this.database.exec('ROLLBACK');
        throw error;
      } finally {
        this.inTransaction = false;
      }
    },
    setAlarm: async (scheduledTime: number | Date): Promise<void> => {
      this.alarms.push(typeof scheduledTime === 'number' ? scheduledTime : scheduledTime.getTime());
    },
  };

  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T> {
    return callback();
  }

  close(): void {
    this.database.close();
  }
}

class Namespace implements OAuthStorageObjectNamespace {
  readonly names: string[] = [];
  readonly states = new Map<string, SqliteState>();
  private readonly objects = new Map<string, OAuthStorageObject>();

  getByName(name: string) {
    this.names.push(name);
    let object = this.objects.get(name);
    if (!object) {
      const state = new SqliteState();
      this.states.set(name, state);
      object = new OAuthStorageObject(state);
      this.objects.set(name, object);
    }
    return { execute: (command: Parameters<OAuthStorageObject['execute']>[0]) => object!.execute(command) };
  }

  close(): void {
    for (const state of this.states.values()) state.close();
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

describe('Durable Object SQLite adapter against real SQLite statements', () => {
  let namespace: Namespace;
  let now: number;
  let connection: OAuthStorageConnection;

  beforeEach(async () => {
    namespace = new Namespace();
    now = 100;
    const provider = durableObjectSqliteStorage<{ OBJECTS: OAuthStorageObjectNamespace }>({
      binding: (env) => env.OBJECTS,
      now: () => now,
    });
    connection = await provider.open(
      createOAuthStorageOpenContext({
        provider,
        env: { OBJECTS: namespace },
        operationId: 'do-test',
        kind: 'request',
      })
    );
  });

  afterEach(() => namespace.close());

  it('routes every namespace operation to one root and composes registered issue with client state', async () => {
    await connection.clients.create(createClientInput(storedClient(0)));
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
    expect(new Set(namespace.names)).toEqual(new Set(['oauth-do:v1:default:root']));
  });

  it('rolls back composite issue failures and supports external client provenance', async () => {
    // Initialize the root before arming transaction fault injection.
    expect(await connection.clients.get('none')).toBeNull();
    const state = namespace.states.get('oauth-do:v1:default:root')!;
    const externalPlan = issueGrantInput({
      client: { kind: 'external', clientId: 'https://client.example/meta' },
      grant: createStoredGrant(
        { ...storedGrant().value, clientId: 'https://client.example/meta' },
        { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
      ),
      accessToken: storedAccessToken(0, {
        grant: {
          ...storedAccessToken().value.grant!,
          clientId: 'https://client.example/meta',
        },
      }),
    });
    state.failTransactionExecAt = 2;
    await expect(connection.grants.issue(externalPlan)).rejects.toMatchObject({ code: 'internal' });
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' })).toBeNull();
    expect(await connection.grants.issue(externalPlan)).toEqual({ status: 'created' });
    await connection.maintenance.purge({
      now: 100,
      limit: 100,
      purgeExpiredGrants: false,
      purgeOrphanedGrants: true,
      purgeOrphanedTokens: false,
    });
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' })).not.toBeNull();
  });

  it('serializes contenders, persists fences, rejects stale commits, and rolls back commit faults', async () => {
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
    const commit = commitGrantTransitionInput({
      lease: first.lease,
      now: 110,
      grant: nextGrant,
      accessToken: storedAccessToken(0),
    });
    const state = namespace.states.get('oauth-do:v1:default:root')!;
    state.failTransactionExecAt = 2;
    await expect(connection.grants.commitTransition(commit)).rejects.toMatchObject({ code: 'internal' });
    expect((await connection.grants.get(first.lease.grant))?.metadata.revision).toBe(0);
    expect(await connection.grants.commitTransition(commit)).toEqual({ status: 'committed' });

    now = 200;
    const second = await connection.grants.beginTransition(
      await beginGrantTransitionInput({
        namespace: 'default',
        grant: first.lease.grant,
        kind: 'refresh_token',
        credentialId: DIGEST_C,
        ownerId: transitionOwnerId('owner-new'),
        leaseTtlSeconds: 30,
        now,
      })
    );
    expect(second.status).toBe('acquired');
    if (second.status !== 'acquired') throw new Error('expected second lease');
    expect(second.lease.fence).toBeGreaterThan(first.lease.fence);
    expect(await connection.grants.commitTransition(commit)).toEqual({ status: 'lease_lost' });
  });

  it('executes token, consent, replay, cascade, maintenance, and alarm paths', async () => {
    await connection.clients.create(createClientInput(storedClient(0)));
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
        grant: storedGrant(0),
      })
    );
    expect(
      await connection.accessTokens.createForGrant(
        issueAccessTokenInput({
          grant: { userId: 'user-1', grantId: 'grant-1' },
          expectedGrantRevision: 0,
          token: storedAccessToken(0),
        })
      )
    ).toEqual({ status: 'created' });
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
    expect(await connection.clients.deleteWithGrants({ clientId: 'client-1' })).toEqual({
      status: 'deleted',
      deletedGrants: 1,
      deletedAccessTokens: 1,
    });
    const state = namespace.states.get('oauth-do:v1:default:root')!;
    expect(state.alarms.length).toBeGreaterThan(0);
    await new OAuthStorageObject(state).alarm();
    expect(
      await connection.maintenance.purge({
        now: 400,
        limit: 100,
        purgeExpiredGrants: true,
        purgeOrphanedGrants: true,
        purgeOrphanedTokens: true,
      })
    ).toMatchObject({ done: true });
  });

  it('isolates namespaces and rejects operations after close', async () => {
    const otherProvider = durableObjectSqliteStorage<{ OBJECTS: OAuthStorageObjectNamespace }>({
      binding: (env) => env.OBJECTS,
      namespace: 'other',
      now: () => now,
    });
    const other = await otherProvider.open(
      createOAuthStorageOpenContext({
        provider: otherProvider,
        env: { OBJECTS: namespace },
        operationId: 'other',
        kind: 'request',
      })
    );
    await connection.clients.create(createClientInput(storedClient(0)));
    expect(await other.clients.get('client-1')).toBeNull();
    await connection.close();
    await expect(connection.clients.get('client-1')).rejects.toMatchObject({ code: 'unavailable' });
    await other.close();
  });
});
