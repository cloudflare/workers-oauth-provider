import { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
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
  credentialIdFromSha256,
  issueAccessTokenInput,
  issueGrantInput,
  transitionOwnerId,
  type OAuthStorageConnection,
  type StorageGrant,
} from '../../../src/storage';
import {
  durableObjectSqliteStorage,
  OAuthStorageObject,
  type DurableObjectStorageAggregate,
  type DurableObjectStorageCommand,
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
  alarm: number | null = null;
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
    getAlarm: async (): Promise<number | null> => this.alarm,
    setAlarm: async (scheduledTime: number | Date): Promise<void> => {
      this.alarm = typeof scheduledTime === 'number' ? scheduledTime : scheduledTime.getTime();
      this.alarms.push(this.alarm);
    },
    deleteAlarm: async (): Promise<void> => {
      this.alarm = null;
    },
  };

  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T> {
    return callback();
  }

  close(): void {
    this.database.close();
  }
}

function aggregateKey(aggregate: DurableObjectStorageAggregate, namespace = 'default'): string {
  return JSON.stringify([namespace, aggregate.kind, aggregate.key]);
}

class Namespace implements OAuthStorageObjectNamespace {
  readonly names: string[] = [];
  readonly states = new Map<string, SqliteState>();
  readonly namesByAggregate = new Map<string, string>();
  private readonly aggregatesByName = new Map<string, string>();
  private readonly objects = new Map<string, OAuthStorageObject>();

  getByName(name: string) {
    this.names.push(name);
    let object = this.objects.get(name);
    let state = this.states.get(name);
    if (!object || !state) {
      state = new SqliteState();
      object = new OAuthStorageObject(state);
      this.states.set(name, state);
      this.objects.set(name, object);
    }
    const selectedObject = object;
    const selectedState = state;
    return {
      execute: (command: DurableObjectStorageCommand) => {
        const key = aggregateKey(command.aggregate, command.namespace);
        const priorAggregate = this.aggregatesByName.get(name);
        if (priorAggregate !== undefined && priorAggregate !== key) throw new Error('routing collision');
        this.aggregatesByName.set(name, key);
        this.namesByAggregate.set(key, name);
        this.states.set(key, selectedState);
        return selectedObject.execute(command);
      },
    };
  }

  state(kind: DurableObjectStorageAggregate['kind'], key: string, namespace = 'default'): SqliteState {
    const state = this.states.get(aggregateKey({ kind, key }, namespace));
    if (!state) throw new Error(`Missing ${kind} aggregate`);
    return state;
  }

  close(): void {
    for (const [key, state] of this.states) {
      if (!key.startsWith('[')) state.close();
    }
  }
}

function pendingGrant(userId = 'user-1'): ReturnType<typeof createStoredGrant> {
  const value: StorageGrant = {
    ...storedGrant().value,
    userId,
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

function providerOptions(
  storage: ReturnType<typeof durableObjectSqliteStorage>
): ConstructorParameters<typeof OAuthProvider>[0] {
  return {
    apiRoute: '/api/',
    apiHandler: { fetch: async () => new Response('api') },
    defaultHandler: { fetch: async () => new Response('default') },
    authorizeEndpoint: '/authorize',
    tokenEndpoint: '/oauth/token',
    storage,
  };
}

describe('partitioned Durable Object SQLite adapter against real SQLite statements', () => {
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

  it('migrates keyed objects transactionally and rejects newer schema versions', async () => {
    expect(await connection.clients.get('initialize')).toBeNull();
    const state = namespace.state('client', 'initialize');
    state.storage.sql.exec('INSERT INTO schema_migrations(version) VALUES (99)');
    const newer = new OAuthStorageObject(state);
    await expect(
      newer.execute({
        namespace: 'default',
        aggregate: { kind: 'client', key: 'initialize' },
        operation: 'clients.get',
        clientId: 'initialize',
        now: 100,
      })
    ).rejects.toMatchObject({ code: 'schema_mismatch' });

    const failedState = new SqliteState();
    failedState.failTransactionExecAt = 3;
    const command: DurableObjectStorageCommand = {
      namespace: 'default',
      aggregate: { kind: 'client', key: 'x' },
      operation: 'clients.get',
      clientId: 'x',
      now: 100,
    };
    await expect(new OAuthStorageObject(failedState).execute(command)).rejects.toThrow(
      /injected SQLite effect failure/
    );
    failedState.failTransactionExecAt = undefined;
    expect(await new OAuthStorageObject(failedState).execute(command)).toBeNull();
    expect(failedState.database.prepare('SELECT version FROM schema_migrations ORDER BY version').all()).toEqual([
      { version: 1 },
      { version: 2 },
    ]);
    failedState.close();
  });

  it('advertises compatibility issuance and rejects the partitioned adapter in strict mode', () => {
    const storage = durableObjectSqliteStorage<{ OBJECTS: OAuthStorageObjectNamespace }>({
      binding: (env) => env.OBJECTS,
      now: () => now,
    });
    const provider = new OAuthProvider(providerOptions(storage));
    expect(provider.getStorageCompatibility().features['grant-issuance']).toMatchObject({
      status: 'compatibility',
      missingCapabilities: ['issuance.grantOnly'],
    });
    expect(() => new OAuthProvider({ ...providerOptions(storage), storageGuarantees: 'strict' })).toThrow(
      /grant-issuance/
    );
  });

  it('routes clients separately and co-locates each user aggregate', async () => {
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
    await connection.consents.compareAndSwap(
      compareAndSwapConsentInput({
        consent: createStoredConsent(
          { userId: 'user-1', clientId: 'client-1', scope: ['read'], updatedAt: 100 },
          { schemaVersion: 1, revision: 0, createdAt: 100 }
        ),
      })
    );
    const secondGrant = storedGrant(0, { id: 'grant-2', userId: 'user-2' });
    await connection.grants.issue(
      issueGrantInput({ client: { kind: 'external', clientId: 'client-1' }, grant: secondGrant })
    );

    expect((await connection.grants.listByUser({ userId: 'user-1' })).items).toHaveLength(1);
    expect((await connection.grants.listByUser({ userId: 'user-2' })).items).toHaveLength(1);
    const clientName = namespace.namesByAggregate.get(aggregateKey({ kind: 'client', key: 'client-1' }));
    const userOneName = namespace.namesByAggregate.get(aggregateKey({ kind: 'user', key: 'user-1' }));
    const userTwoName = namespace.namesByAggregate.get(aggregateKey({ kind: 'user', key: 'user-2' }));
    expect(new Set([clientName, userOneName, userTwoName]).size).toBe(3);
    for (const name of [clientName, userOneName, userTwoName]) {
      expect(name).toMatch(/^oauth-do:v2:(?:client|user):[0-9a-f]{64}$/);
      expect(name).not.toContain('user-');
      expect(name).not.toContain('client-1');
    }
  });

  it('checks a registered client object before touching the user aggregate', async () => {
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'missing', expectedRevision: 0 },
          grant: storedGrant(0, { clientId: 'missing' }),
        })
      )
    ).toEqual({ status: 'client_not_found' });
    expect(namespace.namesByAggregate.has(aggregateKey({ kind: 'user', key: 'user-1' }))).toBe(false);

    await connection.clients.create(createClientInput(storedClient(0)));
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'client-1', expectedRevision: 1 },
          grant: storedGrant(),
        })
      )
    ).toEqual({ status: 'client_conflict' });
    expect(namespace.namesByAggregate.has(aggregateKey({ kind: 'user', key: 'user-1' }))).toBe(false);
  });

  it('rejects global and cross-user operations before Durable Object I/O', async () => {
    const calls = namespace.names.length;
    await expect(connection.clients.list()).rejects.toMatchObject({ code: 'unsupported_operation' });
    await expect(connection.clients.deleteWithGrants({ clientId: 'client-1' })).rejects.toMatchObject({
      code: 'unsupported_operation',
    });
    await expect(connection.grants.listByClient({ clientId: 'client-1' })).rejects.toMatchObject({
      code: 'unsupported_operation',
    });
    await expect(
      connection.maintenance.purge({
        now,
        limit: 10,
        purgeExpiredGrants: true,
        purgeOrphanedGrants: true,
        purgeOrphanedTokens: true,
      })
    ).rejects.toMatchObject({ code: 'unsupported_operation' });
    expect(namespace.names).toHaveLength(calls);
  });

  it('binds each physical object to one namespace and aggregate identity', async () => {
    await connection.grants.get({ userId: 'user-1', grantId: 'none' });
    const userState = namespace.state('user', 'user-1');
    await expect(
      new OAuthStorageObject(userState).execute({
        namespace: 'default',
        aggregate: { kind: 'client', key: 'client-1' },
        operation: 'clients.get',
        clientId: 'client-1',
        now,
      })
    ).rejects.toMatchObject({ code: 'invalid_configuration', operation: 'storage.route' });

    await connection.clients.get('client-1');
    const clientState = namespace.state('client', 'client-1');
    await expect(
      new OAuthStorageObject(clientState).execute({
        namespace: 'other',
        aggregate: { kind: 'client', key: 'client-1' },
        operation: 'clients.get',
        clientId: 'client-1',
        now,
      })
    ).rejects.toMatchObject({ code: 'invalid_configuration', operation: 'storage.route' });
  });

  it('atomically replaces earlier grants for one user and client', async () => {
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'external', clientId: 'client-1' },
        grant: storedGrant(),
        accessToken: storedAccessToken(),
      })
    );
    const replacement = storedGrant(0, { id: 'grant-2' });
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'external', clientId: 'client-1' },
          grant: replacement,
          replaceExistingUserClientGrants: true,
        })
      )
    ).toEqual({ status: 'created' });
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' })).toBeNull();
    expect(await connection.accessTokens.get({ userId: 'user-1', grantId: 'grant-1', tokenId: DIGEST_B })).toBeNull();
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-2' })).not.toBeNull();
  });

  it('rolls back a composite user-aggregate issue failure', async () => {
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' })).toBeNull();
    const state = namespace.state('user', 'user-1');
    const externalPlan = issueGrantInput({
      client: { kind: 'external', clientId: 'https://client.example/meta' },
      grant: createStoredGrant(
        { ...storedGrant().value, clientId: 'https://client.example/meta' },
        { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
      ),
      accessToken: storedAccessToken(0, {
        grant: { ...storedAccessToken().value.grant!, clientId: 'https://client.example/meta' },
      }),
    });
    state.failTransactionExecAt = 5;
    await expect(connection.grants.issue(externalPlan)).rejects.toMatchObject({ code: 'internal' });
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' })).toBeNull();
    expect(await connection.grants.issue(externalPlan)).toEqual({ status: 'created' });
  });

  it('serializes same-user contenders, persists fences, and rolls back commit faults', async () => {
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
    const state = namespace.state('user', 'user-1');
    state.failTransactionExecAt = 7;
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

  it('keeps token, consent, and transitions with the user while replay uses its own object', async () => {
    await connection.grants.issue(
      issueGrantInput({ client: { kind: 'external', clientId: 'client-1' }, grant: storedGrant(0) })
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
    const sameShardDigest = credentialIdFromSha256(`${DIGEST_B.slice(0, 2)}${'d'.repeat(62)}`);
    expect(
      await connection.replay.reserve({
        reservationNamespace: 'ema-jti',
        keyHash: sameShardDigest,
        expiresAt: 300,
      })
    ).toEqual({ status: 'reserved' });

    const user = namespace.state('user', 'user-1');
    const replay = namespace.state('replay', JSON.stringify(['ema-jti', DIGEST_B.slice(0, 2)]));
    expect(user.database.prepare("SELECT COUNT(*) AS count FROM records WHERE kind='token'").get()).toEqual({
      count: 1,
    });
    expect(replay.database.prepare('SELECT COUNT(*) AS count FROM replay').get()).toEqual({ count: 2 });
    expect(await connection.grants.revoke({ grant: { userId: 'user-1', grantId: 'grant-1' } })).toEqual({
      status: 'revoked',
      deletedAccessTokens: 1,
    });
    expect((await connection.consents.listByUser({ userId: 'user-1' })).items).toHaveLength(1);
  });

  it('requires the full token parent key for reads and deletion', async () => {
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'external', clientId: 'client-1' },
        grant: storedGrant(),
        accessToken: storedAccessToken(),
      })
    );
    const wrongParent = { userId: 'user-1', grantId: 'wrong-grant', tokenId: DIGEST_B } as const;
    expect(await connection.accessTokens.get(wrongParent)).toBeNull();
    expect(await connection.accessTokens.delete({ key: wrongParent })).toEqual({ status: 'not_found' });
    expect(
      await connection.accessTokens.get({ userId: 'user-1', grantId: 'grant-1', tokenId: DIGEST_B })
    ).not.toBeNull();
  });

  it('uses local alarms without pretending an expired client can cascade across users', async () => {
    const wallNow = Math.floor(Date.now() / 1000);
    const past = wallNow - 1;
    const future = wallNow + 1_000;
    const expiringClient = createStoredClient(storedClient().value, {
      schemaVersion: 1,
      revision: 0,
      createdAt: 100,
      expiresAt: past,
    });
    await connection.clients.create(createClientInput(expiringClient));
    const clientGrant = createStoredGrant(
      { ...storedGrant().value, expiresAt: future },
      { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: future }
    );
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
        grant: clientGrant,
      })
    );
    await new OAuthStorageObject(namespace.state('client', 'client-1')).alarm();
    expect(await connection.clients.get('client-1')).toBeNull();
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' })).not.toBeNull();

    const expiredGrant = createStoredGrant(
      { ...storedGrant().value, id: 'expired', clientId: 'external', expiresAt: past },
      { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: past }
    );
    const child = storedAccessToken(0, {
      id: DIGEST_C,
      grantId: 'expired',
      expiresAt: future,
      grant: { ...storedAccessToken().value.grant!, clientId: 'external' },
    });
    await connection.grants.issue(
      issueGrantInput({ client: { kind: 'external', clientId: 'external' }, grant: expiredGrant, accessToken: child })
    );
    await new OAuthStorageObject(namespace.state('user', 'user-1')).alarm();
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'expired' })).toBeNull();
    expect(await connection.accessTokens.get({ userId: 'user-1', grantId: 'expired', tokenId: DIGEST_C })).toBeNull();
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
    expect(new Set(namespace.names).size).toBe(2);
    await connection.close();
    await expect(connection.clients.get('client-1')).rejects.toMatchObject({ code: 'unavailable' });
    await expect(connection.clients.list()).rejects.toMatchObject({ code: 'unavailable' });
    await other.close();
  });
});
