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
  replaceClientInput,
  transitionOwnerId,
  type OAuthStorageConnection,
  type StorageGrant,
} from '../../../src/storage';
import { d1Storage } from '../../../src/storage/d1';
import { migrateD1Storage } from '../../../src/storage/d1/migrations';
import { DIGEST_A, DIGEST_B, DIGEST_C, storedAccessToken, storedClient, storedGrant } from '../fixtures';

class SqliteD1 {
  readonly database = new DatabaseSync(':memory:');
  failBatchAt: number | undefined;

  prepare(sql: string): D1PreparedStatement {
    return new SqliteStatement(this, sql, []) as unknown as D1PreparedStatement;
  }

  async batch(statements: D1PreparedStatement[]): Promise<D1Result[]> {
    this.database.exec('BEGIN IMMEDIATE');
    try {
      const results: D1Result[] = [];
      for (let index = 0; index < statements.length; index++) {
        if (this.failBatchAt === index) {
          this.failBatchAt = undefined;
          throw new Error(`injected batch failure at ${index}`);
        }
        results.push(await statements[index]!.run());
      }
      this.database.exec('COMMIT');
      return results;
    } catch (error) {
      this.database.exec('ROLLBACK');
      throw error;
    }
  }

  close(): void {
    this.database.close();
  }
}

class SqliteStatement {
  constructor(
    private readonly owner: SqliteD1,
    private readonly sql: string,
    private readonly bindings: unknown[]
  ) {}

  bind(...values: unknown[]): SqliteStatement {
    return new SqliteStatement(this.owner, this.sql, values);
  }

  async run(): Promise<D1Result> {
    const result = this.owner.database.prepare(this.sql).run(...this.bindings);
    return d1Result([], result.changes);
  }

  async all<T>(): Promise<D1Result<T>> {
    const rows = this.owner.database.prepare(this.sql).all(...this.bindings) as T[];
    return d1Result(rows, 0);
  }

  async first<T>(column?: string): Promise<T | null> {
    const row = this.owner.database.prepare(this.sql).get(...this.bindings);
    if (row === undefined) return null;
    return (column === undefined ? row : row[column]) as T;
  }
}

function d1Result<T>(results: T[], changes: number): D1Result<T> {
  return {
    success: true,
    results,
    meta: { changes },
  } as unknown as D1Result<T>;
}

function pendingGrant(id = 'grant-1'): ReturnType<typeof createStoredGrant> {
  const value: StorageGrant = {
    ...storedGrant().value,
    id,
    expiresAt: undefined,
    refreshTokenId: undefined,
    authCodeId: DIGEST_A,
    authCodeWrappedKey: 'wrapped-code-key',
  };
  return createStoredGrant(value, {
    schemaVersion: 1,
    revision: 0,
    createdAt: 100,
    expiresAt: 700,
  });
}

describe('D1 storage adapter against SQLite transaction semantics', () => {
  let d1: SqliteD1;
  let now: number;
  let connection: OAuthStorageConnection;

  beforeEach(async () => {
    d1 = new SqliteD1();
    now = 100;
    await migrateD1Storage(d1 as unknown as D1Database);
    const provider = d1Storage<{ DB: D1Database }>({
      binding: (env) => env.DB,
      now: () => now,
    });
    connection = await provider.open(
      createOAuthStorageOpenContext({
        provider,
        env: { DB: d1 as unknown as D1Database },
        operationId: 'd1-test',
        kind: 'request',
      })
    );
  });

  afterEach(() => {
    d1.close();
  });

  it('runs migrations idempotently and performs client CAS with pagination', async () => {
    await migrateD1Storage(d1 as unknown as D1Database);
    expect(await connection.clients.create(createClientInput(storedClient(0)))).toEqual({ status: 'created' });
    expect(await connection.clients.create(createClientInput(storedClient(0)))).toEqual({ status: 'conflict' });
    expect(await connection.clients.replace(replaceClientInput('client-1', 0, storedClient(1)))).toEqual({
      status: 'updated',
    });
    expect((await connection.clients.get('client-1'))?.metadata.revision).toBe(1);
    expect((await connection.clients.list({ limit: 1 })).items).toHaveLength(1);
  });

  it('guards registered issuance, permits external issuance, and rolls back a failed grant-plus-token batch', async () => {
    const registered = issueGrantInput({
      client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
      grant: storedGrant(0),
      accessToken: storedAccessToken(0),
    });
    expect(await connection.grants.issue(registered)).toEqual({ status: 'client_not_found' });
    await connection.clients.create(createClientInput(storedClient(0)));
    d1.failBatchAt = 1;
    await expect(connection.grants.issue(registered)).rejects.toMatchObject({ code: 'internal' });
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' })).toBeNull();
    expect(await connection.grants.issue(registered)).toEqual({ status: 'created' });

    const external = createStoredGrant(
      { ...storedGrant().value, id: 'external-grant', clientId: 'https://client.example/meta' },
      { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
    );
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'external', clientId: external.value.clientId },
          grant: external,
        })
      )
    ).toEqual({ status: 'created' });
  });

  it('allows one transition contender, persists monotonic fences, rejects stale commits, and rolls back commit faults', async () => {
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
    if (first.status !== 'acquired') throw new Error('expected acquired');

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
    d1.failBatchAt = 1;
    await expect(connection.grants.commitTransition(commit)).rejects.toMatchObject({ code: 'internal' });
    expect((await connection.grants.get(first.lease.grant))?.metadata.revision).toBe(0);
    expect(await connection.grants.commitTransition(commit)).toEqual({ status: 'committed' });
    expect(
      await connection.grants.beginTransition(
        await beginGrantTransitionInput({
          namespace: 'default',
          grant: first.lease.grant,
          kind: 'authorization_code',
          credentialId: DIGEST_A,
          ownerId: transitionOwnerId('replay-owner'),
          leaseTtlSeconds: 30,
          now: 120,
        })
      )
    ).toEqual({ status: 'already_consumed' });

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
    expect(await connection.grants.commitTransition(commit)).toEqual({ status: 'lease_lost' });
    const refreshedGrant = createStoredGrant(
      {
        ...nextGrant.value,
        refreshTokenId: DIGEST_B,
        previousRefreshTokenId: DIGEST_C,
      },
      { schemaVersion: 1, revision: 2, createdAt: 100, expiresAt: 500 }
    );
    expect(
      await connection.grants.commitTransition(
        commitGrantTransitionInput({
          lease: second.lease,
          now: 210,
          grant: refreshedGrant,
          accessToken: storedAccessToken(0, { id: DIGEST_C }),
        })
      )
    ).toEqual({ status: 'committed' });
  });

  it('executes token CRUD, replay reservation, consent CAS, revocation, and cleanup', async () => {
    await connection.clients.create(createClientInput(storedClient(0)));
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
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
      (await connection.accessTokens.listByGrant({ grant: { userId: 'user-1', grantId: 'grant-1' } })).items
    ).toHaveLength(1);

    expect(
      await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_B, expiresAt: 300 })
    ).toEqual({ status: 'reserved' });
    expect(
      await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_B, expiresAt: 300 })
    ).toEqual({ status: 'exists' });

    const consent = createStoredConsent(
      { userId: 'user-1', clientId: 'client-1', scope: ['read'], updatedAt: 100 },
      { schemaVersion: 1, revision: 0, createdAt: 100 }
    );
    expect(await connection.consents.compareAndSwap(compareAndSwapConsentInput({ consent }))).toEqual({
      status: 'created',
    });
    expect((await connection.consents.listByUser({ userId: 'user-1' })).items).toHaveLength(1);

    expect(await connection.grants.revoke({ grant: { userId: 'user-1', grantId: 'grant-1' } })).toEqual({
      status: 'revoked',
      deletedAccessTokens: 1,
    });
    now = 400;
    const purged = await connection.maintenance.purge({
      now,
      limit: 100,
      purgeExpiredGrants: true,
      purgeOrphanedGrants: true,
      purgeOrphanedTokens: true,
    });
    expect(purged.done).toBe(true);
  });

  it('isolates namespaces and rejects operations after close', async () => {
    const otherProvider = d1Storage<{ DB: D1Database }>({
      binding: (env) => env.DB,
      namespace: 'other',
      now: () => now,
    });
    const other = await otherProvider.open(
      createOAuthStorageOpenContext({
        provider: otherProvider,
        env: { DB: d1 as unknown as D1Database },
        operationId: 'other',
        kind: 'request',
      })
    );
    await connection.clients.create(createClientInput(storedClient(0)));
    expect(await other.clients.get('client-1')).toBeNull();
    await connection.close();
    await expect(connection.clients.get('client-1')).rejects.toMatchObject({ code: 'internal' });
    await other.close();
  });
});
