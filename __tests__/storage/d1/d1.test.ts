import { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { OAuthProvider, type OAuthHelpers } from '../../../src/oauth-provider';
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

function executionContext(): ExecutionContext {
  return { props: {}, exports: {}, waitUntil() {}, passThroughOnException() {} } as ExecutionContext;
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

  it('satisfies the provider strict-mode requirements', () => {
    const storage = d1Storage<{ DB: D1Database }>({ binding: (env) => env.DB, now: () => now });
    expect(
      () =>
        new OAuthProvider({
          apiRoute: '/api/',
          apiHandler: { fetch: async () => new Response('api') },
          defaultHandler: { fetch: async () => new Response('default') },
          authorizeEndpoint: '/authorize',
          tokenEndpoint: '/oauth/token',
          storage,
          storageGuarantees: 'strict',
        })
    ).not.toThrow();
  });

  it('runs the complete strict OAuth authorization flow without KV', async () => {
    interface Env {
      readonly DB: D1Database;
      OAUTH_PROVIDER?: OAuthHelpers | null;
    }
    const storage = d1Storage<Env>({ binding: (env) => env.DB });
    const redirectUri = 'https://client.example/callback';
    const provider = new OAuthProvider<Env>({
      apiRoute: '/api/',
      apiHandler: { fetch: async () => new Response('api') },
      defaultHandler: {
        async fetch(request, env) {
          if (new URL(request.url).pathname !== '/authorize') return new Response('default');
          const parsed = await env.OAUTH_PROVIDER!.parseAuthRequest(request);
          const completed = await env.OAUTH_PROVIDER!.completeAuthorization({
            request: parsed,
            userId: 'user-1',
            metadata: {},
            scope: parsed.scope,
            props: { userId: 'user-1' },
          });
          return Response.redirect(completed.redirectTo);
        },
      },
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      storage,
      storageGuarantees: 'strict',
    });
    const env: Env = { DB: d1 as unknown as D1Database, OAUTH_PROVIDER: null };
    await provider.fetch(new Request('https://example.com/'), env, executionContext());
    const client = await env.OAUTH_PROVIDER!.createClient({
      redirectUris: [redirectUri],
      tokenEndpointAuthMethod: 'none',
    });
    const verifier = 'a'.repeat(64);
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const authorization = await provider.fetch(
      new Request(
        `https://example.com/authorize?response_type=code&client_id=${client.clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}&scope=read&code_challenge=${challenge}&code_challenge_method=S256`
      ),
      env,
      executionContext()
    );
    const code = new URL(authorization.headers.get('Location')!).searchParams.get('code')!;
    const token = await provider.fetch(
      new Request('https://example.com/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: client.clientId,
          redirect_uri: redirectUri,
          code,
          code_verifier: verifier,
        }),
      }),
      env,
      executionContext()
    );
    expect(token.status).toBe(200);
    const tokens = (await token.json()) as { access_token: string; refresh_token: string };
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
  });

  it('tracks schema versions, rolls back failed migration batches, and rejects newer schemas', async () => {
    await migrateD1Storage(d1 as unknown as D1Database);
    expect(await d1.prepare('SELECT version FROM oauth_storage_schema WHERE id=1').first<number>('version')).toBe(1);

    const failed = new SqliteD1();
    failed.failBatchAt = 0;
    await expect(migrateD1Storage(failed as unknown as D1Database)).rejects.toThrow(/injected/);
    expect(
      await failed.prepare('SELECT version FROM oauth_storage_schema WHERE id=1').first<number>('version')
    ).toBeNull();
    failed.close();

    await d1.prepare('UPDATE oauth_storage_schema SET version=99 WHERE id=1').run();
    await expect(migrateD1Storage(d1 as unknown as D1Database)).rejects.toThrow(/newer than supported/);
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
    const replacement = createStoredGrant(
      { ...storedGrant().value, id: 'replacement-grant' },
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
    await connection.maintenance.purge({
      now: 100,
      limit: 100,
      purgeExpiredGrants: false,
      purgeOrphanedGrants: true,
      purgeOrphanedTokens: false,
    });
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'external-grant' })).not.toBeNull();
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

  it('does not delete prior grants when replacement preconditions fail', async () => {
    await connection.clients.create(createClientInput(storedClient(0)));
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
        grant: storedGrant(0, { id: 'old-grant' }),
        accessToken: storedAccessToken(0, { grantId: 'old-grant' }),
      })
    );
    const replacement = (id: string, clientId = 'client-1') =>
      createStoredGrant(
        { ...storedGrant().value, id, clientId },
        { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
      );
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'missing', expectedRevision: 0 },
          grant: replacement('missing-replacement', 'missing'),
          replaceExistingUserClientGrants: true,
        })
      )
    ).toEqual({ status: 'client_not_found' });
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'client-1', expectedRevision: 9 },
          grant: replacement('stale-replacement'),
          replaceExistingUserClientGrants: true,
        })
      )
    ).toEqual({ status: 'client_conflict' });
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
        grant: replacement('conflicting-target'),
      })
    );
    expect(
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
          grant: replacement('conflicting-target'),
          replaceExistingUserClientGrants: true,
        })
      )
    ).toEqual({ status: 'conflict' });
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'old-grant' })).not.toBeNull();
  });

  it('atomically cascades client deletion with exact effect counts', async () => {
    await connection.clients.create(createClientInput(storedClient(0)));
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
        grant: storedGrant(0),
        accessToken: storedAccessToken(0),
      })
    );
    expect(await connection.clients.deleteWithGrants({ clientId: 'client-1', expectedRevision: 0 })).toEqual({
      status: 'deleted',
      deletedGrants: 1,
      deletedAccessTokens: 1,
    });
    expect(await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' })).toBeNull();
  });

  it('classifies consumed current and previous refresh credentials and rejects expired replay reservations', async () => {
    const consumed = createStoredGrant(
      {
        ...storedGrant().value,
        refreshTokenId: DIGEST_A,
        refreshTokenWrappedKey: undefined,
        previousRefreshTokenId: DIGEST_C,
        previousRefreshTokenWrappedKey: undefined,
      },
      { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
    );
    await connection.grants.issue(
      issueGrantInput({ client: { kind: 'external', clientId: 'client-1' }, grant: consumed })
    );
    for (const credentialId of [DIGEST_A, DIGEST_C]) {
      expect(
        await connection.grants.beginTransition(
          await beginGrantTransitionInput({
            namespace: 'default',
            grant: { userId: 'user-1', grantId: 'grant-1' },
            kind: 'refresh_token',
            credentialId,
            ownerId: transitionOwnerId(`consumed-${credentialId[0]}`),
            leaseTtlSeconds: 30,
            now,
          })
        )
      ).toEqual({ status: 'already_consumed' });
    }
    await expect(
      connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_B, expiresAt: now })
    ).rejects.toMatchObject({ code: 'conflict' });
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
    for (const id of ['expired-1', 'expired-2']) {
      await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'external', clientId: 'external' },
          grant: createStoredGrant(
            { ...storedGrant().value, id, clientId: 'external', createdAt: 50, expiresAt: 90 },
            { schemaVersion: 1, revision: 0, createdAt: 50, expiresAt: 90 }
          ),
        })
      );
    }
    now = 400;
    const firstPurge = await connection.maintenance.purge({
      now,
      limit: 1,
      purgeExpiredGrants: true,
      purgeOrphanedGrants: true,
      purgeOrphanedTokens: true,
    });
    expect(firstPurge).toMatchObject({ grantsChecked: 1, grantsPurged: 1, done: false });
    const secondPurge = await connection.maintenance.purge({
      now,
      limit: 1,
      purgeExpiredGrants: true,
      purgeOrphanedGrants: true,
      purgeOrphanedTokens: true,
    });
    expect(secondPurge).toMatchObject({ grantsChecked: 1, grantsPurged: 1, done: true });
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
