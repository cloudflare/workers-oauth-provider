import { OAuthStorageError } from '../errors';
import { createOAuthStorageOpenContext, type Awaitable, type OAuthStorageProvider } from '../lifecycle';
import {
  createStoredAccessToken,
  createStoredClient,
  createStoredConsent,
  createStoredGrant,
  credentialIdFromSha256,
  type StorageGrant,
} from '../records';
import { compareAndSwapConsentInput, createClientInput, issueGrantInput, replaceClientInput } from '../stores';
import { beginGrantTransitionInput, commitGrantTransitionInput, transitionOwnerId } from '../transitions';

/** Mutable deterministic clock supplied by an adapter fixture. */
export interface OAuthStorageConformanceClock {
  now(): number;
  advance(seconds: number): void;
}

/** One opened adapter fixture used by conformance cases. */
export interface OAuthStorageConformanceFixture<Env> {
  readonly provider: OAuthStorageProvider<Env>;
  readonly env: Env;
  readonly clock: OAuthStorageConformanceClock;
  /** Optional physical-I/O counter used to prove unsupported operations fail before I/O. */
  ioCount?(): number;
  dispose?(): Awaitable<void>;
}

/** Creates isolated fixtures. Different namespaces should share one physical backend when possible. */
export interface OAuthStorageConformanceFactory<Env> {
  reset(): Awaitable<void>;
  create(namespace: string): Awaitable<OAuthStorageConformanceFixture<Env>>;
}

/** Result returned by one runner-neutral case. */
export type OAuthStorageConformanceResult =
  | { readonly status: 'passed' }
  | { readonly status: 'skipped'; readonly reason: string };

/** One substantive runner-neutral conformance case. */
export interface OAuthStorageConformanceCase {
  readonly name: string;
  run(): Promise<OAuthStorageConformanceResult>;
}

const DIGEST_A = credentialIdFromSha256('a'.repeat(64));
const DIGEST_B = credentialIdFromSha256('b'.repeat(64));
const DIGEST_C = credentialIdFromSha256('c'.repeat(64));

/**
 * Builds the common OAuth storage conformance suite without importing a test runner.
 *
 * Adapters should additionally test backend-specific transactions, scripts, faults,
 * migrations, and concurrency against their real execution model.
 */
export function createOAuthStorageConformanceCases<Env>(
  factory: OAuthStorageConformanceFactory<Env>
): readonly OAuthStorageConformanceCase[] {
  return Object.freeze([
    testCase('connection lifecycle', async () => {
      await factory.reset();
      const fixture = await factory.create('default');
      const connection = await open(fixture, 'lifecycle');
      equal(connection.namespace, 'default');
      await connection.close();
      await rejects(
        () => connection.clients.get('client-1'),
        (error) => isStorageCode(error, 'unavailable')
      );
      await fixture.dispose?.();
    }),
    testCase('namespace isolation', async () => {
      await factory.reset();
      const first = await factory.create('first');
      const second = await factory.create('second');
      const firstConnection = await open(first, 'namespace-first');
      const secondConnection = await open(second, 'namespace-second');
      equal(await firstConnection.clients.create(createClientInput(client())), { status: 'created' });
      equal(await secondConnection.clients.get('client-1'), null);
      await firstConnection.close();
      await secondConnection.close();
      await first.dispose?.();
      await second.dispose?.();
    }),
    testCase('client CAS queries and logical expiry', async () => {
      await factory.reset();
      const fixture = await factory.create('default');
      const connection = await open(fixture, 'clients');
      equal(await connection.clients.create(createClientInput(client(0, 200))), { status: 'created' });
      equal(await connection.clients.create(createClientInput(client(0, 200))), { status: 'conflict' });
      equal(await connection.clients.replace(replaceClientInput('client-1', 0, client(1, 200))), {
        status: 'updated',
      });
      const replaced = await connection.clients.get('client-1');
      if (fixture.provider.capabilities.clients.replace === 'strong') equal(replaced?.metadata.revision, 1);
      else equal(replaced?.value.clientId, 'client-1');
      if (fixture.provider.capabilities.queries.listClients !== 'unsupported') {
        equal((await connection.clients.list({ limit: 1 })).items.length, 1);
      }
      fixture.clock.advance(101);
      equal(await connection.clients.get('client-1'), null);
      await connection.close();
      await fixture.dispose?.();
    }),
    testCase('grant token issue and cascade', async () => {
      await factory.reset();
      const fixture = await factory.create('default');
      const connection = await open(fixture, 'issue');
      const result = await connection.grants.issue(
        issueGrantInput({
          client: { kind: 'external', clientId: 'client-1' },
          grant: grant(),
          accessToken: token(),
        })
      );
      equal(result, { status: 'created' });
      equal((await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' }))?.value.clientId, 'client-1');
      equal(
        (await connection.accessTokens.get({ userId: 'user-1', grantId: 'grant-1', tokenId: DIGEST_B }))?.value.id,
        DIGEST_B
      );
      if (fixture.provider.capabilities.queries.tokensByGrant !== 'unsupported') {
        equal(
          (await connection.accessTokens.listByGrant({ grant: { userId: 'user-1', grantId: 'grant-1' } })).items.length,
          1
        );
      }
      equal(await connection.grants.revoke({ grant: { userId: 'user-1', grantId: 'grant-1' } }), {
        status: 'revoked',
        deletedAccessTokens: 1,
      });
      equal(await connection.accessTokens.get({ userId: 'user-1', grantId: 'grant-1', tokenId: DIGEST_B }), null);
      await connection.close();
      await fixture.dispose?.();
    }),
    testCase('replay and consent behavior', async () => {
      await factory.reset();
      const fixture = await factory.create('default');
      const connection = await open(fixture, 'replay-consent');
      equal(await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_A, expiresAt: 200 }), {
        status: 'reserved',
      });
      equal(await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_A, expiresAt: 200 }), {
        status: 'exists',
      });
      if (fixture.provider.capabilities.consents.compareAndSwap === 'unsupported') {
        const before = fixture.ioCount?.();
        await rejects(
          () => connection.consents.compareAndSwap(compareAndSwapConsentInput({ consent: consent() })),
          (error) => isStorageCode(error, 'unsupported_operation')
        );
        if (before !== undefined) equal(fixture.ioCount?.(), before);
      } else {
        equal(await connection.consents.compareAndSwap(compareAndSwapConsentInput({ consent: consent() })), {
          status: 'created',
        });
        equal((await connection.consents.get({ userId: 'user-1', clientId: 'client-1' }))?.value.scope, ['read']);
      }
      await connection.close();
      await fixture.dispose?.();
    }),
    testCase('authorization transition behavior', async () => {
      await factory.reset();
      const fixture = await factory.create('default');
      const connection = await open(fixture, 'transition');
      if (fixture.provider.capabilities.transitions.authorizationCode === 'unsupported') {
        return skip('authorization-code transitions are unsupported');
      }
      await connection.grants.issue(
        issueGrantInput({ client: { kind: 'external', clientId: 'client-1' }, grant: pendingGrant() })
      );
      const firstInput = await beginGrantTransitionInput({
        namespace: fixture.provider.namespace,
        grant: { userId: 'user-1', grantId: 'grant-1' },
        kind: 'authorization_code',
        credentialId: DIGEST_A,
        ownerId: transitionOwnerId('owner-1'),
        leaseTtlSeconds: 30,
        now: fixture.clock.now(),
      });
      const first = await connection.grants.beginTransition(firstInput);
      equal(first.status, 'acquired');
      if (first.status !== 'acquired') throw new Error('Expected acquired transition');
      const second = await connection.grants.beginTransition(
        await beginGrantTransitionInput({
          ...firstInput,
          namespace: fixture.provider.namespace,
          ownerId: transitionOwnerId('owner-2'),
        })
      );
      if (fixture.provider.capabilities.transitions.authorizationCode === 'strong') equal(second.status, 'busy');
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
      equal(
        await connection.grants.commitTransition(
          commitGrantTransitionInput({
            lease: first.lease,
            now: fixture.clock.now() + 1,
            grant: nextGrant,
            accessToken: token(),
          })
        ),
        { status: 'committed' }
      );
      equal((await connection.grants.beginTransition(firstInput)).status, 'already_consumed');
      await connection.close();
      await fixture.dispose?.();
    }),
    testCase('concurrent strong client creation', async () => {
      await factory.reset();
      const fixture = await factory.create('default');
      if (fixture.provider.capabilities.clients.create !== 'strong') return skip('client create is not strong');
      const connection = await open(fixture, 'concurrent-client');
      const results = await Promise.all(
        Array.from({ length: 20 }, () => connection.clients.create(createClientInput(client())))
      );
      equal(results.filter((result) => result.status === 'created').length, 1);
      equal(results.filter((result) => result.status === 'conflict').length, 19);
      await connection.close();
      await fixture.dispose?.();
    }),
    testCase('bounded maintenance progress', async () => {
      await factory.reset();
      const fixture = await factory.create('default');
      const connection = await open(fixture, 'maintenance');
      if (fixture.provider.capabilities.queries.globalMaintenance === 'unsupported') {
        return skip('global maintenance is unsupported');
      }
      for (const id of ['expired-1', 'expired-2']) {
        await connection.grants.issue(
          issueGrantInput({
            client: { kind: 'external', clientId: 'external' },
            grant: expiredGrant(id),
          })
        );
      }
      const first = await connection.maintenance.purge({
        now: fixture.clock.now(),
        limit: 1,
        purgeExpiredGrants: true,
        purgeOrphanedGrants: false,
        purgeOrphanedTokens: false,
      });
      equal(first.grantsPurged, 1);
      equal(first.done, false);
      const second = await connection.maintenance.purge({
        now: fixture.clock.now(),
        limit: 1,
        purgeExpiredGrants: true,
        purgeOrphanedGrants: false,
        purgeOrphanedTokens: false,
      });
      equal(second.grantsPurged, 1);
      equal(second.done, true);
      await connection.close();
      await fixture.dispose?.();
    }),
  ]);
}

function testCase(
  name: string,
  body: () => Promise<void | OAuthStorageConformanceResult>
): OAuthStorageConformanceCase {
  return Object.freeze({
    name,
    async run() {
      return (await body()) ?? { status: 'passed' };
    },
  });
}

async function open<Env>(fixture: OAuthStorageConformanceFixture<Env>, operationId: string) {
  return fixture.provider.open(
    createOAuthStorageOpenContext({
      provider: fixture.provider,
      env: fixture.env,
      operationId,
      kind: 'request',
    })
  );
}

function client(revision = 0, expiresAt?: number) {
  return createStoredClient(
    { clientId: 'client-1', redirectUris: ['https://client.example/callback'], tokenEndpointAuthMethod: 'none' },
    { schemaVersion: 1, revision, createdAt: 100, ...(expiresAt === undefined ? {} : { expiresAt }) }
  );
}
function grant() {
  return createStoredGrant(
    {
      id: 'grant-1',
      clientId: 'client-1',
      userId: 'user-1',
      scope: ['read'],
      metadata: {},
      encryptedProps: 'ciphertext',
      createdAt: 100,
      expiresAt: 500,
      refreshTokenId: DIGEST_A,
      refreshTokenWrappedKey: 'wrapped-refresh',
    },
    { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
  );
}
function pendingGrant() {
  const value: StorageGrant = {
    ...grant().value,
    expiresAt: undefined,
    refreshTokenId: undefined,
    refreshTokenWrappedKey: undefined,
    authCodeId: DIGEST_A,
    authCodeWrappedKey: 'wrapped-code',
  };
  return createStoredGrant(value, { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 700 });
}
function expiredGrant(id: string) {
  return createStoredGrant(
    { ...grant().value, id, clientId: 'external', createdAt: 50, expiresAt: 90 },
    { schemaVersion: 1, revision: 0, createdAt: 50, expiresAt: 90 }
  );
}
function token() {
  return createStoredAccessToken(
    {
      id: DIGEST_B,
      grantId: 'grant-1',
      userId: 'user-1',
      createdAt: 100,
      expiresAt: 300,
      scope: ['read'],
      wrappedEncryptionKey: 'wrapped-access',
      grant: { clientId: 'client-1', scope: ['read'], encryptedProps: 'ciphertext' },
    },
    { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 300 }
  );
}
function consent() {
  return createStoredConsent(
    { userId: 'user-1', clientId: 'client-1', scope: ['read'], updatedAt: 100 },
    { schemaVersion: 1, revision: 0, createdAt: 100 }
  );
}
function equal(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Conformance assertion failed: ${JSON.stringify(actual)} !== ${JSON.stringify(expected)}`);
  }
}
async function rejects(action: () => Promise<unknown>, predicate: (error: unknown) => boolean): Promise<void> {
  try {
    await action();
  } catch (error) {
    if (predicate(error)) return;
    throw error;
  }
  throw new Error('Expected conformance operation to reject');
}
function isStorageCode(error: unknown, code: string): boolean {
  return error instanceof OAuthStorageError && error.code === code;
}
function skip(reason: string): OAuthStorageConformanceResult {
  return { status: 'skipped', reason };
}
