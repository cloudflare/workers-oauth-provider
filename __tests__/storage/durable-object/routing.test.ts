import { describe, expect, it, vi } from 'vitest';
import {
  DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES,
  durableObjectSqliteStorage,
  type DurableObjectStorageCommand,
  type OAuthStorageObjectNamespace,
} from '../../../src/storage/durable-object';
import {
  compareAndSwapConsentInput,
  createClientInput,
  createStoredConsent,
  issueGrantInput,
} from '../../../src/storage';
import { DIGEST_A, storedClient, storedGrant } from '../fixtures';

const EXPECTED_STRONG = [
  'clients.create',
  'clients.replace',
  'issuance.existingGrantAccessToken',
  'transitions.authorizationCode',
  'transitions.refreshToken',
  'replayReservation',
  'revocation.accessToken',
  'revocation.grantCascade',
  'consents.compareAndSwap',
  'consents.delete',
  'consistency.readAfterWrite',
  'queries.grantsByUser',
  'queries.tokensByGrant',
  'queries.consentsByUser',
] as const;

const EXPECTED_UNSUPPORTED = [
  'revocation.clientCascade',
  'queries.listClients',
  'queries.grantsByClient',
  'queries.globalMaintenance',
] as const;

function capability(path: string): unknown {
  return path
    .split('.')
    .reduce<unknown>(
      (value, key) => (value as Readonly<Record<string, unknown>>)[key],
      DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES as unknown as Readonly<Record<string, unknown>>
    );
}

describe('partitioned Durable Object routing', () => {
  it('maps strong and unsupported descriptors to explicit adapter behavior', () => {
    for (const path of EXPECTED_STRONG) expect(capability(path), path).toBe('strong');
    for (const path of EXPECTED_UNSUPPORTED) expect(capability(path), path).toBe('unsupported');
    expect(DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES.issuance.grantOnly).toBe('best_effort');
    expect(DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES.issuance.grantWithAccessToken).toBe('best_effort');
    expect(DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES.issuance.replaceUserClientGrants).toBe('best_effort');
  });

  it('routes client, user, and replay commands to deterministic independent objects', async () => {
    const names: string[] = [];
    const commands: DurableObjectStorageCommand[] = [];
    const namespace: OAuthStorageObjectNamespace = {
      getByName(name) {
        names.push(name);
        return {
          execute: vi.fn(async (command: DurableObjectStorageCommand) => {
            commands.push(command);
            if (command.operation === 'clients.get') return storedClient();
            if (command.operation === 'clients.create') return { status: 'created' };
            if (command.operation === 'grants.issue') return { status: 'created' };
            if (command.operation === 'consents.cas') return { status: 'created' };
            if (command.operation === 'replay.reserve') return { status: 'reserved' };
            return null;
          }),
        };
      },
    };
    const provider = durableObjectSqliteStorage<{ binding: OAuthStorageObjectNamespace }>({
      binding: (env) => env.binding,
      namespace: 'tenant/a',
      now: () => 200,
    });
    const connection = await provider.open({
      env: { binding: namespace },
      namespace: 'tenant/a',
      operationId: 'test',
      kind: 'request',
    });
    await connection.clients.create(createClientInput(storedClient()));
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
        grant: storedGrant(),
      })
    );
    await connection.consents.compareAndSwap(
      compareAndSwapConsentInput({
        consent: createStoredConsent(
          { userId: 'user-1', clientId: 'client-1', scope: ['read'], updatedAt: 200 },
          { schemaVersion: 1, revision: 0, createdAt: 100 }
        ),
      })
    );
    await connection.replay.reserve({ reservationNamespace: 'ema-jti', keyHash: DIGEST_A, expiresAt: 300 });

    expect(commands.map((command) => command.namespace)).toEqual(Array(5).fill('tenant/a'));
    expect(commands.map((command) => command.aggregate.kind)).toEqual(['client', 'client', 'user', 'user', 'replay']);
    expect(commands[2]?.aggregate).toEqual({ kind: 'user', key: 'user-1' });
    expect(commands[3]?.aggregate).toEqual({ kind: 'user', key: 'user-1' });
    expect(new Set(names).size).toBe(3);
    for (const name of new Set(names)) {
      expect(name).toMatch(/^oauth-do:v2:(?:client|user|replay):[0-9a-f]{64}$/);
      expect(name).not.toContain('tenant');
      expect(name).not.toContain('user-1');
      expect(name).not.toContain('client-1');
    }
  });

  it('derives one object name per aggregate within a request-scoped connection', async () => {
    const digest = vi.spyOn(crypto.subtle, 'digest');
    const namespace: OAuthStorageObjectNamespace = {
      getByName() {
        return { execute: async () => null };
      },
    };
    const provider = durableObjectSqliteStorage({ binding: () => namespace, now: () => 200 });
    const connection = await provider.open({
      env: {},
      namespace: 'default',
      operationId: 'cache',
      kind: 'request',
    });

    await connection.grants.get({ userId: 'user-1', grantId: 'grant-1' });
    await connection.accessTokens.get({ userId: 'user-1', grantId: 'grant-1', tokenId: DIGEST_A });
    await connection.consents.get({ userId: 'user-1', clientId: 'client-1' });
    await connection.grants.listByUser({ userId: 'user-1' });
    expect(digest).toHaveBeenCalledTimes(1);

    // The same raw key in a different aggregate kind must not alias the user route.
    await connection.clients.get('user-1');
    expect(digest).toHaveBeenCalledTimes(2);
    connection.close();
    digest.mockRestore();
  });

  it('rejects unsupported and post-close calls before touching the namespace', async () => {
    const getByName = vi.fn();
    const provider = durableObjectSqliteStorage({ binding: () => ({ getByName }), namespace: 'closed' });
    const connection = await provider.open({ env: {}, namespace: 'closed', operationId: 'test', kind: 'request' });
    await expect(connection.clients.list()).rejects.toMatchObject({ code: 'unsupported_operation' });
    expect(getByName).not.toHaveBeenCalled();
    connection.close();
    await expect(connection.clients.create(createClientInput(storedClient()))).rejects.toMatchObject({
      code: 'unavailable',
    });
    await expect(connection.clients.list()).rejects.toMatchObject({ code: 'unavailable' });
    expect(getByName).not.toHaveBeenCalled();
  });
});
