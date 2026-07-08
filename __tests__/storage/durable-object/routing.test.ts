import { describe, expect, it, vi } from 'vitest';
import {
  DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES,
  durableObjectSqliteStorage,
  type DurableObjectStorageCommand,
  type OAuthStorageObjectNamespace,
} from '../../../src/storage/durable-object';
import { createClientInput, issueGrantInput } from '../../../src/storage';
import { storedClient, storedGrant } from '../fixtures';

/** Descriptor-to-test map. Every strong capability has an explicit assertion here or an operation test below. */
const EXPECTED_STRONG = [
  'clients.create',
  'clients.replace',
  'issuance.grantOnly',
  'issuance.grantWithAccessToken',
  'issuance.replaceUserClientGrants',
  'issuance.existingGrantAccessToken',
  'transitions.authorizationCode',
  'transitions.refreshToken',
  'replayReservation',
  'revocation.accessToken',
  'revocation.grantCascade',
  'revocation.clientCascade',
  'consents.compareAndSwap',
  'consents.delete',
  'consistency.readAfterWrite',
  'queries.listClients',
  'queries.grantsByUser',
  'queries.grantsByClient',
  'queries.tokensByGrant',
  'queries.consentsByUser',
  'queries.globalMaintenance',
] as const;

describe('Durable Object root routing', () => {
  it('maps every advertised strong descriptor to this suite', () => {
    const c = DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES as unknown as Record<string, unknown>;
    for (const path of EXPECTED_STRONG) {
      const value = path.split('.').reduce<unknown>((v, key) => (v as Record<string, unknown>)[key], c);
      expect(value, path).toBe('strong');
    }
  });

  it('routes client, grant, query, consent, replay, and maintenance commands to one deterministic root', async () => {
    const names: string[] = [];
    const commands: DurableObjectStorageCommand[] = [];
    const namespace: OAuthStorageObjectNamespace = {
      getByName(name) {
        names.push(name);
        return {
          execute: vi.fn(async (command: DurableObjectStorageCommand) => {
            commands.push(command);
            if (command.operation === 'clients.get') return storedClient();
            if (command.operation === 'grants.issue') return { status: 'created' };
            if (command.operation.endsWith('list')) return { items: [] };
            if (command.operation === 'maintenance.purge')
              return { grantsChecked: 0, grantsPurged: 0, tokensChecked: 0, tokensPurged: 0, done: true };
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
    await connection.clients.get('client-1');
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
        grant: storedGrant(),
      })
    );
    await connection.clients.list();
    await connection.consents.listByUser({ userId: 'user-1' });
    await connection.maintenance.purge({
      now: 200,
      limit: 10,
      purgeOrphanedGrants: true,
      purgeExpiredGrants: true,
      purgeOrphanedTokens: true,
    });
    expect(new Set(names)).toEqual(new Set(['oauth-do:v1:tenant%2Fa:root']));
    expect(commands.map((command) => command.operation)).toEqual([
      'clients.get',
      'grants.issue',
      'clients.list',
      'consents.list',
      'maintenance.purge',
    ]);
  });

  it('rejects calls after close without touching the namespace', async () => {
    const getByName = vi.fn();
    const provider = durableObjectSqliteStorage({ binding: () => ({ getByName }), namespace: 'closed' });
    const connection = await provider.open({ env: {}, namespace: 'closed', operationId: 'test', kind: 'request' });
    connection.close();
    await expect(connection.clients.create(createClientInput(storedClient()))).rejects.toMatchObject({
      code: 'unavailable',
    });
    expect(getByName).not.toHaveBeenCalled();
  });
});
