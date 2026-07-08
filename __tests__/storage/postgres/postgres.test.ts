import { describe, expect, it } from 'vitest';
import {
  POSTGRES_STORAGE_CAPABILITIES,
  POSTGRES_STORAGE_MIGRATIONS,
  postgresStorage,
  type PostgresClient,
} from '../../../src/storage/postgres';
import { createOAuthStorageOpenContext } from '../../../src/storage/lifecycle';
import { issueGrantInput } from '../../../src/storage/stores';
import { storedGrant } from '../fixtures';

class RecordingClient implements PostgresClient {
  readonly calls: { sql: string; values: readonly unknown[] }[] = [];
  released = false;
  async query<Row = Readonly<Record<string, unknown>>>(sql: string, values: readonly unknown[] = []) {
    this.calls.push({ sql, values });
    return { rows: [] as readonly Row[], rowCount: 0 };
  }
  release() {
    this.released = true;
  }
}

describe('PostgreSQL storage adapter', () => {
  it('advertises the transaction-backed guarantees', () => {
    expect(POSTGRES_STORAGE_CAPABILITIES.consistency.readAfterWrite).toBe('strong');
    expect(POSTGRES_STORAGE_CAPABILITIES.transitions.refreshToken).toBe('strong');
    expect(POSTGRES_STORAGE_CAPABILITIES.replayReservation).toBe('strong');
    expect(POSTGRES_STORAGE_CAPABILITIES.expiration.cleanup).toBe('manual');
  });

  it('acquires and releases exactly one request-scoped client and binds values', async () => {
    const client = new RecordingClient();
    const provider = postgresStorage<{ client: RecordingClient }>({
      clientFactory: { acquire: ({ env }) => env.client },
      now: () => 200,
    });
    const connection = await provider.open(
      createOAuthStorageOpenContext({
        provider,
        env: { client },
        operationId: 'postgres-test',
        kind: 'request',
      })
    );
    await connection.clients.get("client' OR true --");
    expect(client.calls[0].sql).toContain('client_id=$2');
    expect(client.calls[0].sql).not.toContain("client' OR true --");
    expect(client.calls[0].values).toEqual(['default', "client' OR true --"]);
    await connection.close();
    expect(client.released).toBe(true);
  });

  it('ships immutable schema constraints, cascades, indexes, replay uniqueness and fencing', () => {
    const migrationSql = POSTGRES_STORAGE_MIGRATIONS.flatMap((migration) => migration.statements).join(';');
    expect(migrationSql).toContain('PRIMARY KEY(namespace,reservation_namespace,key_hash)');
    expect(migrationSql).toContain('transition_fence bigint NOT NULL DEFAULT 0');
    expect(migrationSql.match(/ON DELETE CASCADE/g)).toHaveLength(2);
    expect(migrationSql).toContain('registered_client_id text');
    expect(migrationSql).toContain('CHECK(registered_client_id IS NULL OR registered_client_id=client_id)');
    expect(migrationSql).toContain('FOREIGN KEY(namespace,registered_client_id)');
    expect(migrationSql).not.toContain('FOREIGN KEY(namespace,client_id)');
    expect(migrationSql).toContain('CREATE INDEX IF NOT EXISTS oauth_grants_client_idx');
    expect(migrationSql).toContain('value jsonb NOT NULL');
  });

  it('binds external grant provenance as null and registered provenance as the client id', async () => {
    const client = new RecordingClient();
    const provider = postgresStorage({ clientFactory: { acquire: () => client }, now: () => 200 });
    const connection = await provider.open(
      createOAuthStorageOpenContext({ provider, env: {}, operationId: 'provenance', kind: 'request' })
    );
    const clientId = 'https://client.example/metadata.json';
    const grant = storedGrant(0, { id: 'g', userId: 'u', clientId });
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'external', clientId },
        grant,
        replaceExistingUserClientGrants: false,
      })
    );
    const externalInsert = client.calls.find((call) => call.sql.includes('INSERT INTO oauth_grants'))!;
    expect(externalInsert.sql).toContain('registered_client_id');
    expect(externalInsert.values[4]).toBeNull();

    client.calls.length = 0;
    client.query = async <Row = Readonly<Record<string, unknown>>>(sql: string, values: readonly unknown[] = []) => {
      client.calls.push({ sql, values });
      if (sql.includes('SELECT revision FROM oauth_clients'))
        return { rows: [{ revision: 7 }] as unknown as readonly Row[], rowCount: 1 };
      return { rows: [] as readonly Row[], rowCount: sql.includes('INSERT INTO oauth_grants') ? 1 : 0 };
    };
    await connection.grants.issue(
      issueGrantInput({
        client: { kind: 'registered', clientId: grant.value.clientId, expectedRevision: 7 },
        grant,
        replaceExistingUserClientGrants: false,
      })
    );
    const lock = client.calls.find((call) => call.sql.includes('SELECT revision FROM oauth_clients'))!;
    expect(lock.sql).toContain('FOR UPDATE');
    const registeredInsert = client.calls.find((call) => call.sql.includes('INSERT INTO oauth_grants'))!;
    expect(registeredInsert.values[4]).toBe(grant.value.clientId);
  });

  it('uses only positional placeholders and supplies every referenced value', async () => {
    const client = new RecordingClient();
    const provider = postgresStorage({ clientFactory: { acquire: () => client }, now: () => 200 });
    const connection = await provider.open(
      createOAuthStorageOpenContext({ provider, env: {}, operationId: 'placeholders', kind: 'request' })
    );
    await connection.clients.get("x' OR true --");
    for (const call of client.calls) {
      const indexes = [...call.sql.matchAll(/\$(\d+)/g)].map((match) => Number(match[1]));
      expect(indexes.length ? Math.max(...indexes) : 0).toBe(call.values.length);
      expect(call.sql).not.toContain("x' OR true --");
    }
  });
});
