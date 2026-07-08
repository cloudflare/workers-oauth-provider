import { describe, expect, it } from 'vitest';
import migrationSql from '../../../src/storage/postgres/0001_initial.sql?raw';
import { POSTGRES_STORAGE_CAPABILITIES, postgresStorage, type PostgresClient } from '../../../src/storage/postgres';
import { createOAuthStorageOpenContext } from '../../../src/storage/lifecycle';

class RecordingClient implements PostgresClient {
  readonly calls: { sql: string; values: readonly unknown[] }[] = [];
  released = false;
  async query(sql: string, values: readonly unknown[] = []) {
    this.calls.push({ sql, values });
    return { rows: [], rowCount: 0 };
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
    expect(migrationSql).toContain('PRIMARY KEY(namespace,reservation_namespace,key_hash)');
    expect(migrationSql).toContain('transition_fence bigint NOT NULL DEFAULT 0');
    expect(migrationSql.match(/ON DELETE CASCADE/g)).toHaveLength(2);
    expect(migrationSql).toContain('CREATE INDEX oauth_grants_client_idx');
    expect(migrationSql).toContain('value jsonb NOT NULL');
  });
});
