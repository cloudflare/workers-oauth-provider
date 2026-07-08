import { OAuthStorageError } from '../errors';
import type { PostgresClient } from './index';

/** One immutable PostgreSQL storage migration. */
export interface PostgresStorageMigration {
  readonly version: number;
  readonly statements: readonly string[];
}

/** Versioned PostgreSQL schema. Apply before serving OAuth traffic. */
export const POSTGRES_STORAGE_MIGRATIONS: readonly PostgresStorageMigration[] = Object.freeze([
  Object.freeze({
    version: 1,
    statements: Object.freeze([
      `CREATE TABLE IF NOT EXISTS oauth_clients (namespace text NOT NULL, client_id text NOT NULL, value jsonb NOT NULL, schema_version integer NOT NULL CHECK(schema_version>=0), revision bigint NOT NULL CHECK(revision>=0), created_at bigint NOT NULL CHECK(created_at>=0), expires_at bigint, PRIMARY KEY(namespace,client_id))`,
      `CREATE TABLE IF NOT EXISTS oauth_grants (namespace text NOT NULL, user_id text NOT NULL, grant_id text NOT NULL, client_id text NOT NULL, registered_client_id text, value jsonb NOT NULL, schema_version integer NOT NULL CHECK(schema_version>=0), revision bigint NOT NULL CHECK(revision>=0), created_at bigint NOT NULL CHECK(created_at>=0), expires_at bigint, transition_fence bigint NOT NULL DEFAULT 0 CHECK(transition_fence>=0), transition_lease_id text, transition_owner_id text, transition_kind text CHECK(transition_kind IN ('authorization_code','refresh_token')), transition_credential_id char(64), transition_callback_key char(64), transition_lease_expires_at bigint, PRIMARY KEY(namespace,user_id,grant_id), CHECK(registered_client_id IS NULL OR registered_client_id=client_id), FOREIGN KEY(namespace,registered_client_id) REFERENCES oauth_clients(namespace,client_id) ON DELETE CASCADE)`,
      `CREATE INDEX IF NOT EXISTS oauth_grants_client_idx ON oauth_grants(namespace,client_id,user_id,grant_id)`,
      `CREATE INDEX IF NOT EXISTS oauth_grants_user_client_idx ON oauth_grants(namespace,user_id,client_id,grant_id)`,
      `CREATE TABLE IF NOT EXISTS oauth_access_tokens (namespace text NOT NULL, user_id text NOT NULL, grant_id text NOT NULL, token_id char(64) NOT NULL CHECK(token_id ~ '^[0-9a-f]{64}$'), value jsonb NOT NULL, schema_version integer NOT NULL CHECK(schema_version>=0), revision bigint NOT NULL CHECK(revision>=0), created_at bigint NOT NULL CHECK(created_at>=0), expires_at bigint NOT NULL, PRIMARY KEY(namespace,user_id,grant_id,token_id), FOREIGN KEY(namespace,user_id,grant_id) REFERENCES oauth_grants(namespace,user_id,grant_id) ON DELETE CASCADE)`,
      `CREATE INDEX IF NOT EXISTS oauth_access_tokens_expiry_idx ON oauth_access_tokens(namespace,expires_at)`,
      `CREATE TABLE IF NOT EXISTS oauth_consents (namespace text NOT NULL, user_id text NOT NULL, client_id text NOT NULL, reference_id text NOT NULL DEFAULT '', value jsonb NOT NULL, schema_version integer NOT NULL CHECK(schema_version>=0), revision bigint NOT NULL CHECK(revision>=0), created_at bigint NOT NULL CHECK(created_at>=0), expires_at bigint, PRIMARY KEY(namespace,user_id,client_id,reference_id))`,
      `CREATE INDEX IF NOT EXISTS oauth_consents_user_idx ON oauth_consents(namespace,user_id,client_id,reference_id)`,
      `CREATE TABLE IF NOT EXISTS oauth_replay_reservations (namespace text NOT NULL, reservation_namespace text NOT NULL, key_hash char(64) NOT NULL CHECK(key_hash ~ '^[0-9a-f]{64}$'), expires_at bigint NOT NULL, PRIMARY KEY(namespace,reservation_namespace,key_hash))`,
      `CREATE INDEX IF NOT EXISTS oauth_replay_expiry_idx ON oauth_replay_reservations(namespace,expires_at)`,
    ]),
  }),
]);

/** Latest PostgreSQL schema version understood by this package. */
export const POSTGRES_STORAGE_SCHEMA_VERSION =
  POSTGRES_STORAGE_MIGRATIONS[POSTGRES_STORAGE_MIGRATIONS.length - 1]!.version;

/** Applies pending PostgreSQL migrations on one exclusive session. */
export async function migratePostgresStorage(client: PostgresClient): Promise<void> {
  await client.query(
    `CREATE TABLE IF NOT EXISTS oauth_storage_schema (id integer PRIMARY KEY CHECK(id=1), version integer NOT NULL)`
  );
  const result = await client.query<{ version: number | string }>(
    `SELECT version FROM oauth_storage_schema WHERE id=1`
  );
  const current = result.rows[0] ? Number(result.rows[0].version) : 0;
  if (current > POSTGRES_STORAGE_SCHEMA_VERSION) {
    throw new OAuthStorageError('schema_mismatch', { operation: 'storage.migrate' });
  }
  for (const migration of POSTGRES_STORAGE_MIGRATIONS) {
    if (migration.version <= current) continue;
    await client.query('BEGIN');
    try {
      for (const statement of migration.statements) await client.query(statement);
      await client.query(
        `INSERT INTO oauth_storage_schema(id,version) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET version=EXCLUDED.version`,
        [migration.version]
      );
      await client.query('COMMIT');
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {}
      throw error;
    }
  }
}
