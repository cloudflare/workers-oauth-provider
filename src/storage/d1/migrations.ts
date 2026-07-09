export interface D1StorageMigration {
  readonly version: number;
  readonly statements: readonly string[];
}

/** Adapter-owned D1 schema. Consumers apply these statements in version order. */
export const D1_STORAGE_MIGRATIONS: readonly D1StorageMigration[] = Object.freeze([
  Object.freeze({
    version: 1,
    statements: Object.freeze([
      `CREATE TABLE IF NOT EXISTS oauth_storage_schema (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS oauth_clients (namespace TEXT NOT NULL, client_id TEXT NOT NULL, revision INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, value_json TEXT NOT NULL, PRIMARY KEY(namespace, client_id))`,
      `CREATE INDEX IF NOT EXISTS oauth_clients_page ON oauth_clients(namespace, client_id)`,
      `CREATE TABLE IF NOT EXISTS oauth_grants (namespace TEXT NOT NULL, user_id TEXT NOT NULL, grant_id TEXT NOT NULL, client_id TEXT NOT NULL, client_kind TEXT NOT NULL CHECK(client_kind IN ('registered','external')), issue_marker TEXT, revision INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, value_json TEXT NOT NULL, PRIMARY KEY(namespace, user_id, grant_id))`,
      `CREATE INDEX IF NOT EXISTS oauth_grants_user ON oauth_grants(namespace, user_id, grant_id)`,
      `CREATE INDEX IF NOT EXISTS oauth_grants_client ON oauth_grants(namespace, client_id, user_id, grant_id)`,
      `CREATE TABLE IF NOT EXISTS oauth_access_tokens (namespace TEXT NOT NULL, user_id TEXT NOT NULL, grant_id TEXT NOT NULL, token_id TEXT NOT NULL, revision INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, value_json TEXT NOT NULL, PRIMARY KEY(namespace, user_id, grant_id, token_id))`,
      `CREATE INDEX IF NOT EXISTS oauth_tokens_grant ON oauth_access_tokens(namespace, user_id, grant_id, token_id)`,
      `CREATE TABLE IF NOT EXISTS oauth_consents (namespace TEXT NOT NULL, user_id TEXT NOT NULL, client_id TEXT NOT NULL, reference_id TEXT NOT NULL, revision INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, value_json TEXT NOT NULL, PRIMARY KEY(namespace, user_id, client_id, reference_id))`,
      `CREATE INDEX IF NOT EXISTS oauth_consents_user ON oauth_consents(namespace, user_id, client_id, reference_id)`,
      `CREATE TABLE IF NOT EXISTS oauth_replay_reservations (namespace TEXT NOT NULL, reservation_namespace TEXT NOT NULL, key_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(namespace, reservation_namespace, key_hash))`,
      `CREATE TABLE IF NOT EXISTS oauth_transition_leases (namespace TEXT NOT NULL, user_id TEXT NOT NULL, grant_id TEXT NOT NULL, kind TEXT NOT NULL, lease_id TEXT NOT NULL, owner_id TEXT NOT NULL, credential_id TEXT NOT NULL, callback_key TEXT NOT NULL, fence INTEGER NOT NULL, expected_revision INTEGER NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(namespace, user_id, grant_id))`,
      `CREATE TABLE IF NOT EXISTS oauth_operation_assertions (id TEXT PRIMARY KEY, ok INTEGER NOT NULL CHECK(ok=1))`,
    ]),
  }),
]);

export const D1_STORAGE_SCHEMA_VERSION = D1_STORAGE_MIGRATIONS[D1_STORAGE_MIGRATIONS.length - 1]!.version;

/** Applies pending adapter migrations using D1's transactional batch primitive. */
export async function migrateD1Storage(database: D1Database): Promise<void> {
  await database
    .prepare(
      `CREATE TABLE IF NOT EXISTS oauth_storage_schema (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)`
    )
    .run();
  const current =
    (await database.prepare(`SELECT version FROM oauth_storage_schema WHERE id=1`).first<number>('version')) ?? 0;
  if (current > D1_STORAGE_SCHEMA_VERSION) {
    throw new Error(`D1 OAuth storage schema ${current} is newer than supported version ${D1_STORAGE_SCHEMA_VERSION}`);
  }
  for (const migration of D1_STORAGE_MIGRATIONS) {
    if (migration.version <= current) continue;
    await database.batch([
      ...migration.statements.map((sql) => database.prepare(sql)),
      database
        .prepare(
          `INSERT INTO oauth_storage_schema(id,version) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version WHERE oauth_storage_schema.version<excluded.version`
        )
        .bind(migration.version),
    ]);
  }
}
