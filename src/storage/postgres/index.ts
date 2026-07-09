import { defineOAuthStorageCapabilities, type OAuthStorageCapabilities } from '../capabilities';

export {
  migratePostgresStorage,
  POSTGRES_STORAGE_MIGRATIONS,
  POSTGRES_STORAGE_SCHEMA_VERSION,
  type PostgresStorageMigration,
} from './migrations';
import { OAuthStorageError, isOAuthStorageError } from '../errors';
import {
  defineStorageNamespace,
  type OAuthStorageConnection,
  type OAuthStorageOpenContext,
  type OAuthStorageProvider,
} from '../lifecycle';
import { createPage, createPageRequest, type Page, type PageRequest } from '../pagination';
import {
  createStoredAccessToken,
  createStoredClient,
  createStoredConsent,
  createStoredGrant,
  credentialIdFromSha256,
  hideLogicallyExpired,
  type AccessTokenKey,
  type CredentialId,
  type GrantKey,
  type StoredAccessToken,
  type StoredClient,
  type StoredConsent,
  type StoredGrant,
} from '../records';
import type {
  CreateResult,
  DeleteClientResult,
  DeleteResult,
  IssueAccessTokenResult,
  IssueGrantResult,
  ReplaceConsentResult,
  ReplaceResult,
  ReplayReservationResult,
  RevokeGrantResult,
} from '../results';
import {
  assertCreateClientInput,
  assertIssueAccessTokenInput,
  assertIssueGrantInput,
  assertReplaceClientInput,
  type CompareAndSwapConsentInput,
  type CreateClientInput,
  type IssueAccessTokenInput,
  type IssueGrantInput,
  type OAuthAccessTokenStore,
  type OAuthClientStore,
  type OAuthConsentStore,
  type OAuthGrantStore,
  type OAuthMaintenanceStore,
  type OAuthReplayStore,
  type PurgeStorageInput,
  type PurgeStorageResult,
  type ReplaceClientInput,
} from '../stores';
import {
  assertBeginGrantTransitionInput,
  assertCommitGrantTransitionInput,
  createGrantTransitionLease,
  transitionLeaseId,
  validateBeginGrantTransitionResult,
  type AbortGrantTransitionInput,
  type AbortGrantTransitionResult,
  type BeginGrantTransitionInput,
  type BeginGrantTransitionResult,
  type CommitGrantTransitionResult,
  type ValidatedCommitGrantTransitionInput,
} from '../transitions';

/** Minimal driver-neutral result returned by an injected PostgreSQL client. */
export interface PostgresQueryResult<Row = Readonly<Record<string, unknown>>> {
  readonly rows: readonly Row[];
  readonly rowCount: number;
}
/** One exclusive PostgreSQL session. Values are always bound through `$n` parameters. */
export interface PostgresClient {
  query<Row = Readonly<Record<string, unknown>>>(
    sql: string,
    values?: readonly unknown[]
  ): Promise<PostgresQueryResult<Row>>;
  release(): void | Promise<void>;
}
/** Acquires one exclusive request-scoped PostgreSQL session. */
export interface PostgresClientFactory<Env> {
  acquire(context: OAuthStorageOpenContext<Env>): PostgresClient | Promise<PostgresClient>;
}
/** Configuration for postgresStorage. Hyperdrive query caching must be disabled because cached reads violate these guarantees. */
export interface PostgresStorageOptions<Env> {
  readonly clientFactory: PostgresClientFactory<Env>;
  readonly namespace?: string;
  readonly now?: () => number;
  readonly randomId?: () => string;
}

export const POSTGRES_STORAGE_CAPABILITIES: OAuthStorageCapabilities = defineOAuthStorageCapabilities({
  consistency: { readAfterWrite: 'strong' },
  clients: { create: 'strong', replace: 'strong' },
  issuance: {
    grantOnly: 'strong',
    grantWithAccessToken: 'strong',
    replaceUserClientGrants: 'strong',
    existingGrantAccessToken: 'strong',
  },
  transitions: { authorizationCode: 'strong', refreshToken: 'strong' },
  replayReservation: 'strong',
  revocation: { accessToken: 'strong', grantCascade: 'strong', clientCascade: 'strong' },
  consents: { compareAndSwap: 'strong', delete: 'strong' },
  queries: {
    listClients: 'strong',
    grantsByUser: 'strong',
    grantsByClient: 'strong',
    tokensByGrant: 'strong',
    consentsByUser: 'strong',
    globalMaintenance: 'strong',
  },
  expiration: { cleanup: 'manual', minimumTtlSeconds: 0 },
});

type Row = {
  value: unknown;
  schema_version: number;
  revision: number;
  created_at: number | string;
  expires_at: number | string | null;
};
type CountRow = { count: number | string };
type GrantTransitionRow = Row & {
  transition_lease_id: string | null;
  transition_owner_id: string | null;
  transition_kind: string | null;
  transition_credential_id: string | null;
  transition_callback_key: string | null;
  transition_lease_expires_at: number | string | null;
  transition_fence: number | string;
};
const TABLE = {
  clients: 'oauth_clients',
  grants: 'oauth_grants',
  tokens: 'oauth_access_tokens',
  consents: 'oauth_consents',
  replay: 'oauth_replay_reservations',
} as const;

/** Creates a strong PostgreSQL provider. Do not use it through cache-enabled Hyperdrive. */
export function postgresStorage<Env>(options: PostgresStorageOptions<Env>): OAuthStorageProvider<Env> {
  if (!options || !options.clientFactory || typeof options.clientFactory.acquire !== 'function')
    throw new TypeError('PostgreSQL storage requires a client factory');
  if (options.now !== undefined && typeof options.now !== 'function') {
    throw new TypeError('PostgreSQL storage clock must be a function');
  }
  if (options.randomId !== undefined && typeof options.randomId !== 'function') {
    throw new TypeError('PostgreSQL storage randomId must be a function');
  }
  const namespace = defineStorageNamespace(options.namespace);
  const clock = options.now ?? (() => Math.floor(Date.now() / 1000));
  const randomId = options.randomId ?? (() => crypto.randomUUID());
  return Object.freeze({
    id: 'postgresql',
    contractVersion: 1 as const,
    namespace,
    capabilities: POSTGRES_STORAGE_CAPABILITIES,
    async open(context: OAuthStorageOpenContext<Env>) {
      if (context.namespace !== namespace)
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      let client: PostgresClient;
      try {
        client = await options.clientFactory.acquire(context);
      } catch (cause) {
        throw new OAuthStorageError('unavailable', { operation: 'storage.open', cause });
      }
      if (!client || typeof client.query !== 'function' || typeof client.release !== 'function')
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      return new Connection(client, namespace, clock, randomId);
    },
  });
}

class Connection implements OAuthStorageConnection {
  readonly clients: OAuthClientStore;
  readonly grants: OAuthGrantStore;
  readonly accessTokens: OAuthAccessTokenStore;
  readonly consents: OAuthConsentStore;
  readonly replay: OAuthReplayStore;
  readonly maintenance: OAuthMaintenanceStore;
  #closed = false;
  constructor(
    private readonly db: PostgresClient,
    readonly namespace: string,
    private readonly clock: () => number,
    private readonly randomId: () => string
  ) {
    this.clients = Object.freeze({
      get: (id: string) => this.run('clients.get', () => this.getClient(id)),
      create: (i: CreateClientInput) => this.run('clients.create', () => this.createClient(i)),
      replace: (i: ReplaceClientInput) => this.run('clients.replace', () => this.replaceClient(i)),
      deleteWithGrants: (i: Parameters<OAuthClientStore['deleteWithGrants']>[0]) =>
        this.run('clients.deleteWithGrants', () => this.deleteClient(i)),
      list: (p?: PageRequest) => this.run('clients.list', () => this.listClients(p)),
    });
    this.grants = Object.freeze({
      get: (k: GrantKey) => this.run('grants.get', () => this.getGrant(k)),
      issue: (i: IssueGrantInput) => this.run('grants.issue', () => this.issueGrant(i)),
      listByUser: (i: Parameters<OAuthGrantStore['listByUser']>[0]) =>
        this.run('grants.listByUser', () => this.listGrants('user_id', i.userId, i.page)),
      listByClient: (i: Parameters<OAuthGrantStore['listByClient']>[0]) =>
        this.run('grants.listByClient', () => this.listGrants('client_id', i.clientId, i.page)),
      beginTransition: (i: BeginGrantTransitionInput) => this.run('grants.beginTransition', () => this.begin(i)),
      commitTransition: (i: ValidatedCommitGrantTransitionInput) =>
        this.run('grants.commitTransition', () => this.commit(i)),
      abortTransition: (i: AbortGrantTransitionInput) => this.run('grants.abortTransition', () => this.abort(i)),
      revoke: (i: Parameters<OAuthGrantStore['revoke']>[0]) =>
        this.run('grants.revoke', () => this.revoke(i.grant, i.expectedRevision)),
    });
    this.accessTokens = Object.freeze({
      get: (k: AccessTokenKey) => this.run('accessTokens.get', () => this.getToken(k)),
      createForGrant: (i: IssueAccessTokenInput) => this.run('accessTokens.createForGrant', () => this.createToken(i)),
      delete: (i: Parameters<OAuthAccessTokenStore['delete']>[0]) =>
        this.run('accessTokens.delete', () => this.deleteToken(i.key)),
      listByGrant: (i: Parameters<OAuthAccessTokenStore['listByGrant']>[0]) =>
        this.run('accessTokens.listByGrant', () => this.listTokens(i.grant, i.page)),
    });
    this.consents = Object.freeze({
      get: (i: Parameters<OAuthConsentStore['get']>[0]) => this.run('consents.get', () => this.getConsent(i)),
      compareAndSwap: (i: CompareAndSwapConsentInput) => this.run('consents.compareAndSwap', () => this.casConsent(i)),
      delete: (i: Parameters<OAuthConsentStore['delete']>[0]) =>
        this.run('consents.delete', () => this.deleteConsent(i)),
      listByUser: (i: Parameters<OAuthConsentStore['listByUser']>[0]) =>
        this.run('consents.listByUser', () => this.listConsents(i.userId, i.page)),
    });
    this.replay = Object.freeze({
      reserve: (i: Parameters<OAuthReplayStore['reserve']>[0]) => this.run('replay.reserve', () => this.reserve(i)),
    });
    this.maintenance = Object.freeze({
      purge: (i: PurgeStorageInput) => this.run('maintenance.purge', () => this.purge(i)),
    });
  }
  async close() {
    if (!this.#closed) {
      this.#closed = true;
      await this.db.release();
    }
  }
  private now() {
    const n = this.clock();
    if (!Number.isSafeInteger(n) || n < 0)
      throw new OAuthStorageError('invalid_configuration', { operation: 'storage.clock' });
    return n;
  }
  private async tx<T>(fn: () => Promise<T>): Promise<T> {
    await this.db.query('BEGIN');
    try {
      const out = await fn();
      await this.db.query('COMMIT');
      return out;
    } catch (e) {
      try {
        await this.db.query('ROLLBACK');
      } catch {}
      throw e;
    }
  }
  private async run<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    if (this.#closed) throw new OAuthStorageError('unavailable', { operation });
    try {
      return await fn();
    } catch (e) {
      if (isOAuthStorageError(e) || e instanceof TypeError) throw e;
      throw new OAuthStorageError('internal', { operation, cause: e });
    }
  }
  private rowClient(r: Row) {
    return createStoredClient(r.value as never, meta(r));
  }
  private rowGrant(r: Row) {
    return createStoredGrant(r.value as never, meta(r));
  }
  private rowToken(r: Row) {
    return createStoredAccessToken(r.value as never, meta(r));
  }
  private rowConsent(r: Row) {
    return createStoredConsent(r.value as never, meta(r));
  }
  private async getClient(id: string) {
    const r = await this.db.query<Row>(
      `SELECT value,schema_version,revision,created_at,expires_at FROM ${TABLE.clients} WHERE namespace=$1 AND client_id=$2`,
      [this.namespace, id]
    );
    return r.rows[0] ? hideLogicallyExpired(this.rowClient(r.rows[0]), this.now()) : null;
  }
  private async createClient(i: CreateClientInput): Promise<CreateResult> {
    assertCreateClientInput(i);
    const r = await this.db.query(
      `INSERT INTO ${TABLE.clients}(namespace,client_id,value,schema_version,revision,created_at,expires_at) VALUES($1,$2,$3::jsonb,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
      vals(this.namespace, i.client.value.clientId, i.client)
    );
    return r.rowCount ? { status: 'created' } : { status: 'conflict' };
  }
  private async replaceClient(i: ReplaceClientInput): Promise<ReplaceResult> {
    assertReplaceClientInput(i);
    const r = await this.db.query(
      `UPDATE ${TABLE.clients} SET value=$3::jsonb,schema_version=$4,revision=$5,created_at=$6,expires_at=$7 WHERE namespace=$1 AND client_id=$2 AND revision=$8 AND (expires_at IS NULL OR expires_at>$9)`,
      [...vals(this.namespace, i.clientId, i.client), i.expectedRevision, this.now()]
    );
    if (r.rowCount) return { status: 'updated' };
    return (await this.getClient(i.clientId)) ? { status: 'conflict' } : { status: 'not_found' };
  }
  private async deleteClient(i: {
    readonly clientId: string;
    readonly expectedRevision?: number;
  }): Promise<DeleteClientResult> {
    return this.tx(async () => {
      const q = await this.db.query<{ revision: number }>(
        `SELECT revision FROM ${TABLE.clients} WHERE namespace=$1 AND client_id=$2 FOR UPDATE`,
        [this.namespace, i.clientId]
      );
      if (!q.rows[0]) return { status: 'not_found' };
      if (i.expectedRevision !== undefined && safeInteger(q.rows[0].revision, 'client revision') !== i.expectedRevision)
        return { status: 'conflict' };
      const tc = await this.db.query<CountRow>(
        `SELECT count(*) AS count FROM ${TABLE.tokens} t JOIN ${TABLE.grants} g USING(namespace,user_id,grant_id) WHERE g.namespace=$1 AND g.registered_client_id=$2`,
        [this.namespace, i.clientId]
      );
      const gc = await this.db.query<CountRow>(
        `SELECT count(*) AS count FROM ${TABLE.grants} WHERE namespace=$1 AND registered_client_id=$2`,
        [this.namespace, i.clientId]
      );
      await this.db.query(`DELETE FROM ${TABLE.clients} WHERE namespace=$1 AND client_id=$2`, [
        this.namespace,
        i.clientId,
      ]);
      return { status: 'deleted', deletedGrants: num(gc.rows[0]?.count), deletedAccessTokens: num(tc.rows[0]?.count) };
    });
  }
  private listClients(p?: PageRequest) {
    return this.list<StoredClient>(TABLE.clients, 'client_id', [], p, (r) => this.rowClient(r));
  }
  private async getGrant(k: GrantKey) {
    const r = await this.db.query<Row>(
      `SELECT value,schema_version,revision,created_at,expires_at FROM ${TABLE.grants} WHERE namespace=$1 AND user_id=$2 AND grant_id=$3`,
      [this.namespace, k.userId, k.grantId]
    );
    return r.rows[0] ? hideLogicallyExpired(this.rowGrant(r.rows[0]), this.now()) : null;
  }
  private async issueGrant(i: IssueGrantInput): Promise<IssueGrantResult> {
    assertIssueGrantInput(i);
    return this.tx(async () => {
      if (i.client.kind === 'registered') {
        const c = await this.db.query<{ revision: number }>(
          `SELECT revision FROM ${TABLE.clients} WHERE namespace=$1 AND client_id=$2 AND (expires_at IS NULL OR expires_at>$3) FOR UPDATE`,
          [this.namespace, i.client.clientId, this.now()]
        );
        if (!c.rows[0]) return { status: 'client_not_found' };
        if (safeInteger(c.rows[0].revision, 'client revision') !== i.client.expectedRevision)
          return { status: 'client_conflict' };
      }
      const g = await this.db.query(
        `INSERT INTO ${TABLE.grants}(namespace,user_id,grant_id,client_id,registered_client_id,value,schema_version,revision,created_at,expires_at,transition_fence) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,0) ON CONFLICT DO NOTHING`,
        [
          this.namespace,
          i.grant.value.userId,
          i.grant.value.id,
          i.grant.value.clientId,
          i.client.kind === 'registered' ? i.grant.value.clientId : null,
          JSON.stringify(i.grant.value),
          i.grant.metadata.schemaVersion,
          i.grant.metadata.revision,
          i.grant.metadata.createdAt,
          i.grant.metadata.expiresAt ?? null,
        ]
      );
      if (!g.rowCount) return { status: 'conflict' };
      if (i.accessToken) await this.insertToken(i.accessToken);
      if (i.replaceExistingUserClientGrants)
        await this.db.query(
          `DELETE FROM ${TABLE.grants} WHERE namespace=$1 AND user_id=$2 AND client_id=$3 AND grant_id<>$4`,
          [this.namespace, i.grant.value.userId, i.grant.value.clientId, i.grant.value.id]
        );
      return { status: 'created' };
    });
  }
  private async listGrants(column: 'user_id' | 'client_id', value: string, p?: PageRequest) {
    if (column === 'user_id') {
      return this.list<StoredGrant>(TABLE.grants, 'grant_id', ['user_id=$2', value], p, (r) => this.rowGrant(r));
    }
    const request = createPageRequest(p);
    const limit = request.limit ?? 100;
    const cursor = decodeTupleCursor(request.cursor);
    const values: unknown[] = [this.namespace, value, this.now()];
    const after = cursor ? ` AND (user_id,grant_id)>($${values.push(cursor[0])},$${values.push(cursor[1])})` : '';
    values.push(limit + 1);
    const result = await this.db.query<Row & { page_user: string; page_grant: string }>(
      `SELECT value,schema_version,revision,created_at,expires_at,user_id AS page_user,grant_id AS page_grant FROM ${TABLE.grants} WHERE namespace=$1 AND client_id=$2 AND (expires_at IS NULL OR expires_at>$3)${after} ORDER BY user_id,grant_id LIMIT $${values.length}`,
      values
    );
    const rows = result.rows.slice(0, limit);
    const last = rows[rows.length - 1];
    return createPage(
      rows.map((row) => this.rowGrant(row)),
      result.rows.length > limit && last ? encodeTupleCursor([last.page_user, last.page_grant]) : undefined
    );
  }
  private async begin(i: BeginGrantTransitionInput): Promise<BeginGrantTransitionResult> {
    assertBeginGrantTransitionInput(i);
    return this.tx(async () => {
      const q = await this.db.query<GrantTransitionRow>(
        `SELECT value,schema_version,revision,created_at,expires_at,transition_lease_id,transition_owner_id,transition_kind,transition_credential_id,transition_callback_key,transition_lease_expires_at,transition_fence FROM ${TABLE.grants} WHERE namespace=$1 AND user_id=$2 AND grant_id=$3 FOR UPDATE`,
        [this.namespace, i.grant.userId, i.grant.grantId]
      );
      if (!q.rows[0]) return { status: 'not_found' };
      const row = q.rows[0],
        grant = this.rowGrant(row);
      if (grant.metadata.expiresAt !== undefined && grant.metadata.expiresAt <= i.now) return { status: 'expired' };
      const activeLeaseExpiry =
        row.transition_lease_expires_at === null
          ? undefined
          : safeInteger(row.transition_lease_expires_at, 'transition lease expiry');
      if (row.transition_lease_id && activeLeaseExpiry !== undefined && activeLeaseExpiry > i.now) {
        return { status: 'busy', retryAfterSeconds: Math.max(1, activeLeaseExpiry - i.now) };
      }
      if (i.kind === 'authorization_code') {
        if (grant.value.authCodeId !== i.credentialId) return { status: 'invalid_credential' };
        if (grant.value.authCodeWrappedKey === undefined) return { status: 'already_consumed' };
      } else {
        const current = grant.value.refreshTokenId === i.credentialId,
          previous = grant.value.previousRefreshTokenId === i.credentialId;
        if (!current && !previous) return { status: 'invalid_credential' };
        if (
          (current && grant.value.refreshTokenWrappedKey === undefined) ||
          (previous && grant.value.previousRefreshTokenWrappedKey === undefined)
        )
          return { status: 'already_consumed' };
      }
      const fence = safeInteger(row.transition_fence, 'transition fence') + 1,
        id = this.randomId(),
        expires = i.now + i.leaseTtlSeconds;
      await this.db.query(
        `UPDATE ${TABLE.grants} SET transition_lease_id=$4,transition_owner_id=$5,transition_kind=$6,transition_credential_id=$7,transition_callback_key=$8,transition_lease_expires_at=$9,transition_fence=$10 WHERE namespace=$1 AND user_id=$2 AND grant_id=$3`,
        [
          this.namespace,
          i.grant.userId,
          i.grant.grantId,
          id,
          i.ownerId,
          i.kind,
          i.credentialId,
          i.callbackIdempotencyKey,
          expires,
          fence,
        ]
      );
      const lease = createGrantTransitionLease(
        {
          id: transitionLeaseId(id),
          grant: i.grant,
          kind: i.kind,
          credentialId: i.credentialId,
          ownerId: i.ownerId,
          fence,
          expectedRevision: grant.metadata.revision,
          expiresAt: expires,
          callbackIdempotencyKey: i.callbackIdempotencyKey,
        },
        i.now,
        i.leaseTtlSeconds
      );
      return validateBeginGrantTransitionResult(i, { status: 'acquired', grant, lease }, i.leaseTtlSeconds);
    });
  }
  private async commit(i: ValidatedCommitGrantTransitionInput): Promise<CommitGrantTransitionResult> {
    assertCommitGrantTransitionInput(i);
    return this.tx(async () => {
      const q = await this.db.query<GrantTransitionRow>(
        `SELECT value,schema_version,revision,created_at,expires_at,transition_lease_id,transition_owner_id,transition_kind,transition_credential_id,transition_callback_key,transition_lease_expires_at,transition_fence FROM ${TABLE.grants} WHERE namespace=$1 AND user_id=$2 AND grant_id=$3 FOR UPDATE`,
        [this.namespace, i.lease.grant.userId, i.lease.grant.grantId]
      );
      if (!q.rows[0]) return { status: 'not_found' };
      const r = q.rows[0];
      if (r.expires_at !== null && safeInteger(r.expires_at, 'grant expiry') <= i.now) return { status: 'expired' };
      if (
        r.transition_lease_id !== i.lease.id ||
        r.transition_owner_id !== i.lease.ownerId ||
        r.transition_kind !== i.lease.kind ||
        r.transition_credential_id !== i.lease.credentialId ||
        r.transition_callback_key !== i.lease.callbackIdempotencyKey ||
        safeInteger(r.transition_fence, 'transition fence') !== i.lease.fence ||
        safeInteger(r.transition_lease_expires_at, 'transition lease expiry') !== i.lease.expiresAt ||
        safeInteger(r.transition_lease_expires_at, 'transition lease expiry') <= i.now
      )
        return { status: 'lease_lost' };
      if (safeInteger(r.revision, 'grant revision') !== i.lease.expectedRevision) return { status: 'conflict' };
      const updated = await this.db.query(
        `UPDATE ${TABLE.grants} SET client_id=$4,value=$5::jsonb,schema_version=$6,revision=$7,created_at=$8,expires_at=$9,transition_lease_id=NULL,transition_owner_id=NULL,transition_kind=NULL,transition_credential_id=NULL,transition_callback_key=NULL,transition_lease_expires_at=NULL WHERE namespace=$1 AND user_id=$2 AND grant_id=$3 AND revision=$10 AND transition_lease_id=$11 AND transition_owner_id=$12 AND transition_kind=$13 AND transition_credential_id=$14 AND transition_callback_key=$15 AND transition_lease_expires_at=$16 AND transition_fence=$17`,
        [
          this.namespace,
          i.grant.value.userId,
          i.grant.value.id,
          i.grant.value.clientId,
          JSON.stringify(i.grant.value),
          i.grant.metadata.schemaVersion,
          i.grant.metadata.revision,
          i.grant.metadata.createdAt,
          i.grant.metadata.expiresAt ?? null,
          i.lease.expectedRevision,
          i.lease.id,
          i.lease.ownerId,
          i.lease.kind,
          i.lease.credentialId,
          i.lease.callbackIdempotencyKey,
          i.lease.expiresAt,
          i.lease.fence,
        ]
      );
      if (!updated.rowCount) return { status: 'lease_lost' };
      await this.insertToken(i.accessToken);
      return { status: 'committed' };
    });
  }
  private async abort(i: AbortGrantTransitionInput): Promise<AbortGrantTransitionResult> {
    const r = await this.db.query(
      `UPDATE ${TABLE.grants} SET transition_lease_id=NULL,transition_owner_id=NULL,transition_kind=NULL,transition_credential_id=NULL,transition_callback_key=NULL,transition_lease_expires_at=NULL WHERE namespace=$1 AND user_id=$2 AND grant_id=$3 AND transition_lease_id=$4 AND transition_fence=$5`,
      [this.namespace, i.lease.grant.userId, i.lease.grant.grantId, i.lease.id, i.lease.fence]
    );
    if (r.rowCount) return { status: 'aborted' };
    return (await this.getGrant(i.lease.grant)) ? { status: 'lease_lost' } : { status: 'not_found' };
  }
  private async revoke(k: GrantKey, revision?: number): Promise<RevokeGrantResult> {
    return this.tx(async () => {
      const q = await this.db.query<{ revision: number }>(
        `SELECT revision FROM ${TABLE.grants} WHERE namespace=$1 AND user_id=$2 AND grant_id=$3 FOR UPDATE`,
        [this.namespace, k.userId, k.grantId]
      );
      if (!q.rows[0]) return { status: 'not_found' };
      if (revision !== undefined && safeInteger(q.rows[0].revision, 'grant revision') !== revision)
        return { status: 'conflict' };
      const c = await this.db.query<CountRow>(
        `SELECT count(*) AS count FROM ${TABLE.tokens} WHERE namespace=$1 AND user_id=$2 AND grant_id=$3`,
        [this.namespace, k.userId, k.grantId]
      );
      await this.db.query(`DELETE FROM ${TABLE.grants} WHERE namespace=$1 AND user_id=$2 AND grant_id=$3`, [
        this.namespace,
        k.userId,
        k.grantId,
      ]);
      return { status: 'revoked', deletedAccessTokens: num(c.rows[0]?.count) };
    });
  }
  private async getToken(k: AccessTokenKey) {
    const q = await this.db.query<Row>(
      `SELECT value,schema_version,revision,created_at,expires_at FROM ${TABLE.tokens} WHERE namespace=$1 AND user_id=$2 AND grant_id=$3 AND token_id=$4`,
      [this.namespace, k.userId, k.grantId, k.tokenId]
    );
    return q.rows[0] ? hideLogicallyExpired(this.rowToken(q.rows[0]), this.now()) : null;
  }
  private insertToken(t: StoredAccessToken) {
    return this.db.query(
      `INSERT INTO ${TABLE.tokens}(namespace,user_id,grant_id,token_id,value,schema_version,revision,created_at,expires_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`,
      [
        this.namespace,
        t.value.userId,
        t.value.grantId,
        t.value.id,
        JSON.stringify(t.value),
        t.metadata.schemaVersion,
        t.metadata.revision,
        t.metadata.createdAt,
        t.metadata.expiresAt ?? null,
      ]
    );
  }
  private async createToken(i: IssueAccessTokenInput): Promise<IssueAccessTokenResult> {
    assertIssueAccessTokenInput(i);
    return this.tx(async () => {
      const g = await this.db.query<{ revision: number }>(
        `SELECT revision FROM ${TABLE.grants} WHERE namespace=$1 AND user_id=$2 AND grant_id=$3 AND (expires_at IS NULL OR expires_at>$4) FOR UPDATE`,
        [this.namespace, i.grant.userId, i.grant.grantId, this.now()]
      );
      if (!g.rows[0]) return { status: 'grant_not_found' };
      if (safeInteger(g.rows[0].revision, 'grant revision') !== i.expectedGrantRevision)
        return { status: 'grant_conflict' };
      try {
        await this.insertToken(i.token);
      } catch (e) {
        if (isUnique(e)) return { status: 'conflict' };
        throw e;
      }
      return { status: 'created' };
    });
  }
  private async deleteToken(k: AccessTokenKey): Promise<DeleteResult> {
    const r = await this.db.query(
      `DELETE FROM ${TABLE.tokens} WHERE namespace=$1 AND user_id=$2 AND grant_id=$3 AND token_id=$4`,
      [this.namespace, k.userId, k.grantId, k.tokenId]
    );
    return r.rowCount ? { status: 'deleted' } : { status: 'not_found' };
  }
  private listTokens(k: GrantKey, p?: PageRequest) {
    return this.list<StoredAccessToken>(
      TABLE.tokens,
      'token_id',
      ['user_id=$2 AND grant_id=$3', k.userId, k.grantId],
      p,
      (r) => this.rowToken(r)
    );
  }
  private async getConsent(i: { userId: string; clientId: string; referenceId?: string }) {
    const q = await this.db.query<Row>(
      `SELECT value,schema_version,revision,created_at,expires_at FROM ${TABLE.consents} WHERE namespace=$1 AND user_id=$2 AND client_id=$3 AND reference_id=$4`,
      [this.namespace, i.userId, i.clientId, i.referenceId ?? '']
    );
    return q.rows[0] ? hideLogicallyExpired(this.rowConsent(q.rows[0]), this.now()) : null;
  }
  private async casConsent(i: CompareAndSwapConsentInput): Promise<ReplaceConsentResult> {
    const c = i.consent,
      ref = c.value.referenceId ?? '';
    if (i.expectedRevision === undefined) {
      const r = await this.db.query(
        `INSERT INTO ${TABLE.consents}(namespace,user_id,client_id,reference_id,value,schema_version,revision,created_at,expires_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
        [
          this.namespace,
          c.value.userId,
          c.value.clientId,
          ref,
          JSON.stringify(c.value),
          c.metadata.schemaVersion,
          c.metadata.revision,
          c.metadata.createdAt,
          c.metadata.expiresAt ?? null,
        ]
      );
      return r.rowCount ? { status: 'created' } : { status: 'conflict' };
    }
    const r = await this.db.query(
      `UPDATE ${TABLE.consents} SET value=$5::jsonb,schema_version=$6,revision=$7,created_at=$8,expires_at=$9 WHERE namespace=$1 AND user_id=$2 AND client_id=$3 AND reference_id=$4 AND revision=$10`,
      [
        this.namespace,
        c.value.userId,
        c.value.clientId,
        ref,
        JSON.stringify(c.value),
        c.metadata.schemaVersion,
        c.metadata.revision,
        c.metadata.createdAt,
        c.metadata.expiresAt ?? null,
        i.expectedRevision,
      ]
    );
    return r.rowCount ? { status: 'updated' } : { status: 'conflict' };
  }
  private async deleteConsent(i: {
    userId: string;
    clientId: string;
    referenceId?: string;
    expectedRevision?: number;
  }): Promise<DeleteResult> {
    const r = await this.db.query(
      `DELETE FROM ${TABLE.consents} WHERE namespace=$1 AND user_id=$2 AND client_id=$3 AND reference_id=$4${i.expectedRevision === undefined ? '' : ' AND revision=$5'}`,
      [
        this.namespace,
        i.userId,
        i.clientId,
        i.referenceId ?? '',
        ...(i.expectedRevision === undefined ? [] : [i.expectedRevision]),
      ]
    );
    if (r.rowCount) return { status: 'deleted' };
    return (await this.getConsent(i)) ? { status: 'conflict' } : { status: 'not_found' };
  }
  private async listConsents(user: string, p?: PageRequest) {
    const request = createPageRequest(p);
    const limit = request.limit ?? 100;
    const cursor = decodeTupleCursor(request.cursor);
    const values: unknown[] = [this.namespace, user, this.now()];
    const after = cursor ? ` AND (client_id,reference_id)>($${values.push(cursor[0])},$${values.push(cursor[1])})` : '';
    values.push(limit + 1);
    const result = await this.db.query<Row & { page_client: string; page_reference: string }>(
      `SELECT value,schema_version,revision,created_at,expires_at,client_id AS page_client,reference_id AS page_reference FROM ${TABLE.consents} WHERE namespace=$1 AND user_id=$2 AND (expires_at IS NULL OR expires_at>$3)${after} ORDER BY client_id,reference_id LIMIT $${values.length}`,
      values
    );
    const rows = result.rows.slice(0, limit);
    const last = rows[rows.length - 1];
    return createPage(
      rows.map((row) => this.rowConsent(row)),
      result.rows.length > limit && last ? encodeTupleCursor([last.page_client, last.page_reference]) : undefined
    );
  }
  private async reserve(i: {
    reservationNamespace: string;
    keyHash: CredentialId;
    expiresAt: number;
  }): Promise<ReplayReservationResult> {
    credentialIdFromSha256(i.keyHash);
    const now = this.now();
    if (i.expiresAt <= now) throw new OAuthStorageError('conflict', { operation: 'replay.reserve' });
    const r = await this.db.query(
      `INSERT INTO ${TABLE.replay}(namespace,reservation_namespace,key_hash,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(namespace,reservation_namespace,key_hash) DO UPDATE SET expires_at=EXCLUDED.expires_at WHERE ${TABLE.replay}.expires_at<=$5`,
      [this.namespace, i.reservationNamespace, i.keyHash, i.expiresAt, now]
    );
    return r.rowCount ? { status: 'reserved' } : { status: 'exists' };
  }
  private async purge(i: PurgeStorageInput): Promise<PurgeStorageResult> {
    if (!Number.isSafeInteger(i.limit) || i.limit < 1) throw new TypeError('Purge limit must be positive');
    return this.tx(async () => {
      let gp = 0,
        tp = 0,
        gc = 0,
        tc = 0;
      if (i.purgeExpiredGrants) {
        const r = await this.db.query(
          `DELETE FROM ${TABLE.grants} WHERE ctid IN (SELECT ctid FROM ${TABLE.grants} WHERE namespace=$1 AND expires_at<=$2 LIMIT $3 FOR UPDATE SKIP LOCKED)`,
          [this.namespace, i.now, i.limit]
        );
        gp = r.rowCount;
        gc = r.rowCount;
      }
      if (i.purgeOrphanedTokens && gp < i.limit) {
        const r = await this.db.query(
          `DELETE FROM ${TABLE.tokens} t WHERE ctid IN (SELECT t.ctid FROM ${TABLE.tokens} t LEFT JOIN ${TABLE.grants} g USING(namespace,user_id,grant_id) WHERE t.namespace=$1 AND g.grant_id IS NULL LIMIT $2 FOR UPDATE OF t SKIP LOCKED)`,
          [this.namespace, i.limit - gp]
        );
        tp = r.rowCount;
        tc = r.rowCount;
      }
      await this.db.query(`DELETE FROM ${TABLE.replay} WHERE namespace=$1 AND expires_at<=$2`, [this.namespace, i.now]);
      return { grantsChecked: gc, grantsPurged: gp, tokensChecked: tc, tokensPurged: tp, done: gp + tp < i.limit };
    });
  }
  private async list<T>(
    table: string,
    order: string,
    filter: readonly unknown[],
    p: PageRequest | undefined,
    decode: (r: Row) => T
  ): Promise<Page<T>> {
    const req = createPageRequest(p),
      limit = req.limit ?? 100,
      cursor = decodeCursor(req.cursor),
      conditions = ['namespace=$1'];
    if (filter.length) conditions.push(String(filter[0]));
    const values = [this.namespace, ...filter.slice(1)];
    values.push(this.now());
    conditions.push(`(expires_at IS NULL OR expires_at>$${values.length})`);
    if (cursor !== undefined) {
      values.push(cursor);
      conditions.push(`${order}>$${values.length}`);
    }
    values.push(limit + 1);
    const q = await this.db.query<Row & { page_key: string }>(
      `SELECT value,schema_version,revision,created_at,expires_at,${order} AS page_key FROM ${table} WHERE ${conditions.join(' AND ')} ORDER BY ${order} ASC LIMIT $${values.length}`,
      values
    );
    const rows = q.rows.slice(0, limit);
    return createPage(
      rows.map(decode),
      q.rows.length > limit ? encodeCursor(String(rows[rows.length - 1].page_key)) : undefined
    );
  }
}
function vals(
  ns: string,
  id: string,
  r: { value: unknown; metadata: { schemaVersion: number; revision: number; createdAt: number; expiresAt?: number } }
) {
  return [
    ns,
    id,
    JSON.stringify(r.value),
    r.metadata.schemaVersion,
    r.metadata.revision,
    r.metadata.createdAt,
    r.metadata.expiresAt ?? null,
  ] as const;
}
function meta(r: Row) {
  return {
    schemaVersion: safeInteger(r.schema_version, 'schema version'),
    revision: safeInteger(r.revision, 'record revision'),
    createdAt: safeInteger(r.created_at, 'record creation'),
    ...(r.expires_at === null ? {} : { expiresAt: safeInteger(r.expires_at, 'record expiry') }),
  };
}
function num(v: number | string | undefined) {
  return v === undefined ? 0 : safeInteger(v, 'count');
}
function safeInteger(value: unknown, field: string): number {
  try {
    if (typeof value === 'number') {
      if (Number.isSafeInteger(value)) return value;
      throw new Error(field);
    }
    if (typeof value === 'string' && /^-?\d+$/.test(value)) {
      const integer = BigInt(value);
      if (integer >= BigInt(Number.MIN_SAFE_INTEGER) && integer <= BigInt(Number.MAX_SAFE_INTEGER)) {
        return Number(integer);
      }
    }
  } catch (error) {
    if (isOAuthStorageError(error)) throw error;
  }
  throw new OAuthStorageError('schema_mismatch', { operation: 'storage.decode' });
}
function encodeCursor(v: string) {
  return btoa(unescape(encodeURIComponent(v)));
}
function decodeCursor(v?: string) {
  if (v === undefined) return undefined;
  try {
    return decodeURIComponent(escape(atob(v)));
  } catch {
    throw new TypeError('Invalid PostgreSQL page cursor');
  }
}
function encodeTupleCursor(value: readonly [string, string]): string {
  return encodeCursor(JSON.stringify(value));
}
function decodeTupleCursor(value?: string): [string, string] | undefined {
  const decoded = decodeCursor(value);
  if (decoded === undefined) return undefined;
  try {
    const parsed = JSON.parse(decoded) as unknown;
    if (
      !Array.isArray(parsed) ||
      parsed.length !== 2 ||
      typeof parsed[0] !== 'string' ||
      typeof parsed[1] !== 'string'
    ) {
      throw new TypeError('Invalid PostgreSQL tuple cursor');
    }
    return [parsed[0], parsed[1]];
  } catch {
    throw new TypeError('Invalid PostgreSQL tuple cursor');
  }
}
function isUnique(e: unknown) {
  return typeof e === 'object' && e !== null && 'code' in e && (e as { code: unknown }).code === '23505';
}
