import { defineOAuthStorageCapabilities, type OAuthStorageCapabilities } from '../capabilities';
import { OAuthStorageError, isOAuthStorageError, unsupportedStorageOperation } from '../errors';
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
  type AccessTokenKey,
  type GrantKey,
  type StoredAccessToken,
  type StoredClient,
  type StoredConsent,
  type StoredGrant,
  type StorageMetadata,
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
  assertCompareAndSwapConsentInput,
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
  AbortGrantTransitionResult,
  BeginGrantTransitionInput,
  BeginGrantTransitionResult,
  CommitGrantTransitionResult,
  ValidatedCommitGrantTransitionInput,
} from '../transitions';

export const D1_STORAGE_CAPABILITIES: OAuthStorageCapabilities = defineOAuthStorageCapabilities({
  consistency: { readAfterWrite: 'session' },
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
    listClients: 'session',
    grantsByUser: 'session',
    grantsByClient: 'session',
    tokensByGrant: 'session',
    consentsByUser: 'session',
    globalMaintenance: 'session',
  },
  expiration: { cleanup: 'manual', minimumTtlSeconds: 0 },
});

export interface D1StorageOptions<Env> {
  readonly binding: (env: Env) => D1Database;
  readonly namespace?: string;
  readonly now?: () => number;
}

export function d1Storage<Env>(options: D1StorageOptions<Env>): OAuthStorageProvider<Env> {
  if (!options || typeof options.binding !== 'function') throw new TypeError('D1 storage requires a binding resolver');
  if (options.now !== undefined && typeof options.now !== 'function')
    throw new TypeError('D1 storage clock must be a function');
  const namespace = defineStorageNamespace(options.namespace);
  const clock = options.now ?? (() => Math.floor(Date.now() / 1000));
  return Object.freeze({
    id: 'd1',
    contractVersion: 1 as const,
    namespace,
    capabilities: D1_STORAGE_CAPABILITIES,
    open(context: OAuthStorageOpenContext<Env>): OAuthStorageConnection {
      if (context.namespace !== namespace)
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      let database: D1Database;
      try {
        database = options.binding(context.env);
      } catch (cause) {
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open', cause });
      }
      if (!database || typeof database.prepare !== 'function' || typeof database.batch !== 'function') {
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      }
      return new D1Connection(database, namespace, clock);
    },
  });
}

type Row = { value_json: string; revision: number; created_at: number; expires_at: number | null };
const REF_NONE = '';

class D1Connection implements OAuthStorageConnection {
  readonly clients: OAuthClientStore;
  readonly grants: OAuthGrantStore;
  readonly accessTokens: OAuthAccessTokenStore;
  readonly consents: OAuthConsentStore;
  readonly replay: OAuthReplayStore;
  readonly maintenance: OAuthMaintenanceStore;
  #closed = false;

  constructor(
    private readonly db: D1Database,
    readonly namespace: string,
    private readonly clock: () => number
  ) {
    this.clients = Object.freeze<OAuthClientStore>({
      get: (id) => this.run('clients.get', () => this.getClient(id)),
      create: (input) => this.run('clients.create', () => this.createClient(input)),
      replace: (input) => this.run('clients.replace', () => this.replaceClient(input)),
      deleteWithGrants: (input) => this.run('clients.deleteWithGrants', () => this.deleteClient(input)),
      list: (input) => this.run('clients.list', () => this.listClients(input)),
    });
    this.grants = Object.freeze<OAuthGrantStore>({
      get: (key) => this.run('grants.get', () => this.getGrant(key)),
      issue: (input) => this.run('grants.issue', () => this.issueGrant(input)),
      listByUser: (input) =>
        this.run('grants.listByUser', () => this.listGrants('user_id = ?', input.userId, input.page)),
      listByClient: (input) =>
        this.run('grants.listByClient', () => this.listGrants('client_id = ?', input.clientId, input.page)),
      beginTransition: (input) => this.run('grants.beginTransition', () => this.beginTransition(input)),
      commitTransition: (input) => this.run('grants.commitTransition', () => this.commitTransition(input)),
      abortTransition: (input) => this.run('grants.abortTransition', () => this.abortTransition(input)),
      revoke: (input) => this.run('grants.revoke', () => this.revokeGrant(input.grant, input.expectedRevision)),
    });
    this.accessTokens = Object.freeze<OAuthAccessTokenStore>({
      get: (key) => this.run('accessTokens.get', () => this.getToken(key)),
      createForGrant: (input) => this.run('accessTokens.createForGrant', () => this.createToken(input)),
      delete: (input) => this.run('accessTokens.delete', () => this.deleteToken(input.key)),
      listByGrant: (input) => this.run('accessTokens.listByGrant', () => this.listTokens(input.grant, input.page)),
    });
    this.consents = Object.freeze<OAuthConsentStore>({
      get: (input) => this.run('consents.get', () => this.getConsent(input)),
      compareAndSwap: (input) => this.run('consents.compareAndSwap', () => this.casConsent(input)),
      delete: (input) => this.run('consents.delete', () => this.deleteConsent(input)),
      listByUser: (input) => this.run('consents.listByUser', () => this.listConsents(input.userId, input.page)),
    });
    this.replay = Object.freeze<OAuthReplayStore>({
      reserve: (input) => this.run('replay.reserve', () => this.reserve(input)),
    });
    this.maintenance = Object.freeze<OAuthMaintenanceStore>({
      purge: (input) => this.run('maintenance.purge', () => this.purge(input)),
    });
  }

  close(): void {
    this.#closed = true;
  }
  private now(): number {
    return Math.floor(this.clock());
  }
  private metadata(row: Row): StorageMetadata {
    return {
      schemaVersion: 1,
      revision: row.revision,
      createdAt: row.created_at,
      ...(row.expires_at === null ? {} : { expiresAt: row.expires_at }),
    };
  }
  private async first(sql: string, ...bindings: unknown[]): Promise<Row | null> {
    return this.db
      .prepare(sql)
      .bind(...bindings)
      .first<Row>();
  }
  private stmt(sql: string, ...bindings: unknown[]): D1PreparedStatement {
    return this.db.prepare(sql).bind(...bindings);
  }
  private expired(row: Row | StorageMetadata, now = this.now()): boolean {
    const expiresAt = 'expires_at' in row ? row.expires_at : row.expiresAt;
    return expiresAt !== null && expiresAt !== undefined && expiresAt <= now;
  }
  private changes(result: D1Result): number {
    return Number(result.meta.changes ?? 0);
  }

  private decodeClient(row: Row): StoredClient {
    return createStoredClient(JSON.parse(row.value_json), this.metadata(row));
  }
  private decodeGrant(row: Row): StoredGrant {
    return createStoredGrant(JSON.parse(row.value_json), this.metadata(row));
  }
  private decodeToken(row: Row): StoredAccessToken {
    const value = JSON.parse(row.value_json);
    value.id = credentialIdFromSha256(value.id);
    return createStoredAccessToken(value, this.metadata(row));
  }
  private decodeConsent(row: Row): StoredConsent {
    return createStoredConsent(JSON.parse(row.value_json), this.metadata(row));
  }
  private values(record: StoredClient | StoredGrant | StoredAccessToken | StoredConsent): unknown[] {
    return [
      record.metadata.revision,
      record.metadata.createdAt,
      record.metadata.expiresAt ?? null,
      JSON.stringify(record.value),
    ];
  }

  private async getClient(id: string): Promise<StoredClient | null> {
    const row = await this.first(
      `SELECT value_json,revision,created_at,expires_at FROM oauth_clients WHERE namespace=? AND client_id=?`,
      this.namespace,
      id
    );
    return !row || this.expired(row) ? null : this.decodeClient(row);
  }
  private async createClient(input: CreateClientInput): Promise<CreateResult> {
    assertCreateClientInput(input);
    const r = await this.stmt(
      `INSERT OR IGNORE INTO oauth_clients(namespace,client_id,revision,created_at,expires_at,value_json) VALUES(?,?,?,?,?,?)`,
      this.namespace,
      input.client.value.clientId,
      ...this.values(input.client)
    ).run();
    return { status: this.changes(r) === 1 ? 'created' : 'conflict' };
  }
  private async replaceClient(input: ReplaceClientInput): Promise<ReplaceResult> {
    assertReplaceClientInput(input);
    const r = await this.stmt(
      `UPDATE oauth_clients SET revision=?,created_at=?,expires_at=?,value_json=? WHERE namespace=? AND client_id=? AND revision=? AND (expires_at IS NULL OR expires_at>?)`,
      ...this.values(input.client),
      this.namespace,
      input.clientId,
      input.expectedRevision,
      this.now()
    ).run();
    if (this.changes(r)) return { status: 'updated' };
    return (await this.getClient(input.clientId)) ? { status: 'conflict' } : { status: 'not_found' };
  }
  private async deleteClient(input: { clientId: string; expectedRevision?: number }): Promise<DeleteClientResult> {
    const current = await this.getClient(input.clientId);
    if (!current) return { status: 'not_found' };
    if (input.expectedRevision !== undefined && current.metadata.revision !== input.expectedRevision)
      return { status: 'conflict' };
    const guard = `EXISTS(SELECT 1 FROM oauth_clients c WHERE c.namespace=? AND c.client_id=? AND c.revision=?)`;
    const guardBindings = [this.namespace, input.clientId, current.metadata.revision];
    const results = await this.db.batch([
      this.stmt(
        `DELETE FROM oauth_access_tokens WHERE namespace=? AND ${guard} AND EXISTS(SELECT 1 FROM oauth_grants g WHERE g.namespace=oauth_access_tokens.namespace AND g.user_id=oauth_access_tokens.user_id AND g.grant_id=oauth_access_tokens.grant_id AND g.client_id=?)`,
        this.namespace,
        ...guardBindings,
        input.clientId
      ),
      this.stmt(
        `DELETE FROM oauth_transition_leases WHERE namespace=? AND ${guard} AND EXISTS(SELECT 1 FROM oauth_grants g WHERE g.namespace=oauth_transition_leases.namespace AND g.user_id=oauth_transition_leases.user_id AND g.grant_id=oauth_transition_leases.grant_id AND g.client_id=?)`,
        this.namespace,
        ...guardBindings,
        input.clientId
      ),
      this.stmt(
        `DELETE FROM oauth_grants WHERE namespace=? AND client_id=? AND ${guard}`,
        this.namespace,
        input.clientId,
        ...guardBindings
      ),
      this.stmt(
        `DELETE FROM oauth_clients WHERE namespace=? AND client_id=? AND revision=?`,
        this.namespace,
        input.clientId,
        current.metadata.revision
      ),
    ]);
    if (this.changes(results[3]!) !== 1) {
      return (await this.getClient(input.clientId)) ? { status: 'conflict' } : { status: 'not_found' };
    }
    return {
      status: 'deleted',
      deletedGrants: this.changes(results[2]!),
      deletedAccessTokens: this.changes(results[0]!),
    };
  }
  private listClients(input: PageRequest = {}): Promise<Page<StoredClient>> {
    return this.list(
      `SELECT value_json,revision,created_at,expires_at,client_id AS cursor_key FROM oauth_clients WHERE namespace=? AND (expires_at IS NULL OR expires_at>?) AND client_id>? ORDER BY client_id LIMIT ?`,
      [this.namespace, this.now()],
      input,
      (r) => this.decodeClient(r)
    );
  }

  private async getGrant(key: GrantKey): Promise<StoredGrant | null> {
    const grant = await this.getGrantRaw(key);
    return grant && !this.expired(grant.metadata) ? grant : null;
  }
  private async getGrantRaw(key: GrantKey): Promise<StoredGrant | null> {
    const row = await this.first(
      `SELECT value_json,revision,created_at,expires_at FROM oauth_grants WHERE namespace=? AND user_id=? AND grant_id=?`,
      this.namespace,
      key.userId,
      key.grantId
    );
    return row ? this.decodeGrant(row) : null;
  }
  private async issueGrant(input: IssueGrantInput): Promise<IssueGrantResult> {
    assertIssueGrantInput(input);
    const g = input.grant;
    const issueMarker = crypto.randomUUID();
    const clientGuard =
      input.client.kind === 'registered'
        ? `EXISTS(SELECT 1 FROM oauth_clients WHERE namespace=? AND client_id=? AND revision=? AND (expires_at IS NULL OR expires_at>?))`
        : '1';
    const clientBindings =
      input.client.kind === 'registered'
        ? [this.namespace, input.client.clientId, input.client.expectedRevision, this.now()]
        : [];
    const statements = [
      this.stmt(
        `INSERT INTO oauth_grants(namespace,user_id,grant_id,client_id,client_kind,issue_marker,revision,created_at,expires_at,value_json) SELECT ?,?,?,?,?,?,?,?,?,? WHERE ${clientGuard}`,
        this.namespace,
        g.value.userId,
        g.value.id,
        g.value.clientId,
        input.client.kind,
        issueMarker,
        ...this.values(g),
        ...clientBindings
      ),
    ];
    if (input.replaceExistingUserClientGrants) {
      statements.push(
        this.stmt(
          `DELETE FROM oauth_access_tokens WHERE namespace=? AND EXISTS(SELECT 1 FROM oauth_grants issued WHERE issued.namespace=? AND issued.user_id=? AND issued.grant_id=? AND issued.issue_marker=?) AND EXISTS(SELECT 1 FROM oauth_grants prior WHERE prior.namespace=oauth_access_tokens.namespace AND prior.user_id=oauth_access_tokens.user_id AND prior.grant_id=oauth_access_tokens.grant_id AND prior.user_id=? AND prior.client_id=? AND prior.grant_id<>?)`,
          this.namespace,
          this.namespace,
          g.value.userId,
          g.value.id,
          issueMarker,
          g.value.userId,
          g.value.clientId,
          g.value.id
        ),
        this.stmt(
          `DELETE FROM oauth_transition_leases WHERE namespace=? AND EXISTS(SELECT 1 FROM oauth_grants issued WHERE issued.namespace=? AND issued.user_id=? AND issued.grant_id=? AND issued.issue_marker=?) AND user_id=? AND grant_id IN (SELECT grant_id FROM oauth_grants WHERE namespace=? AND user_id=? AND client_id=? AND grant_id<>?)`,
          this.namespace,
          this.namespace,
          g.value.userId,
          g.value.id,
          issueMarker,
          g.value.userId,
          this.namespace,
          g.value.userId,
          g.value.clientId,
          g.value.id
        ),
        this.stmt(
          `DELETE FROM oauth_grants WHERE namespace=? AND user_id=? AND client_id=? AND grant_id<>? AND EXISTS(SELECT 1 FROM oauth_grants issued WHERE issued.namespace=? AND issued.user_id=? AND issued.grant_id=? AND issued.issue_marker=?)`,
          this.namespace,
          g.value.userId,
          g.value.clientId,
          g.value.id,
          this.namespace,
          g.value.userId,
          g.value.id,
          issueMarker
        )
      );
    }
    if (input.accessToken) {
      const t = input.accessToken;
      statements.push(
        this.stmt(
          `INSERT INTO oauth_access_tokens(namespace,user_id,grant_id,token_id,revision,created_at,expires_at,value_json) SELECT ?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM oauth_grants WHERE namespace=? AND user_id=? AND grant_id=? AND revision=? AND issue_marker=?)`,
          this.namespace,
          t.value.userId,
          t.value.grantId,
          t.value.id,
          ...this.values(t),
          this.namespace,
          g.value.userId,
          g.value.id,
          g.metadata.revision,
          issueMarker
        )
      );
    }
    statements.push(
      this.stmt(
        `UPDATE oauth_grants SET issue_marker=NULL WHERE namespace=? AND user_id=? AND grant_id=? AND issue_marker=?`,
        this.namespace,
        g.value.userId,
        g.value.id,
        issueMarker
      )
    );
    let results: D1Result[];
    try {
      results = await this.db.batch(statements);
    } catch (error) {
      if (!isConstraintError(error)) throw error;
      results = [];
    }
    if (results.length > 0 && this.changes(results[0]!) === 1) {
      const tokenResult = input.accessToken ? results[results.length - 2] : undefined;
      const clearedMarker = results[results.length - 1];
      if ((!tokenResult || this.changes(tokenResult) === 1) && this.changes(clearedMarker!) === 1) {
        return { status: 'created' };
      }
    }
    if (input.client.kind === 'registered') {
      const client = await this.getClient(input.client.clientId);
      if (!client) return { status: 'client_not_found' };
      if (client.metadata.revision !== input.client.expectedRevision) return { status: 'client_conflict' };
    }
    return { status: 'conflict' };
  }
  private listGrants(predicate: string, value: string, page?: PageRequest): Promise<Page<StoredGrant>> {
    return this.list(
      `SELECT value_json,revision,created_at,expires_at,user_id||char(0)||grant_id AS cursor_key FROM oauth_grants WHERE namespace=? AND ${predicate} AND (expires_at IS NULL OR expires_at>?) AND user_id||char(0)||grant_id>? ORDER BY user_id,grant_id LIMIT ?`,
      [this.namespace, value, this.now()],
      page,
      (r) => this.decodeGrant(r)
    );
  }
  private async revokeGrant(key: GrantKey, expected?: number): Promise<RevokeGrantResult> {
    const g = await this.getGrantRaw(key);
    if (!g) return { status: 'not_found' };
    if (expected !== undefined && g.metadata.revision !== expected) return { status: 'conflict' };
    const guard = `EXISTS(SELECT 1 FROM oauth_grants g WHERE g.namespace=? AND g.user_id=? AND g.grant_id=? AND g.revision=?)`;
    const guardBindings = [this.namespace, key.userId, key.grantId, g.metadata.revision];
    const results = await this.db.batch([
      this.stmt(
        `DELETE FROM oauth_access_tokens WHERE namespace=? AND user_id=? AND grant_id=? AND ${guard}`,
        this.namespace,
        key.userId,
        key.grantId,
        ...guardBindings
      ),
      this.stmt(
        `DELETE FROM oauth_transition_leases WHERE namespace=? AND user_id=? AND grant_id=? AND ${guard}`,
        this.namespace,
        key.userId,
        key.grantId,
        ...guardBindings
      ),
      this.stmt(
        `DELETE FROM oauth_grants WHERE namespace=? AND user_id=? AND grant_id=? AND revision=?`,
        this.namespace,
        key.userId,
        key.grantId,
        g.metadata.revision
      ),
    ]);
    if (this.changes(results[2]!) !== 1) {
      return (await this.getGrant(key)) ? { status: 'conflict' } : { status: 'not_found' };
    }
    return { status: 'revoked', deletedAccessTokens: this.changes(results[0]!) };
  }

  private async getToken(key: AccessTokenKey): Promise<StoredAccessToken | null> {
    const row = await this.first(
      `SELECT value_json,revision,created_at,expires_at FROM oauth_access_tokens WHERE namespace=? AND user_id=? AND grant_id=? AND token_id=?`,
      this.namespace,
      key.userId,
      key.grantId,
      key.tokenId
    );
    return !row || this.expired(row) ? null : this.decodeToken(row);
  }
  private insertTokenStatement(t: StoredAccessToken): D1PreparedStatement {
    return this.stmt(
      `INSERT OR IGNORE INTO oauth_access_tokens(namespace,user_id,grant_id,token_id,revision,created_at,expires_at,value_json) VALUES(?,?,?,?,?,?,?,?)`,
      this.namespace,
      t.value.userId,
      t.value.grantId,
      t.value.id,
      ...this.values(t)
    );
  }
  private async createToken(input: IssueAccessTokenInput): Promise<IssueAccessTokenResult> {
    assertIssueAccessTokenInput(input);
    const t = input.token;
    const r = await this.stmt(
      `INSERT OR IGNORE INTO oauth_access_tokens(namespace,user_id,grant_id,token_id,revision,created_at,expires_at,value_json) SELECT ?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM oauth_grants WHERE namespace=? AND user_id=? AND grant_id=? AND revision=? AND (expires_at IS NULL OR expires_at>?))`,
      this.namespace,
      t.value.userId,
      t.value.grantId,
      t.value.id,
      ...this.values(t),
      this.namespace,
      input.grant.userId,
      input.grant.grantId,
      input.expectedGrantRevision,
      this.now()
    ).run();
    if (this.changes(r)) return { status: 'created' };
    const grant = await this.getGrant(input.grant);
    if (!grant) return { status: 'grant_not_found' };
    return grant.metadata.revision !== input.expectedGrantRevision
      ? { status: 'grant_conflict' }
      : { status: 'conflict' };
  }
  private async deleteToken(key: AccessTokenKey): Promise<DeleteResult> {
    const r = await this.stmt(
      `DELETE FROM oauth_access_tokens WHERE namespace=? AND user_id=? AND grant_id=? AND token_id=?`,
      this.namespace,
      key.userId,
      key.grantId,
      key.tokenId
    ).run();
    return { status: this.changes(r) ? 'deleted' : 'not_found' };
  }
  private listTokens(key: GrantKey, page?: PageRequest): Promise<Page<StoredAccessToken>> {
    return this.list(
      `SELECT value_json,revision,created_at,expires_at,token_id AS cursor_key FROM oauth_access_tokens WHERE namespace=? AND user_id=? AND grant_id=? AND (expires_at IS NULL OR expires_at>?) AND token_id>? ORDER BY token_id LIMIT ?`,
      [this.namespace, key.userId, key.grantId, this.now()],
      page,
      (r) => this.decodeToken(r)
    );
  }

  private async getConsent(input: {
    userId: string;
    clientId: string;
    referenceId?: string;
  }): Promise<StoredConsent | null> {
    const row = await this.first(
      `SELECT value_json,revision,created_at,expires_at FROM oauth_consents WHERE namespace=? AND user_id=? AND client_id=? AND reference_id=?`,
      this.namespace,
      input.userId,
      input.clientId,
      input.referenceId ?? REF_NONE
    );
    return !row || this.expired(row) ? null : this.decodeConsent(row);
  }
  private async casConsent(input: CompareAndSwapConsentInput): Promise<ReplaceConsentResult> {
    assertCompareAndSwapConsentInput(input);
    const c = input.consent;
    const ref = c.value.referenceId ?? REF_NONE;
    if (input.expectedRevision === undefined) {
      const r = await this.stmt(
        `INSERT OR IGNORE INTO oauth_consents(namespace,user_id,client_id,reference_id,revision,created_at,expires_at,value_json) VALUES(?,?,?,?,?,?,?,?)`,
        this.namespace,
        c.value.userId,
        c.value.clientId,
        ref,
        ...this.values(c)
      ).run();
      return { status: this.changes(r) ? 'created' : 'conflict' };
    }
    const r = await this.stmt(
      `UPDATE oauth_consents SET revision=?,created_at=?,expires_at=?,value_json=? WHERE namespace=? AND user_id=? AND client_id=? AND reference_id=? AND revision=? AND (expires_at IS NULL OR expires_at>?)`,
      ...this.values(c),
      this.namespace,
      c.value.userId,
      c.value.clientId,
      ref,
      input.expectedRevision,
      this.now()
    ).run();
    return { status: this.changes(r) ? 'updated' : 'conflict' };
  }
  private async deleteConsent(input: {
    userId: string;
    clientId: string;
    referenceId?: string;
    expectedRevision?: number;
  }): Promise<DeleteResult> {
    const sql = `DELETE FROM oauth_consents WHERE namespace=? AND user_id=? AND client_id=? AND reference_id=?${input.expectedRevision === undefined ? '' : ' AND revision=?'}`;
    const bindings: unknown[] = [this.namespace, input.userId, input.clientId, input.referenceId ?? REF_NONE];
    if (input.expectedRevision !== undefined) bindings.push(input.expectedRevision);
    const r = await this.stmt(sql, ...bindings).run();
    if (this.changes(r)) return { status: 'deleted' };
    return (await this.getConsent(input)) ? { status: 'conflict' } : { status: 'not_found' };
  }
  private listConsents(userId: string, page?: PageRequest): Promise<Page<StoredConsent>> {
    return this.list(
      `SELECT value_json,revision,created_at,expires_at,client_id||char(0)||reference_id AS cursor_key FROM oauth_consents WHERE namespace=? AND user_id=? AND (expires_at IS NULL OR expires_at>?) AND client_id||char(0)||reference_id>? ORDER BY client_id,reference_id LIMIT ?`,
      [this.namespace, userId, this.now()],
      page,
      (r) => this.decodeConsent(r)
    );
  }

  private async reserve(input: {
    reservationNamespace: string;
    keyHash: string;
    expiresAt: number;
  }): Promise<ReplayReservationResult> {
    credentialIdFromSha256(input.keyHash);
    const now = this.now();
    if (!Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now) {
      throw new OAuthStorageError('conflict', { operation: 'replay.reserve' });
    }
    await this.stmt(
      `DELETE FROM oauth_replay_reservations WHERE namespace=? AND reservation_namespace=? AND key_hash=? AND expires_at<=?`,
      this.namespace,
      input.reservationNamespace,
      input.keyHash,
      now
    ).run();
    const r = await this.stmt(
      `INSERT OR IGNORE INTO oauth_replay_reservations(namespace,reservation_namespace,key_hash,expires_at) VALUES(?,?,?,?)`,
      this.namespace,
      input.reservationNamespace,
      input.keyHash,
      input.expiresAt
    ).run();
    return { status: this.changes(r) ? 'reserved' : 'exists' };
  }
  private async purge(input: PurgeStorageInput): Promise<PurgeStorageResult> {
    if (!Number.isSafeInteger(input.limit) || input.limit < 1) throw new TypeError('Purge limit must be positive');
    let remaining = input.limit;
    let grantsChecked = 0;
    let grantsPurged = 0;
    let tokensChecked = 0;
    let tokensPurged = 0;
    const grantPredicate = [
      ...(input.purgeExpiredGrants ? ['g.expires_at IS NOT NULL AND g.expires_at<=?'] : []),
      ...(input.purgeOrphanedGrants ? ["g.client_kind='registered' AND c.client_id IS NULL"] : []),
    ].join(' OR ');
    if (grantPredicate && remaining > 0) {
      const candidates = await this.db
        .prepare(
          `SELECT g.user_id,g.grant_id FROM oauth_grants g LEFT JOIN oauth_clients c ON c.namespace=g.namespace AND c.client_id=g.client_id WHERE g.namespace=? AND (${grantPredicate}) ORDER BY g.user_id,g.grant_id LIMIT ?`
        )
        .bind(this.namespace, ...(input.purgeExpiredGrants ? [input.now] : []), remaining)
        .all<{ user_id: string; grant_id: string }>();
      grantsChecked = candidates.results.length;
      remaining -= grantsChecked;
      for (const candidate of candidates.results) {
        if ((await this.revokeGrant({ userId: candidate.user_id, grantId: candidate.grant_id })).status === 'revoked') {
          grantsPurged++;
        }
      }
    }
    if (input.purgeOrphanedTokens && remaining > 0) {
      const candidates = await this.db
        .prepare(
          `SELECT t.user_id,t.grant_id,t.token_id FROM oauth_access_tokens t LEFT JOIN oauth_grants g ON g.namespace=t.namespace AND g.user_id=t.user_id AND g.grant_id=t.grant_id WHERE t.namespace=? AND ((t.expires_at IS NOT NULL AND t.expires_at<=?) OR g.grant_id IS NULL) ORDER BY t.user_id,t.grant_id,t.token_id LIMIT ?`
        )
        .bind(this.namespace, input.now, remaining)
        .all<{ user_id: string; grant_id: string; token_id: string }>();
      tokensChecked = candidates.results.length;
      remaining -= tokensChecked;
      for (const candidate of candidates.results) {
        const deleted = await this.deleteToken({
          userId: candidate.user_id,
          grantId: candidate.grant_id,
          tokenId: credentialIdFromSha256(candidate.token_id),
        });
        if (deleted.status === 'deleted') tokensPurged++;
      }
    }
    await this.stmt(
      `DELETE FROM oauth_replay_reservations WHERE namespace=? AND expires_at<=?`,
      this.namespace,
      input.now
    ).run();
    const moreGrants =
      grantPredicate &&
      (await this.db
        .prepare(
          `SELECT 1 AS present FROM oauth_grants g LEFT JOIN oauth_clients c ON c.namespace=g.namespace AND c.client_id=g.client_id WHERE g.namespace=? AND (${grantPredicate}) LIMIT 1`
        )
        .bind(this.namespace, ...(input.purgeExpiredGrants ? [input.now] : []))
        .first<number>('present')) === 1;
    const moreTokens =
      input.purgeOrphanedTokens &&
      (await this.db
        .prepare(
          `SELECT 1 AS present FROM oauth_access_tokens t LEFT JOIN oauth_grants g ON g.namespace=t.namespace AND g.user_id=t.user_id AND g.grant_id=t.grant_id WHERE t.namespace=? AND ((t.expires_at IS NOT NULL AND t.expires_at<=?) OR g.grant_id IS NULL) LIMIT 1`
        )
        .bind(this.namespace, input.now)
        .first<number>('present')) === 1;
    return { grantsChecked, grantsPurged, tokensChecked, tokensPurged, done: !moreGrants && !moreTokens };
  }

  private async list<T>(
    sql: string,
    prefix: unknown[],
    input: PageRequest | undefined,
    decode: (row: Row & { cursor_key: string }) => T
  ): Promise<Page<T>> {
    const page = createPageRequest(input);
    const limit = page.limit ?? 100;
    const result = await this.db
      .prepare(sql)
      .bind(...prefix, page.cursor ?? '', limit + 1)
      .all<Row & { cursor_key: string }>();
    const rows = result.results;
    const more = rows.length > limit;
    const selected = rows.slice(0, limit);
    return createPage(selected.map(decode), more ? selected[selected.length - 1]!.cursor_key : undefined);
  }
  private async beginTransition(input: BeginGrantTransitionInput): Promise<BeginGrantTransitionResult> {
    assertBeginGrantTransitionInput(input);
    const leaseId = `${input.ownerId}:${input.now}`;
    const expiresAt = input.now + input.leaseTtlSeconds;
    const credentialGuard =
      input.kind === 'authorization_code'
        ? `json_extract(value_json,'$.authCodeId')=? AND json_extract(value_json,'$.authCodeWrappedKey') IS NOT NULL`
        : `((json_extract(value_json,'$.refreshTokenId')=? AND json_extract(value_json,'$.refreshTokenWrappedKey') IS NOT NULL) OR (json_extract(value_json,'$.previousRefreshTokenId')=? AND json_extract(value_json,'$.previousRefreshTokenWrappedKey') IS NOT NULL))`;
    const credentialBindings =
      input.kind === 'authorization_code' ? [input.credentialId] : [input.credentialId, input.credentialId];
    const result = await this.stmt(
      `INSERT INTO oauth_transition_leases(namespace,user_id,grant_id,kind,lease_id,owner_id,credential_id,callback_key,fence,expected_revision,expires_at)
       SELECT ?,g.user_id,g.grant_id,?,?,?,?,?,COALESCE(l.fence,0)+1,g.revision,?
       FROM oauth_grants g LEFT JOIN oauth_transition_leases l ON l.namespace=g.namespace AND l.user_id=g.user_id AND l.grant_id=g.grant_id
       WHERE g.namespace=? AND g.user_id=? AND g.grant_id=? AND (g.expires_at IS NULL OR g.expires_at>?) AND ${credentialGuard} AND (l.grant_id IS NULL OR l.expires_at<=?)
       ON CONFLICT(namespace,user_id,grant_id) DO UPDATE SET kind=excluded.kind,lease_id=excluded.lease_id,owner_id=excluded.owner_id,credential_id=excluded.credential_id,callback_key=excluded.callback_key,fence=excluded.fence,expected_revision=excluded.expected_revision,expires_at=excluded.expires_at WHERE oauth_transition_leases.expires_at<=?`,
      this.namespace,
      input.kind,
      leaseId,
      input.ownerId,
      input.credentialId,
      input.callbackIdempotencyKey,
      expiresAt,
      this.namespace,
      input.grant.userId,
      input.grant.grantId,
      input.now,
      ...credentialBindings,
      input.now,
      input.now
    ).run();
    if (!this.changes(result)) {
      const rawGrant = await this.first(
        `SELECT value_json,revision,created_at,expires_at FROM oauth_grants WHERE namespace=? AND user_id=? AND grant_id=?`,
        this.namespace,
        input.grant.userId,
        input.grant.grantId
      );
      if (!rawGrant) return { status: 'not_found' };
      if (this.expired(rawGrant, input.now)) return { status: 'expired' };
      const grant = this.decodeGrant(rawGrant);
      const active = await this.db
        .prepare(
          `SELECT expires_at FROM oauth_transition_leases WHERE namespace=? AND user_id=? AND grant_id=? AND expires_at>?`
        )
        .bind(this.namespace, input.grant.userId, input.grant.grantId, input.now)
        .first<{ expires_at: number }>();
      if (active) return { status: 'busy', retryAfterSeconds: Math.max(1, active.expires_at - input.now) };
      if (input.kind === 'authorization_code') {
        if (grant.value.authCodeId !== input.credentialId) return { status: 'invalid_credential' };
        return grant.value.authCodeWrappedKey === undefined
          ? { status: 'already_consumed' }
          : { status: 'invalid_credential' };
      }
      const matchesConsumedCurrent =
        grant.value.refreshTokenId === input.credentialId && grant.value.refreshTokenWrappedKey === undefined;
      const matchesConsumedPrevious =
        grant.value.previousRefreshTokenId === input.credentialId &&
        grant.value.previousRefreshTokenWrappedKey === undefined;
      return matchesConsumedCurrent || matchesConsumedPrevious
        ? { status: 'already_consumed' }
        : { status: 'invalid_credential' };
    }
    const grant = await this.getGrant(input.grant);
    const leaseRow = await this.db
      .prepare(
        `SELECT fence,expected_revision,expires_at FROM oauth_transition_leases WHERE namespace=? AND user_id=? AND grant_id=? AND lease_id=?`
      )
      .bind(this.namespace, input.grant.userId, input.grant.grantId, leaseId)
      .first<{ fence: number; expected_revision: number; expires_at: number }>();
    if (!grant || !leaseRow) return { status: 'not_found' };
    const lease = createGrantTransitionLease(
      {
        id: transitionLeaseId(leaseId),
        grant: input.grant,
        kind: input.kind,
        credentialId: input.credentialId,
        ownerId: input.ownerId,
        fence: leaseRow.fence,
        expectedRevision: leaseRow.expected_revision,
        expiresAt: leaseRow.expires_at,
        callbackIdempotencyKey: input.callbackIdempotencyKey,
      },
      input.now,
      input.leaseTtlSeconds
    );
    return validateBeginGrantTransitionResult(input, { status: 'acquired', grant, lease }, input.leaseTtlSeconds);
  }

  private async commitTransition(input: ValidatedCommitGrantTransitionInput): Promise<CommitGrantTransitionResult> {
    assertCommitGrantTransitionInput(input);
    const lease = input.lease;
    if (input.now >= lease.expiresAt) return { status: 'expired' };
    const guard = `EXISTS(SELECT 1 FROM oauth_transition_leases l WHERE l.namespace=? AND l.user_id=? AND l.grant_id=? AND l.lease_id=? AND l.owner_id=? AND l.fence=? AND l.expected_revision=? AND l.expires_at>?)`;
    const guardBindings = [
      this.namespace,
      lease.grant.userId,
      lease.grant.grantId,
      lease.id,
      lease.ownerId,
      lease.fence,
      lease.expectedRevision,
      input.now,
    ];
    const token = input.accessToken;
    let results: D1Result[];
    try {
      results = await this.db.batch([
        this.stmt(
          `UPDATE oauth_grants SET revision=?,created_at=?,expires_at=?,value_json=? WHERE namespace=? AND user_id=? AND grant_id=? AND revision=? AND ${guard}`,
          ...this.values(input.grant),
          this.namespace,
          lease.grant.userId,
          lease.grant.grantId,
          lease.expectedRevision,
          ...guardBindings
        ),
        this.stmt(
          `INSERT INTO oauth_access_tokens(namespace,user_id,grant_id,token_id,revision,created_at,expires_at,value_json) SELECT ?,?,?,?,?,?,?,? WHERE ${guard} AND EXISTS(SELECT 1 FROM oauth_grants WHERE namespace=? AND user_id=? AND grant_id=? AND revision=?)`,
          this.namespace,
          token.value.userId,
          token.value.grantId,
          token.value.id,
          ...this.values(token),
          ...guardBindings,
          this.namespace,
          lease.grant.userId,
          lease.grant.grantId,
          input.grant.metadata.revision
        ),
        this.stmt(
          `UPDATE oauth_transition_leases SET lease_id='',owner_id='',credential_id='',callback_key='',expected_revision=?,expires_at=0 WHERE namespace=? AND user_id=? AND grant_id=? AND lease_id=? AND owner_id=? AND fence=? AND expected_revision=? AND expires_at>? AND EXISTS(SELECT 1 FROM oauth_grants WHERE namespace=? AND user_id=? AND grant_id=? AND revision=?) AND EXISTS(SELECT 1 FROM oauth_access_tokens WHERE namespace=? AND user_id=? AND grant_id=? AND token_id=?)`,
          input.grant.metadata.revision,
          ...guardBindings,
          this.namespace,
          lease.grant.userId,
          lease.grant.grantId,
          input.grant.metadata.revision,
          this.namespace,
          token.value.userId,
          token.value.grantId,
          token.value.id
        ),
      ]);
    } catch (error) {
      if (isConstraintError(error)) return { status: 'conflict' };
      throw error;
    }
    return results.every((result) => this.changes(result) === 1) ? { status: 'committed' } : { status: 'lease_lost' };
  }

  private async abortTransition(input: AbortGrantTransitionInput): Promise<AbortGrantTransitionResult> {
    const lease = input.lease;
    const result = await this.stmt(
      `UPDATE oauth_transition_leases SET lease_id='',owner_id='',credential_id='',callback_key='',expires_at=0 WHERE namespace=? AND user_id=? AND grant_id=? AND lease_id=? AND owner_id=? AND fence=?`,
      this.namespace,
      lease.grant.userId,
      lease.grant.grantId,
      lease.id,
      lease.ownerId,
      lease.fence
    ).run();
    return this.changes(result) ? { status: 'aborted' } : { status: 'lease_lost' };
  }
  private async run<T>(operation: string, task: () => Promise<T>): Promise<T> {
    if (this.#closed) throw new OAuthStorageError('internal', { operation });
    try {
      return await task();
    } catch (cause) {
      if (isOAuthStorageError(cause) || cause instanceof TypeError) throw cause;
      const message = cause instanceof Error ? cause.message.toLowerCase() : '';
      const code =
        message.includes('locked') || message.includes('busy')
          ? 'unavailable'
          : message.includes('unique') || message.includes('constraint')
            ? 'conflict'
            : message.includes('schema') || message.includes('no such table')
              ? 'schema_mismatch'
              : 'internal';
      throw new OAuthStorageError(code, { operation, cause });
    }
  }
}

function isConstraintError(error: unknown): boolean {
  return error instanceof Error && /constraint|unique/i.test(error.message);
}
