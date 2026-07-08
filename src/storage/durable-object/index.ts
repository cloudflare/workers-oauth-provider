import { defineOAuthStorageCapabilities, type OAuthStorageCapabilities } from '../capabilities';
import { OAuthStorageError, isOAuthStorageError, unsupportedStorageOperation } from '../errors';
import {
  assertStorageConnectionNamespace,
  defineStorageNamespace,
  type OAuthStorageConnection,
  type OAuthStorageOpenContext,
  type OAuthStorageProvider,
} from '../lifecycle';
import { createPage, createPageRequest, type Page, type PageRequest } from '../pagination';
import {
  createStoredAccessToken,
  createStoredClient,
  createStoredGrant,
  credentialIdFromSha256,
  hideLogicallyExpired,
  type AccessTokenKey,
  type GrantKey,
  type StoredAccessToken,
  type StoredClient,
  type StoredGrant,
} from '../records';
import type {
  CreateResult,
  DeleteResult,
  IssueAccessTokenResult,
  IssueGrantResult,
  ReplaceResult,
  ReplayReservationResult,
  RevokeGrantResult,
} from '../results';
import {
  assertCreateClientInput,
  assertIssueAccessTokenInput,
  assertIssueGrantInput,
  assertIssueGrantSupported,
  assertReplaceClientInput,
  type OAuthAccessTokenStore,
  type OAuthClientStore,
  type OAuthConsentStore,
  type OAuthGrantStore,
  type OAuthMaintenanceStore,
  type OAuthReplayStore,
} from '../stores';
import {
  assertBeginGrantTransitionInput,
  assertCommitGrantTransitionInput,
  createGrantTransitionLease,
  transitionLeaseId,
  validateBeginGrantTransitionResult,
  type AbortGrantTransitionInput,
  type BeginGrantTransitionInput,
  type GrantTransitionLease,
  type ValidatedCommitGrantTransitionInput,
} from '../transitions';

/** Guarantees proved by the single-aggregate Durable Object SQLite implementation. */
export const DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES: OAuthStorageCapabilities = defineOAuthStorageCapabilities({
  consistency: { readAfterWrite: 'strong' },
  clients: { create: 'strong', replace: 'strong' },
  issuance: {
    grantOnly: 'strong',
    grantWithAccessToken: 'strong',
    replaceUserClientGrants: 'unsupported',
    existingGrantAccessToken: 'strong',
  },
  transitions: { authorizationCode: 'strong', refreshToken: 'strong' },
  replayReservation: 'strong',
  revocation: { accessToken: 'strong', grantCascade: 'strong', clientCascade: 'unsupported' },
  consents: { compareAndSwap: 'unsupported', delete: 'unsupported' },
  queries: {
    listClients: 'unsupported',
    grantsByUser: 'unsupported',
    grantsByClient: 'unsupported',
    tokensByGrant: 'strong',
    consentsByUser: 'unsupported',
    globalMaintenance: 'unsupported',
  },
  expiration: { cleanup: 'scheduled', minimumTtlSeconds: 0 },
});

/** RPC-safe commands accepted by {@link OAuthStorageObject}. */
export type DurableObjectStorageCommand =
  | { readonly operation: 'clients.get'; readonly clientId: string; readonly now: number }
  | { readonly operation: 'clients.create'; readonly client: StoredClient }
  | {
      readonly operation: 'clients.replace';
      readonly clientId: string;
      readonly expectedRevision: number;
      readonly client: StoredClient;
    }
  | { readonly operation: 'grants.get'; readonly key: GrantKey; readonly now: number }
  | {
      readonly operation: 'grants.issue';
      readonly input: {
        readonly client: {
          readonly kind: 'registered' | 'external';
          readonly clientId: string;
          readonly expectedRevision?: number;
        };
        readonly grant: StoredGrant;
        readonly accessToken?: StoredAccessToken;
      };
    }
  | { readonly operation: 'grants.begin'; readonly input: BeginGrantTransitionInput }
  | { readonly operation: 'grants.commit'; readonly input: ValidatedCommitGrantTransitionInput }
  | { readonly operation: 'grants.abort'; readonly input: AbortGrantTransitionInput }
  | { readonly operation: 'grants.revoke'; readonly key: GrantKey; readonly expectedRevision?: number }
  | { readonly operation: 'tokens.get'; readonly key: AccessTokenKey; readonly now: number }
  | {
      readonly operation: 'tokens.create';
      readonly input: {
        readonly grant: GrantKey;
        readonly expectedGrantRevision: number;
        readonly token: StoredAccessToken;
      };
    }
  | { readonly operation: 'tokens.delete'; readonly key: AccessTokenKey }
  | { readonly operation: 'tokens.list'; readonly grant: GrantKey; readonly page?: PageRequest; readonly now: number }
  | {
      readonly operation: 'replay.reserve';
      readonly reservationNamespace: string;
      readonly keyHash: string;
      readonly expiresAt: number;
      readonly now: number;
    };

/** Narrow RPC object boundary. Implementations may be a Durable Object stub or a test factory. */
export interface OAuthStorageObjectStub {
  execute(command: DurableObjectStorageCommand): Promise<unknown>;
}

/** Injected Durable Object namespace/factory boundary. */
export interface OAuthStorageObjectNamespace {
  getByName(name: string): OAuthStorageObjectStub;
}

export interface DurableObjectSqliteStorageOptions<Env> {
  readonly binding: (env: Env) => OAuthStorageObjectNamespace;
  readonly namespace?: string;
  readonly now?: () => number;
}

/**
 * Creates the Durable Object SQLite adapter.
 *
 * Partition strategy v1 is deliberately fixed: each operation routes to the
 * aggregate named `oauth-do:v1:<namespace>:<kind>:<encoded aggregate id>`.
 * Clients use clientId, grants/tokens use userId + grantId, and replay entries
 * use reservation namespace + digest. This places all strong aggregate
 * operations in one object's serialization and SQLite transaction domain.
 */
export function durableObjectSqliteStorage<Env>(
  options: DurableObjectSqliteStorageOptions<Env>
): OAuthStorageProvider<Env> {
  if (!options || typeof options.binding !== 'function')
    throw new TypeError('Durable Object storage requires a binding resolver');
  const namespace = defineStorageNamespace(options.namespace);
  const clock = options.now ?? (() => Math.floor(Date.now() / 1000));
  const provider: OAuthStorageProvider<Env> = Object.freeze({
    id: 'durable-object-sqlite',
    contractVersion: 1,
    namespace,
    capabilities: DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES,
    open(context: OAuthStorageOpenContext<Env>): OAuthStorageConnection {
      if (context.namespace !== namespace)
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      let binding: OAuthStorageObjectNamespace;
      try {
        binding = options.binding(context.env);
      } catch (cause) {
        throw new OAuthStorageError('invalid_configuration', { cause, operation: 'storage.open' });
      }
      if (!binding || typeof binding.getByName !== 'function')
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      const connection = new DurableObjectConnection(binding, namespace, clock);
      assertStorageConnectionNamespace(provider, connection);
      return connection;
    },
  });
  return provider;
}

function aggregateName(namespace: string, kind: string, parts: readonly string[]): string {
  return `oauth-do:v1:${encodeURIComponent(namespace)}:${kind}:${parts.map(encodeURIComponent).join(':')}`;
}

class DurableObjectConnection implements OAuthStorageConnection {
  #closed = false;
  readonly clients: OAuthClientStore;
  readonly grants: OAuthGrantStore;
  readonly accessTokens: OAuthAccessTokenStore;
  readonly consents: OAuthConsentStore;
  readonly replay: OAuthReplayStore;
  readonly maintenance: OAuthMaintenanceStore;

  constructor(
    private readonly binding: OAuthStorageObjectNamespace,
    readonly namespace: string,
    private readonly clock: () => number
  ) {
    this.clients = Object.freeze<OAuthClientStore>({
      get: (clientId) => this.call('client', [clientId], { operation: 'clients.get', clientId, now: this.now() }),
      create: async (input) => {
        assertCreateClientInput(input);
        return this.call('client', [input.client.value.clientId], {
          operation: 'clients.create',
          client: input.client,
        });
      },
      replace: async (input) => {
        assertReplaceClientInput(input);
        return this.call('client', [input.clientId], {
          operation: 'clients.replace',
          clientId: input.clientId,
          expectedRevision: input.expectedRevision,
          client: input.client,
        });
      },
      deleteWithGrants: () => Promise.reject(unsupportedStorageOperation('clients.deleteWithGrants')),
      list: () => Promise.reject(unsupportedStorageOperation('clients.list')),
    });
    this.grants = Object.freeze<OAuthGrantStore>({
      get: (key) => this.call('grant', [key.userId, key.grantId], { operation: 'grants.get', key, now: this.now() }),
      issue: async (input) => {
        assertIssueGrantInput(input);
        assertIssueGrantSupported(DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES, input);
        return this.call('grant', [input.grant.value.userId, input.grant.value.id], {
          operation: 'grants.issue',
          input,
        });
      },
      listByUser: () => Promise.reject(unsupportedStorageOperation('grants.listByUser')),
      listByClient: () => Promise.reject(unsupportedStorageOperation('grants.listByClient')),
      beginTransition: async (input) => {
        assertBeginGrantTransitionInput(input);
        return this.call('grant', [input.grant.userId, input.grant.grantId], { operation: 'grants.begin', input });
      },
      commitTransition: async (input) => {
        assertCommitGrantTransitionInput(input);
        return this.call('grant', [input.lease.grant.userId, input.lease.grant.grantId], {
          operation: 'grants.commit',
          input,
        });
      },
      abortTransition: (input) =>
        this.call('grant', [input.lease.grant.userId, input.lease.grant.grantId], { operation: 'grants.abort', input }),
      revoke: (input) =>
        this.call('grant', [input.grant.userId, input.grant.grantId], {
          operation: 'grants.revoke',
          key: input.grant,
          expectedRevision: input.expectedRevision,
        }),
    });
    this.accessTokens = Object.freeze<OAuthAccessTokenStore>({
      get: (key) => this.call('grant', [key.userId, key.grantId], { operation: 'tokens.get', key, now: this.now() }),
      createForGrant: async (input) => {
        assertIssueAccessTokenInput(input);
        return this.call('grant', [input.grant.userId, input.grant.grantId], { operation: 'tokens.create', input });
      },
      delete: (input) =>
        this.call('grant', [input.key.userId, input.key.grantId], { operation: 'tokens.delete', key: input.key }),
      listByGrant: (input) =>
        this.call('grant', [input.grant.userId, input.grant.grantId], {
          operation: 'tokens.list',
          grant: input.grant,
          page: input.page,
          now: this.now(),
        }),
    });
    this.consents = Object.freeze<OAuthConsentStore>({
      get: () => Promise.reject(unsupportedStorageOperation('consents.get')),
      compareAndSwap: () => Promise.reject(unsupportedStorageOperation('consents.compareAndSwap')),
      delete: () => Promise.reject(unsupportedStorageOperation('consents.delete')),
      listByUser: () => Promise.reject(unsupportedStorageOperation('consents.listByUser')),
    });
    this.replay = Object.freeze<OAuthReplayStore>({
      reserve: (input) =>
        this.call('replay', [input.reservationNamespace, input.keyHash], {
          operation: 'replay.reserve',
          ...input,
          now: this.now(),
        }),
    });
    this.maintenance = Object.freeze<OAuthMaintenanceStore>({
      purge: () => Promise.reject(unsupportedStorageOperation('maintenance.purge')),
    });
  }
  close(): void {
    this.#closed = true;
  }
  private now(): number {
    const value = this.clock();
    if (!Number.isSafeInteger(value) || value < 0)
      throw new OAuthStorageError('invalid_configuration', { operation: 'storage.clock' });
    return value;
  }
  private async call<T>(kind: string, parts: readonly string[], command: DurableObjectStorageCommand): Promise<T> {
    if (this.#closed) throw new OAuthStorageError('unavailable', { operation: command.operation });
    try {
      return (await this.binding.getByName(aggregateName(this.namespace, kind, parts)).execute(command)) as T;
    } catch (error) {
      if (isOAuthStorageError(error)) throw error;
      throw new OAuthStorageError('internal', { cause: error, operation: command.operation });
    }
  }
}

interface SqlRow {
  readonly value: string;
  readonly revision: number;
  readonly expires_at: number | null;
}
interface SqlCursor<T = Record<string, unknown>> extends Iterable<T> {
  one(): T;
  toArray(): T[];
}
interface SqlStorage {
  exec<T = Record<string, unknown>>(query: string, ...bindings: unknown[]): SqlCursor<T>;
}
interface ObjectStorage {
  readonly sql: SqlStorage;
  transaction<T>(callback: () => T): T;
  setAlarm?(scheduledTime: number | Date): Promise<void>;
}
interface ObjectState {
  readonly storage: ObjectStorage;
  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
}

/** Durable Object implementation owning one v1 aggregate and its local SQLite database. */
export class OAuthStorageObject {
  private readonly sql: SqlStorage;
  private ready: Promise<void>;
  constructor(private readonly state: ObjectState) {
    this.sql = state.storage.sql;
    this.ready = state.blockConcurrencyWhile(async () => this.migrate());
  }

  async execute(command: DurableObjectStorageCommand): Promise<unknown> {
    await this.ready;
    return this.state.storage.transaction(() => this.executeTransaction(command));
  }

  async alarm(): Promise<void> {
    await this.ready;
    const now = Math.floor(Date.now() / 1000);
    this.state.storage.transaction(() => {
      this.sql.exec('DELETE FROM records WHERE expires_at IS NOT NULL AND expires_at <= ?', now);
      this.sql.exec('DELETE FROM leases WHERE expires_at <= ?', now);
      this.sql.exec('DELETE FROM replay WHERE expires_at <= ?', now);
    });
  }

  private migrate(): void {
    this.sql.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)');
    this.sql.exec(
      'CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, revision INTEGER NOT NULL, expires_at INTEGER, PRIMARY KEY(kind,key))'
    );
    this.sql.exec(
      'CREATE TABLE IF NOT EXISTS leases (grant_key TEXT PRIMARY KEY, value TEXT NOT NULL, fence INTEGER NOT NULL, expires_at INTEGER NOT NULL)'
    );
    this.sql.exec('CREATE TABLE IF NOT EXISTS fences (grant_key TEXT PRIMARY KEY, value INTEGER NOT NULL)');
    this.sql.exec(
      'CREATE TABLE IF NOT EXISTS replay (namespace TEXT NOT NULL, key_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(namespace,key_hash))'
    );
    this.sql.exec('INSERT OR IGNORE INTO schema_migrations(version) VALUES (1)');
  }

  private executeTransaction(command: DurableObjectStorageCommand): unknown {
    switch (command.operation) {
      case 'clients.get':
        return this.readClient(command.clientId, command.now);
      case 'clients.create':
        return this.insert('client', command.client.value.clientId, command.client);
      case 'clients.replace':
        return this.replaceClient(command);
      case 'grants.get':
        return this.readGrant(command.key, command.now);
      case 'grants.issue':
        return this.issue(command.input);
      case 'grants.begin':
        return this.begin(command.input);
      case 'grants.commit':
        return this.commit(command.input);
      case 'grants.abort':
        return this.abort(command.input);
      case 'grants.revoke':
        return this.revoke(command.key, command.expectedRevision);
      case 'tokens.get':
        return this.readToken(command.key, command.now);
      case 'tokens.create':
        return this.createToken(command.input);
      case 'tokens.delete':
        return this.deleteToken(command.key);
      case 'tokens.list':
        return this.listTokens(command.grant, command.page, command.now);
      case 'replay.reserve':
        return this.reserveReplay(command);
    }
  }

  private row(kind: string, key: string): SqlRow | null {
    return (
      this.sql
        .exec<SqlRow>('SELECT value, revision, expires_at FROM records WHERE kind=? AND key=?', kind, key)
        .toArray()[0] ?? null
    );
  }
  private decodeClient(row: SqlRow): StoredClient {
    const stored = JSON.parse(row.value) as StoredClient;
    return createStoredClient(stored.value, stored.metadata);
  }
  private decodeGrant(row: SqlRow): StoredGrant {
    const stored = JSON.parse(row.value) as StoredGrant;
    return createStoredGrant(stored.value, stored.metadata);
  }
  private decodeToken(row: SqlRow): StoredAccessToken {
    const stored = JSON.parse(row.value) as StoredAccessToken;
    return createStoredAccessToken(stored.value, stored.metadata);
  }
  private grantKey(key: GrantKey): string {
    return JSON.stringify([key.userId, key.grantId]);
  }
  private tokenKey(key: AccessTokenKey): string {
    return key.tokenId;
  }
  private insert(kind: string, key: string, value: StoredClient | StoredGrant | StoredAccessToken): CreateResult {
    const changed = this.sql
      .exec(
        'INSERT OR IGNORE INTO records(kind,key,value,revision,expires_at) VALUES(?,?,?,?,?) RETURNING key',
        kind,
        key,
        JSON.stringify(value),
        value.metadata.revision,
        value.metadata.expiresAt ?? null
      )
      .toArray().length;
    this.schedule(value.metadata.expiresAt);
    return { status: changed ? 'created' : 'conflict' };
  }
  private readClient(key: string, now: number): StoredClient | null {
    const row = this.row('client', key);
    return row ? hideLogicallyExpired(this.decodeClient(row), now) : null;
  }
  private readGrant(key: GrantKey, now: number): StoredGrant | null {
    const row = this.row('grant', this.grantKey(key));
    return row ? hideLogicallyExpired(this.decodeGrant(row), now) : null;
  }
  private readToken(key: AccessTokenKey, now: number): StoredAccessToken | null {
    const row = this.row('token', this.tokenKey(key));
    return row ? hideLogicallyExpired(this.decodeToken(row), now) : null;
  }
  private replaceClient(
    command: Extract<DurableObjectStorageCommand, { operation: 'clients.replace' }>
  ): ReplaceResult {
    const row = this.row('client', command.clientId);
    if (!row) return { status: 'not_found' };
    if (row.revision !== command.expectedRevision) return { status: 'conflict' };
    this.sql.exec(
      'UPDATE records SET value=?,revision=?,expires_at=? WHERE kind=? AND key=? AND revision=?',
      JSON.stringify(command.client),
      command.client.metadata.revision,
      command.client.metadata.expiresAt ?? null,
      'client',
      command.clientId,
      command.expectedRevision
    );
    this.schedule(command.client.metadata.expiresAt);
    return { status: 'updated' };
  }
  private issue(input: Extract<DurableObjectStorageCommand, { operation: 'grants.issue' }>['input']): IssueGrantResult {
    const key = this.grantKey({ userId: input.grant.value.userId, grantId: input.grant.value.id });
    if (this.row('grant', key)) return { status: 'conflict' };
    if (input.client.kind === 'registered') {
      const client = this.row('client', input.client.clientId);
      if (!client) return { status: 'client_not_found' };
      if (client.revision !== input.client.expectedRevision) return { status: 'client_conflict' };
    }
    this.insert('grant', key, input.grant);
    if (input.accessToken && this.insert('token', input.accessToken.value.id, input.accessToken).status !== 'created')
      throw new OAuthStorageError('conflict', { operation: 'grants.issue' });
    return { status: 'created' };
  }
  private begin(input: BeginGrantTransitionInput): unknown {
    const grant = this.readGrant(input.grant, input.now);
    if (!grant) return this.row('grant', this.grantKey(input.grant)) ? { status: 'expired' } : { status: 'not_found' };
    if (input.kind === 'authorization_code') {
      if (grant.value.authCodeId !== input.credentialId) return { status: 'invalid_credential' };
      if (!grant.value.authCodeWrappedKey) return { status: 'already_consumed' };
    } else {
      const current = grant.value.refreshTokenId === input.credentialId && grant.value.refreshTokenWrappedKey;
      const previous =
        grant.value.previousRefreshTokenId === input.credentialId && grant.value.previousRefreshTokenWrappedKey;
      if (!current && !previous) return { status: 'invalid_credential' };
    }
    const key = this.grantKey(input.grant);
    const existing = this.sql
      .exec<{ value: string; expires_at: number }>('SELECT value,expires_at FROM leases WHERE grant_key=?', key)
      .toArray()[0];
    if (existing && existing.expires_at > input.now)
      return { status: 'busy', retryAfterSeconds: Math.max(1, existing.expires_at - input.now) };
    const priorFence =
      this.sql.exec<{ value: number }>('SELECT value FROM fences WHERE grant_key=?', key).toArray()[0]?.value ?? 0;
    const fence = priorFence + 1;
    this.sql.exec(
      'INSERT INTO fences(grant_key,value) VALUES(?,?) ON CONFLICT(grant_key) DO UPDATE SET value=excluded.value',
      key,
      fence
    );
    const lease = createGrantTransitionLease(
      {
        id: transitionLeaseId(`${fence}`),
        grant: input.grant,
        kind: input.kind,
        credentialId: input.credentialId,
        ownerId: input.ownerId,
        fence,
        expectedRevision: grant.metadata.revision,
        expiresAt: input.now + input.leaseTtlSeconds,
        callbackIdempotencyKey: input.callbackIdempotencyKey,
      },
      input.now,
      input.leaseTtlSeconds
    );
    this.sql.exec(
      'INSERT INTO leases(grant_key,value,fence,expires_at) VALUES(?,?,?,?) ON CONFLICT(grant_key) DO UPDATE SET value=excluded.value,fence=excluded.fence,expires_at=excluded.expires_at',
      key,
      JSON.stringify(lease),
      fence,
      lease.expiresAt
    );
    this.schedule(lease.expiresAt);
    return validateBeginGrantTransitionResult(input, { status: 'acquired', grant, lease }, input.leaseTtlSeconds);
  }
  private currentLease(lease: GrantTransitionLease): boolean {
    const row = this.sql
      .exec<{
        value: string;
        fence: number;
      }>('SELECT value,fence FROM leases WHERE grant_key=?', this.grantKey(lease.grant))
      .toArray()[0];
    if (!row || row.fence !== lease.fence) return false;
    const stored = JSON.parse(row.value) as GrantTransitionLease;
    return stored.id === lease.id && stored.ownerId === lease.ownerId;
  }
  private commit(input: ValidatedCommitGrantTransitionInput): unknown {
    if (input.now >= input.lease.expiresAt || !this.currentLease(input.lease)) return { status: 'lease_lost' };
    const key = this.grantKey(input.lease.grant);
    const row = this.row('grant', key);
    if (!row) return { status: 'not_found' };
    if (row.expires_at !== null && row.expires_at <= input.now) return { status: 'expired' };
    if (row.revision !== input.lease.expectedRevision) return { status: 'conflict' };
    if (this.row('token', input.accessToken.value.id)) return { status: 'conflict' };
    this.sql.exec(
      'UPDATE records SET value=?,revision=?,expires_at=? WHERE kind=? AND key=? AND revision=?',
      JSON.stringify(input.grant),
      input.grant.metadata.revision,
      input.grant.metadata.expiresAt ?? null,
      'grant',
      key,
      input.lease.expectedRevision
    );
    this.insert('token', input.accessToken.value.id, input.accessToken);
    this.sql.exec('DELETE FROM leases WHERE grant_key=? AND fence=?', key, input.lease.fence);
    return { status: 'committed' };
  }
  private abort(input: AbortGrantTransitionInput): unknown {
    const key = this.grantKey(input.lease.grant);
    if (!this.row('grant', key)) return { status: 'not_found' };
    if (!this.currentLease(input.lease)) return { status: 'lease_lost' };
    this.sql.exec('DELETE FROM leases WHERE grant_key=? AND fence=?', key, input.lease.fence);
    return { status: 'aborted' };
  }
  private revoke(key: GrantKey, expectedRevision?: number): RevokeGrantResult {
    const physical = this.grantKey(key);
    const row = this.row('grant', physical);
    if (!row) return { status: 'not_found' };
    if (expectedRevision !== undefined && row.revision !== expectedRevision) return { status: 'conflict' };
    const count = this.sql
      .exec(
        "DELETE FROM records WHERE kind=? AND json_extract(value,'$.value.userId')=? AND json_extract(value,'$.value.grantId')=? RETURNING key",
        'token',
        key.userId,
        key.grantId
      )
      .toArray().length;
    this.sql.exec('DELETE FROM records WHERE kind=? AND key=?', 'grant', physical);
    this.sql.exec('DELETE FROM leases WHERE grant_key=?', physical);
    return { status: 'revoked', deletedAccessTokens: count };
  }
  private createToken(
    input: Extract<DurableObjectStorageCommand, { operation: 'tokens.create' }>['input']
  ): IssueAccessTokenResult {
    const grant = this.row('grant', this.grantKey(input.grant));
    if (!grant) return { status: 'grant_not_found' };
    if (grant.revision !== input.expectedGrantRevision) return { status: 'grant_conflict' };
    return this.insert('token', input.token.value.id, input.token).status === 'created'
      ? { status: 'created' }
      : { status: 'conflict' };
  }
  private deleteToken(key: AccessTokenKey): DeleteResult {
    return this.sql
      .exec('DELETE FROM records WHERE kind=? AND key=? RETURNING key', 'token', this.tokenKey(key))
      .toArray().length
      ? { status: 'deleted' }
      : { status: 'not_found' };
  }
  private listTokens(grant: GrantKey, page: PageRequest | undefined, now: number): Page<StoredAccessToken> {
    const request = createPageRequest(page);
    const limit = request.limit ?? 1000;
    const after = request.cursor ?? '';
    const rows = this.sql
      .exec<
        SqlRow & { key: string }
      >("SELECT key,value,revision,expires_at FROM records WHERE kind=? AND key>? AND json_extract(value,'$.value.userId')=? AND json_extract(value,'$.value.grantId')=? AND (expires_at IS NULL OR expires_at>?) ORDER BY key LIMIT ?", 'token', after, grant.userId, grant.grantId, now, limit + 1)
      .toArray();
    const more = rows.length > limit;
    const selected = rows.slice(0, limit);
    return createPage(
      selected.map((row) => this.decodeToken(row)),
      more ? selected[selected.length - 1]?.key : undefined
    );
  }
  private reserveReplay(
    command: Extract<DurableObjectStorageCommand, { operation: 'replay.reserve' }>
  ): ReplayReservationResult {
    credentialIdFromSha256(command.keyHash);
    if (!Number.isSafeInteger(command.expiresAt) || command.expiresAt <= command.now)
      throw new OAuthStorageError('conflict', { operation: 'replay.reserve' });
    this.sql.exec(
      'DELETE FROM replay WHERE namespace=? AND key_hash=? AND expires_at<=?',
      command.reservationNamespace,
      command.keyHash,
      command.now
    );
    const inserted = this.sql
      .exec(
        'INSERT OR IGNORE INTO replay(namespace,key_hash,expires_at) VALUES(?,?,?) RETURNING key_hash',
        command.reservationNamespace,
        command.keyHash,
        command.expiresAt
      )
      .toArray().length;
    this.schedule(command.expiresAt);
    return { status: inserted ? 'reserved' : 'exists' };
  }
  private schedule(expiresAt?: number): void {
    if (expiresAt !== undefined && this.state.storage.setAlarm) void this.state.storage.setAlarm(expiresAt * 1000);
  }
}
