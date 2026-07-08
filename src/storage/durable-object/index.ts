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
  createStoredConsent,
  credentialIdFromSha256,
  hideLogicallyExpired,
  type AccessTokenKey,
  type GrantKey,
  type StoredAccessToken,
  type StoredClient,
  type StoredGrant,
  type StoredConsent,
} from '../records';
import type {
  CreateResult,
  DeleteResult,
  IssueAccessTokenResult,
  IssueGrantResult,
  ReplaceResult,
  ReplayReservationResult,
  RevokeGrantResult,
  DeleteClientResult,
  ReplaceConsentResult,
} from '../results';
import {
  assertCreateClientInput,
  assertIssueAccessTokenInput,
  assertIssueGrantInput,
  assertIssueGrantSupported,
  assertCompareAndSwapConsentInput,
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
  | { readonly operation: 'clients.delete'; readonly clientId: string; readonly expectedRevision?: number }
  | { readonly operation: 'clients.list'; readonly page?: PageRequest; readonly now: number }
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
        readonly replaceExistingUserClientGrants?: boolean;
      };
    }
  | {
      readonly operation: 'grants.list-user';
      readonly userId: string;
      readonly page?: PageRequest;
      readonly now: number;
    }
  | {
      readonly operation: 'grants.list-client';
      readonly clientId: string;
      readonly page?: PageRequest;
      readonly now: number;
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
      readonly now: number;
    }
  | { readonly operation: 'tokens.delete'; readonly key: AccessTokenKey }
  | { readonly operation: 'tokens.list'; readonly grant: GrantKey; readonly page?: PageRequest; readonly now: number }
  | {
      readonly operation: 'consents.get';
      readonly userId: string;
      readonly clientId: string;
      readonly referenceId?: string;
      readonly now: number;
    }
  | { readonly operation: 'consents.cas'; readonly consent: StoredConsent; readonly expectedRevision?: number }
  | {
      readonly operation: 'consents.delete';
      readonly userId: string;
      readonly clientId: string;
      readonly referenceId?: string;
      readonly expectedRevision?: number;
    }
  | { readonly operation: 'consents.list'; readonly userId: string; readonly page?: PageRequest; readonly now: number }
  | {
      readonly operation: 'replay.reserve';
      readonly reservationNamespace: string;
      readonly keyHash: string;
      readonly expiresAt: number;
      readonly now: number;
    }
  | {
      readonly operation: 'maintenance.purge';
      readonly now: number;
      readonly limit: number;
      readonly purgeOrphanedGrants: boolean;
      readonly purgeExpiredGrants: boolean;
      readonly purgeOrphanedTokens: boolean;
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
 * Version 1 deliberately routes every operation in a namespace to one root
 * object. This is the only serialization and SQLite transaction domain, so all
 * advertised strong operations compose atomically. The explicit v1 trade-off
 * is that one namespace is limited by a single Durable Object's throughput and
 * storage limits; applications needing horizontal sharding must use a future
 * contract version with correspondingly weaker cross-shard guarantees.
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

function rootName(namespace: string): string {
  return `oauth-do:v1:${encodeURIComponent(namespace)}:root`;
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
      get: (clientId) => this.call({ operation: 'clients.get', clientId, now: this.now() }),
      create: async (input) => {
        assertCreateClientInput(input);
        return this.call({
          operation: 'clients.create',
          client: input.client,
        });
      },
      replace: async (input) => {
        assertReplaceClientInput(input);
        return this.call({
          operation: 'clients.replace',
          clientId: input.clientId,
          expectedRevision: input.expectedRevision,
          client: input.client,
        });
      },
      deleteWithGrants: (input) => this.call({ operation: 'clients.delete', ...input }),
      list: (page) => this.call({ operation: 'clients.list', page, now: this.now() }),
    });
    this.grants = Object.freeze<OAuthGrantStore>({
      get: (key) => this.call({ operation: 'grants.get', key, now: this.now() }),
      issue: async (input) => {
        assertIssueGrantInput(input);
        assertIssueGrantSupported(DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES, input);
        return this.call({
          operation: 'grants.issue',
          input,
        });
      },
      listByUser: (input) => this.call({ operation: 'grants.list-user', ...input, now: this.now() }),
      listByClient: (input) => this.call({ operation: 'grants.list-client', ...input, now: this.now() }),
      beginTransition: async (input) => {
        assertBeginGrantTransitionInput(input);
        return this.call({ operation: 'grants.begin', input });
      },
      commitTransition: async (input) => {
        assertCommitGrantTransitionInput(input);
        return this.call({
          operation: 'grants.commit',
          input,
        });
      },
      abortTransition: (input) => this.call({ operation: 'grants.abort', input }),
      revoke: (input) =>
        this.call({
          operation: 'grants.revoke',
          key: input.grant,
          expectedRevision: input.expectedRevision,
        }),
    });
    this.accessTokens = Object.freeze<OAuthAccessTokenStore>({
      get: (key) => this.call({ operation: 'tokens.get', key, now: this.now() }),
      createForGrant: async (input) => {
        assertIssueAccessTokenInput(input);
        return this.call({ operation: 'tokens.create', input, now: this.now() });
      },
      delete: (input) => this.call({ operation: 'tokens.delete', key: input.key }),
      listByGrant: (input) =>
        this.call({
          operation: 'tokens.list',
          grant: input.grant,
          page: input.page,
          now: this.now(),
        }),
    });
    this.consents = Object.freeze<OAuthConsentStore>({
      get: (input) => this.call({ operation: 'consents.get', ...input, now: this.now() }),
      compareAndSwap: async (input) => {
        assertCompareAndSwapConsentInput(input);
        return this.call({
          operation: 'consents.cas',
          consent: input.consent,
          expectedRevision: input.expectedRevision,
        });
      },
      delete: (input) => this.call({ operation: 'consents.delete', ...input }),
      listByUser: (input) => this.call({ operation: 'consents.list', ...input, now: this.now() }),
    });
    this.replay = Object.freeze<OAuthReplayStore>({
      reserve: (input) =>
        this.call({
          operation: 'replay.reserve',
          ...input,
          now: this.now(),
        }),
    });
    this.maintenance = Object.freeze<OAuthMaintenanceStore>({
      purge: (input) => this.call({ operation: 'maintenance.purge', ...input }),
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
  private async call<T>(command: DurableObjectStorageCommand): Promise<T> {
    if (this.#closed) throw new OAuthStorageError('unavailable', { operation: command.operation });
    try {
      return (await this.binding.getByName(rootName(this.namespace)).execute(command)) as T;
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
  transactionSync<T>(callback: () => T): T;
  getAlarm?(): Promise<number | null>;
  setAlarm?(scheduledTime: number | Date): Promise<void>;
  deleteAlarm?(): Promise<void>;
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
    const result = this.state.storage.transactionSync(() => this.executeTransaction(command));
    await this.syncAlarm();
    return result;
  }

  async alarm(): Promise<void> {
    await this.ready;
    const now = Math.floor(Date.now() / 1000);
    this.state.storage.transactionSync(() => {
      const expiredClients = this.sql
        .exec<
          SqlRow & { key: string }
        >("SELECT key,value,revision,expires_at FROM records WHERE kind='client' AND expires_at IS NOT NULL AND expires_at<=?", now)
        .toArray();
      for (const client of expiredClients) this.deleteClient(client.key, client.revision);
      const expiredGrants = this.sql
        .exec<
          SqlRow & { key: string }
        >("SELECT key,value,revision,expires_at FROM records WHERE kind='grant' AND expires_at IS NOT NULL AND expires_at<=?", now)
        .toArray();
      for (const row of expiredGrants) {
        const grant = this.decodeGrant(row);
        this.revoke({ userId: grant.value.userId, grantId: grant.value.id }, row.revision);
      }
      this.sql.exec(
        "DELETE FROM records WHERE kind IN ('token','consent') AND expires_at IS NOT NULL AND expires_at<=?",
        now
      );
      this.sql.exec('DELETE FROM leases WHERE expires_at <= ?', now);
      this.sql.exec('DELETE FROM replay WHERE expires_at <= ?', now);
    });
    await this.syncAlarm();
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
    this.sql.exec('CREATE INDEX IF NOT EXISTS records_expiry ON records(kind,expires_at)');
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS grants_user ON records(json_extract(value,'$.value.userId'),key) WHERE kind='grant'`
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS grants_client ON records(json_extract(value,'$.value.clientId'),key) WHERE kind='grant'`
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS tokens_grant ON records(json_extract(value,'$.value.userId'),json_extract(value,'$.value.grantId'),key) WHERE kind='token'`
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS consents_user ON records(json_extract(value,'$.value.userId'),key) WHERE kind='consent'`
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
      case 'clients.delete':
        return this.deleteClient(command.clientId, command.expectedRevision);
      case 'clients.list':
        return this.listRecords('client', 'clientId', undefined, command.page, command.now, (row) =>
          this.decodeClient(row)
        );
      case 'grants.get':
        return this.readGrant(command.key, command.now);
      case 'grants.issue':
        return this.issue(command.input);
      case 'grants.list-user':
        return this.listRecords('grant', 'userId', command.userId, command.page, command.now, (row) =>
          this.decodeGrant(row)
        );
      case 'grants.list-client':
        return this.listRecords('grant', 'clientId', command.clientId, command.page, command.now, (row) =>
          this.decodeGrant(row)
        );
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
        return this.createToken(command.input, command.now);
      case 'tokens.delete':
        return this.deleteToken(command.key);
      case 'tokens.list':
        return this.listTokens(command.grant, command.page, command.now);
      case 'consents.get':
        return this.readConsent(command.userId, command.clientId, command.referenceId, command.now);
      case 'consents.cas':
        return this.compareAndSwapConsent(command.consent, command.expectedRevision);
      case 'consents.delete':
        return this.deleteConsent(command);
      case 'consents.list':
        return this.listRecords('consent', 'userId', command.userId, command.page, command.now, (row) =>
          this.decodeConsent(row)
        );
      case 'replay.reserve':
        return this.reserveReplay(command);
      case 'maintenance.purge':
        return this.purge(command);
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
  private decodeConsent(row: SqlRow): StoredConsent {
    const stored = JSON.parse(row.value) as StoredConsent;
    return createStoredConsent(stored.value, stored.metadata);
  }
  private consentKey(userId: string, clientId: string, referenceId?: string): string {
    return JSON.stringify([userId, clientId, referenceId ?? null]);
  }
  private grantKey(key: GrantKey): string {
    return JSON.stringify([key.userId, key.grantId]);
  }
  private grantProvenance(key: string): 'registered' | 'external' | undefined {
    const row = this.row('grant-provenance', key);
    if (!row) return undefined;
    const parsed = JSON.parse(row.value) as { clientKind?: unknown };
    return parsed.clientKind === 'registered' || parsed.clientKind === 'external' ? parsed.clientKind : undefined;
  }
  private tokenKey(key: AccessTokenKey): string {
    return key.tokenId;
  }
  private insert(
    kind: string,
    key: string,
    value: StoredClient | StoredGrant | StoredAccessToken | StoredConsent
  ): CreateResult {
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
    return { status: 'updated' };
  }
  private deleteClient(clientId: string, expectedRevision?: number): DeleteClientResult {
    const client = this.row('client', clientId);
    if (!client) return { status: 'not_found' };
    if (expectedRevision !== undefined && client.revision !== expectedRevision) return { status: 'conflict' };
    const grants = this.sql
      .exec<
        SqlRow & { key: string }
      >("SELECT key,value,revision,expires_at FROM records WHERE kind='grant' AND json_extract(value,'$.value.clientId')=?", clientId)
      .toArray();
    let tokens = 0;
    let deletedGrants = 0;
    for (const grant of grants) {
      if (this.grantProvenance(grant.key) !== 'registered') continue;
      deletedGrants++;
      const value = this.decodeGrant(grant).value;
      tokens += this.sql
        .exec(
          "DELETE FROM records WHERE kind='token' AND json_extract(value,'$.value.userId')=? AND json_extract(value,'$.value.grantId')=? RETURNING key",
          value.userId,
          value.id
        )
        .toArray().length;
      this.sql.exec('DELETE FROM leases WHERE grant_key=?', grant.key);
    }
    this.sql.exec(
      `DELETE FROM records WHERE kind='grant' AND key IN (SELECT key FROM records WHERE kind='grant-provenance' AND json_extract(value,'$.clientKind')='registered' AND json_extract(value,'$.clientId')=?)`,
      clientId
    );
    this.sql.exec(
      `DELETE FROM records WHERE kind='grant-provenance' AND json_extract(value,'$.clientKind')='registered' AND json_extract(value,'$.clientId')=?`,
      clientId
    );
    this.sql.exec("DELETE FROM records WHERE kind='consent' AND json_extract(value,'$.value.clientId')=?", clientId);
    this.sql.exec("DELETE FROM records WHERE kind='client' AND key=?", clientId);
    return { status: 'deleted', deletedGrants, deletedAccessTokens: tokens };
  }
  private listRecords<T>(
    kind: string,
    field: string,
    value: string | undefined,
    page: PageRequest | undefined,
    now: number,
    decode: (row: SqlRow) => T
  ): Page<T> {
    const request = createPageRequest(page);
    const limit = request.limit ?? 1000;
    const after = request.cursor ?? '';
    const rows =
      value === undefined
        ? this.sql
            .exec<
              SqlRow & { key: string }
            >('SELECT key,value,revision,expires_at FROM records WHERE kind=? AND key>? AND (expires_at IS NULL OR expires_at>?) ORDER BY key LIMIT ?', kind, after, now, limit + 1)
            .toArray()
        : this.sql
            .exec<
              SqlRow & { key: string }
            >(`SELECT key,value,revision,expires_at FROM records WHERE kind=? AND key>? AND json_extract(value,'$.value.${field}')=? AND (expires_at IS NULL OR expires_at>?) ORDER BY key LIMIT ?`, kind, after, value, now, limit + 1)
            .toArray();
    const selected = rows.slice(0, limit);
    return createPage(selected.map(decode), rows.length > limit ? selected[selected.length - 1]?.key : undefined);
  }
  private readConsent(
    userId: string,
    clientId: string,
    referenceId: string | undefined,
    now: number
  ): StoredConsent | null {
    const row = this.row('consent', this.consentKey(userId, clientId, referenceId));
    return row ? hideLogicallyExpired(this.decodeConsent(row), now) : null;
  }
  private compareAndSwapConsent(consent: StoredConsent, expectedRevision?: number): ReplaceConsentResult {
    const key = this.consentKey(consent.value.userId, consent.value.clientId, consent.value.referenceId);
    const row = this.row('consent', key);
    if (expectedRevision === undefined)
      return this.insert('consent', key, consent).status === 'created' ? { status: 'created' } : { status: 'conflict' };
    if (!row || row.revision !== expectedRevision) return { status: 'conflict' };
    this.sql.exec(
      'UPDATE records SET value=?,revision=?,expires_at=? WHERE kind=? AND key=? AND revision=?',
      JSON.stringify(consent),
      consent.metadata.revision,
      consent.metadata.expiresAt ?? null,
      'consent',
      key,
      expectedRevision
    );
    return { status: 'updated' };
  }
  private deleteConsent(command: Extract<DurableObjectStorageCommand, { operation: 'consents.delete' }>): DeleteResult {
    const key = this.consentKey(command.userId, command.clientId, command.referenceId);
    const row = this.row('consent', key);
    if (!row) return { status: 'not_found' };
    if (command.expectedRevision !== undefined && row.revision !== command.expectedRevision)
      return { status: 'conflict' };
    this.sql.exec("DELETE FROM records WHERE kind='consent' AND key=?", key);
    return { status: 'deleted' };
  }
  private issue(input: Extract<DurableObjectStorageCommand, { operation: 'grants.issue' }>['input']): IssueGrantResult {
    const key = this.grantKey({ userId: input.grant.value.userId, grantId: input.grant.value.id });
    if (this.row('grant', key)) return { status: 'conflict' };
    if (input.client.kind === 'registered') {
      const client = this.row('client', input.client.clientId);
      if (!client) return { status: 'client_not_found' };
      if (client.revision !== input.client.expectedRevision) return { status: 'client_conflict' };
    }
    if (input.replaceExistingUserClientGrants) {
      const prior = this.sql
        .exec<
          SqlRow & { key: string }
        >("SELECT key,value,revision,expires_at FROM records WHERE kind='grant' AND json_extract(value,'$.value.userId')=? AND json_extract(value,'$.value.clientId')=?", input.grant.value.userId, input.grant.value.clientId)
        .toArray();
      for (const row of prior) {
        const grant = this.decodeGrant(row);
        this.revoke({ userId: grant.value.userId, grantId: grant.value.id });
      }
    }
    this.insert('grant', key, input.grant);
    this.sql.exec(
      `INSERT INTO records(kind,key,value,revision,expires_at) VALUES('grant-provenance',?,?,0,NULL)`,
      key,
      JSON.stringify({ clientKind: input.client.kind, clientId: input.client.clientId })
    );
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
    return (
      stored.id === lease.id &&
      stored.ownerId === lease.ownerId &&
      stored.kind === lease.kind &&
      stored.credentialId === lease.credentialId &&
      stored.callbackIdempotencyKey === lease.callbackIdempotencyKey
    );
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
    this.sql.exec('DELETE FROM records WHERE kind=? AND key=?', 'grant-provenance', physical);
    this.sql.exec('DELETE FROM leases WHERE grant_key=?', physical);
    return { status: 'revoked', deletedAccessTokens: count };
  }
  private createToken(
    input: Extract<DurableObjectStorageCommand, { operation: 'tokens.create' }>['input'],
    now: number
  ): IssueAccessTokenResult {
    const grant = this.row('grant', this.grantKey(input.grant));
    if (!grant || (grant.expires_at !== null && grant.expires_at <= now)) return { status: 'grant_not_found' };
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
  private purge(command: Extract<DurableObjectStorageCommand, { operation: 'maintenance.purge' }>) {
    let remaining = command.limit;
    let grantsChecked = 0;
    let grantsPurged = 0;
    let tokensChecked = 0;
    let tokensPurged = 0;
    const grantPredicate = [
      ...(command.purgeExpiredGrants ? ['g.expires_at IS NOT NULL AND g.expires_at<=?'] : []),
      ...(command.purgeOrphanedGrants ? ["json_extract(p.value,'$.clientKind')='registered' AND c.key IS NULL"] : []),
    ].join(' OR ');
    if (grantPredicate && remaining > 0) {
      const grants = this.sql
        .exec<
          SqlRow & { key: string }
        >(`SELECT g.key,g.value,g.revision,g.expires_at FROM records g LEFT JOIN records p ON p.kind='grant-provenance' AND p.key=g.key LEFT JOIN records c ON c.kind='client' AND c.key=json_extract(g.value,'$.value.clientId') WHERE g.kind='grant' AND (${grantPredicate}) ORDER BY g.key LIMIT ?`, ...(command.purgeExpiredGrants ? [command.now] : []), remaining)
        .toArray();
      grantsChecked = grants.length;
      remaining -= grantsChecked;
      for (const row of grants) {
        const grant = this.decodeGrant(row);
        if (this.revoke({ userId: grant.value.userId, grantId: grant.value.id }).status === 'revoked') {
          grantsPurged++;
        }
      }
    }
    const tokenPredicate = [
      't.expires_at IS NOT NULL AND t.expires_at<=?',
      ...(command.purgeOrphanedTokens ? ['g.key IS NULL'] : []),
    ].join(' OR ');
    if (remaining > 0) {
      const tokens = this.sql
        .exec<
          SqlRow & { key: string }
        >(`SELECT t.key,t.value,t.revision,t.expires_at FROM records t LEFT JOIN records g ON g.kind='grant' AND g.key=json_array(json_extract(t.value,'$.value.userId'),json_extract(t.value,'$.value.grantId')) WHERE t.kind='token' AND (${tokenPredicate}) ORDER BY t.key LIMIT ?`, command.now, remaining)
        .toArray();
      tokensChecked = tokens.length;
      for (const row of tokens) {
        this.sql.exec("DELETE FROM records WHERE kind='token' AND key=?", row.key);
        tokensPurged++;
      }
    }
    const moreGrants =
      grantPredicate !== '' &&
      this.sql
        .exec<{
          present: number;
        }>(
          `SELECT 1 AS present FROM records g LEFT JOIN records p ON p.kind='grant-provenance' AND p.key=g.key LEFT JOIN records c ON c.kind='client' AND c.key=json_extract(g.value,'$.value.clientId') WHERE g.kind='grant' AND (${grantPredicate}) LIMIT 1`,
          ...(command.purgeExpiredGrants ? [command.now] : [])
        )
        .toArray().length > 0;
    const moreTokens =
      this.sql
        .exec<{
          present: number;
        }>(
          `SELECT 1 AS present FROM records t LEFT JOIN records g ON g.kind='grant' AND g.key=json_array(json_extract(t.value,'$.value.userId'),json_extract(t.value,'$.value.grantId')) WHERE t.kind='token' AND (${tokenPredicate}) LIMIT 1`,
          command.now
        )
        .toArray().length > 0;
    return { grantsChecked, grantsPurged, tokensChecked, tokensPurged, done: !moreGrants && !moreTokens };
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
    return { status: inserted ? 'reserved' : 'exists' };
  }
  private async syncAlarm(): Promise<void> {
    if (!this.state.storage.setAlarm) return;
    const row = this.sql
      .exec<{ expires_at: number | null }>(
        `SELECT MIN(expires_at) AS expires_at FROM (
          SELECT expires_at FROM records WHERE expires_at IS NOT NULL
          UNION ALL SELECT expires_at FROM leases
          UNION ALL SELECT expires_at FROM replay
        )`
      )
      .toArray()[0];
    const desired = row?.expires_at === null || row?.expires_at === undefined ? null : row.expires_at * 1000;
    try {
      const current = this.state.storage.getAlarm ? await this.state.storage.getAlarm() : null;
      if (desired === null) {
        if (current !== null && this.state.storage.deleteAlarm) await this.state.storage.deleteAlarm();
      } else if (current !== desired) {
        await this.state.storage.setAlarm(desired);
      }
    } catch {
      // Alarm maintenance is best-effort; logical expiry remains authoritative.
    }
  }
}
