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

/** Guarantees proved by the partitioned Durable Object SQLite implementation. */
export const DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES: OAuthStorageCapabilities = defineOAuthStorageCapabilities({
  consistency: { readAfterWrite: 'strong' },
  clients: { create: 'strong', replace: 'strong' },
  issuance: {
    // Registered-client validation crosses the client and user objects.
    grantOnly: 'best_effort',
    grantWithAccessToken: 'best_effort',
    replaceUserClientGrants: 'best_effort',
    existingGrantAccessToken: 'strong',
  },
  transitions: { authorizationCode: 'strong', refreshToken: 'strong' },
  replayReservation: 'strong',
  revocation: { accessToken: 'strong', grantCascade: 'strong', clientCascade: 'unsupported' },
  consents: { compareAndSwap: 'strong', delete: 'strong' },
  queries: {
    listClients: 'unsupported',
    grantsByUser: 'strong',
    grantsByClient: 'unsupported',
    tokensByGrant: 'strong',
    consentsByUser: 'strong',
    globalMaintenance: 'unsupported',
  },
  expiration: { cleanup: 'scheduled', minimumTtlSeconds: 0 },
});

/** One deterministic Durable Object aggregate. User aggregates own grants, tokens, consent, and transitions. */
export type DurableObjectStorageAggregate =
  | { readonly kind: 'user'; readonly key: string }
  | { readonly kind: 'client'; readonly key: string }
  | { readonly kind: 'replay'; readonly key: string };

/** RPC-safe operation accepted by {@link OAuthStorageObject}. */
export type DurableObjectStorageOperation =
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
        readonly replaceExistingUserClientGrants?: boolean;
      };
    }
  | {
      readonly operation: 'grants.list-user';
      readonly userId: string;
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
    };

/** Routed command accepted by {@link OAuthStorageObject}. */
export type DurableObjectStorageCommand = DurableObjectStorageOperation & {
  readonly namespace: string;
  readonly aggregate: DurableObjectStorageAggregate;
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
 * User-owned records route to one object per namespace and user. Client records
 * and replay reservations use separate deterministic objects or shards. Operations within
 * one user aggregate are strongly atomic; cross-user queries and client cascades
 * are deliberately unsupported without an external authoritative index.
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

async function objectName(namespace: string, aggregate: DurableObjectStorageAggregate): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify([namespace, aggregate.kind, aggregate.key]));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `oauth-do:v2:${aggregate.kind}:${hash}`;
}

function userAggregate(userId: string): DurableObjectStorageAggregate {
  return { kind: 'user', key: userId };
}

function clientAggregate(clientId: string): DurableObjectStorageAggregate {
  return { kind: 'client', key: clientId };
}

function replayAggregate(reservationNamespace: string, keyHash: string): DurableObjectStorageAggregate {
  // One shard per first digest byte bounds object count while retaining strong
  // set-if-absent serialization for each complete replay identifier.
  return { kind: 'replay', key: JSON.stringify([reservationNamespace, keyHash.slice(0, 2)]) };
}

class DurableObjectConnection implements OAuthStorageConnection {
  #closed = false;
  readonly #objectNames = new Map<string, Promise<string>>();
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
      get: (clientId) => this.call(clientAggregate(clientId), { operation: 'clients.get', clientId, now: this.now() }),
      create: async (input) => {
        assertCreateClientInput(input);
        return this.call(clientAggregate(input.client.value.clientId), {
          operation: 'clients.create',
          client: input.client,
        });
      },
      replace: async (input) => {
        assertReplaceClientInput(input);
        return this.call(clientAggregate(input.clientId), {
          operation: 'clients.replace',
          clientId: input.clientId,
          expectedRevision: input.expectedRevision,
          client: input.client,
        });
      },
      deleteWithGrants: () => this.unsupported('clients.deleteWithGrants'),
      list: () => this.unsupported('clients.list'),
    });
    this.grants = Object.freeze<OAuthGrantStore>({
      get: (key) => this.call(userAggregate(key.userId), { operation: 'grants.get', key, now: this.now() }),
      issue: async (input) => {
        assertIssueGrantInput(input);
        assertIssueGrantSupported(DURABLE_OBJECT_SQLITE_STORAGE_CAPABILITIES, input);
        if (input.client.kind === 'registered') {
          const client = await this.call<StoredClient | null>(clientAggregate(input.client.clientId), {
            operation: 'clients.get',
            clientId: input.client.clientId,
            now: this.now(),
          });
          if (!client) return { status: 'client_not_found' };
          if (client.metadata.revision !== input.client.expectedRevision) return { status: 'client_conflict' };
        }
        return this.call(userAggregate(input.grant.value.userId), { operation: 'grants.issue', input });
      },
      listByUser: (input) =>
        this.call(userAggregate(input.userId), { operation: 'grants.list-user', ...input, now: this.now() }),
      listByClient: () => this.unsupported('grants.listByClient'),
      beginTransition: async (input) => {
        assertBeginGrantTransitionInput(input);
        return this.call(userAggregate(input.grant.userId), { operation: 'grants.begin', input });
      },
      commitTransition: async (input) => {
        assertCommitGrantTransitionInput(input);
        return this.call(userAggregate(input.lease.grant.userId), { operation: 'grants.commit', input });
      },
      abortTransition: (input) =>
        this.call(userAggregate(input.lease.grant.userId), { operation: 'grants.abort', input }),
      revoke: (input) =>
        this.call(userAggregate(input.grant.userId), {
          operation: 'grants.revoke',
          key: input.grant,
          expectedRevision: input.expectedRevision,
        }),
    });
    this.accessTokens = Object.freeze<OAuthAccessTokenStore>({
      get: (key) => this.call(userAggregate(key.userId), { operation: 'tokens.get', key, now: this.now() }),
      createForGrant: async (input) => {
        assertIssueAccessTokenInput(input);
        return this.call(userAggregate(input.grant.userId), { operation: 'tokens.create', input, now: this.now() });
      },
      delete: (input) => this.call(userAggregate(input.key.userId), { operation: 'tokens.delete', key: input.key }),
      listByGrant: (input) =>
        this.call(userAggregate(input.grant.userId), {
          operation: 'tokens.list',
          grant: input.grant,
          page: input.page,
          now: this.now(),
        }),
    });
    this.consents = Object.freeze<OAuthConsentStore>({
      get: (input) => this.call(userAggregate(input.userId), { operation: 'consents.get', ...input, now: this.now() }),
      compareAndSwap: async (input) => {
        assertCompareAndSwapConsentInput(input);
        return this.call(userAggregate(input.consent.value.userId), {
          operation: 'consents.cas',
          consent: input.consent,
          expectedRevision: input.expectedRevision,
        });
      },
      delete: (input) => this.call(userAggregate(input.userId), { operation: 'consents.delete', ...input }),
      listByUser: (input) =>
        this.call(userAggregate(input.userId), { operation: 'consents.list', ...input, now: this.now() }),
    });
    this.replay = Object.freeze<OAuthReplayStore>({
      reserve: (input) =>
        this.call(replayAggregate(input.reservationNamespace, input.keyHash), {
          operation: 'replay.reserve',
          ...input,
          now: this.now(),
        }),
    });
    this.maintenance = Object.freeze<OAuthMaintenanceStore>({
      purge: () => this.unsupported('maintenance.purge'),
    });
  }
  close(): void {
    this.#closed = true;
    this.#objectNames.clear();
  }
  private now(): number {
    const value = this.clock();
    if (!Number.isSafeInteger(value) || value < 0)
      throw new OAuthStorageError('invalid_configuration', { operation: 'storage.clock' });
    return value;
  }
  private async unsupported(operation: string): Promise<never> {
    if (this.#closed) throw new OAuthStorageError('unavailable', { operation });
    throw unsupportedStorageOperation(operation);
  }
  private async call<T>(
    aggregate: DurableObjectStorageAggregate,
    operation: DurableObjectStorageOperation
  ): Promise<T> {
    if (this.#closed) throw new OAuthStorageError('unavailable', { operation: operation.operation });
    try {
      const command: DurableObjectStorageCommand = { ...operation, namespace: this.namespace, aggregate };
      const key = `${aggregate.kind}\0${aggregate.key}`;
      let name = this.#objectNames.get(key);
      if (name === undefined) {
        name = objectName(this.namespace, aggregate);
        this.#objectNames.set(key, name);
      }
      return (await this.binding.getByName(await name).execute(command)) as T;
    } catch (error) {
      if (isOAuthStorageError(error)) throw error;
      throw new OAuthStorageError('internal', { cause: error, operation: operation.operation });
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

/** Durable Object implementation owning one keyed aggregate and its local SQLite database. */
export class OAuthStorageObject {
  private readonly sql: SqlStorage;
  private ready: Promise<void>;
  constructor(private readonly state: ObjectState) {
    this.sql = state.storage.sql;
    this.ready = state.blockConcurrencyWhile(async () => this.migrate());
  }

  async execute(command: DurableObjectStorageCommand): Promise<unknown> {
    await this.ready;
    const result = this.state.storage.transactionSync(() => {
      this.bindAggregate(command);
      return this.executeTransaction(command);
    });
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
      for (const client of expiredClients) {
        this.sql.exec("DELETE FROM records WHERE kind='client' AND key=? AND revision=?", client.key, client.revision);
      }
      const expiredGrants = this.sql
        .exec<
          SqlRow & { key: string }
        >("SELECT key,value,revision,expires_at FROM records WHERE kind='grant' AND expires_at IS NOT NULL AND expires_at<=?", now)
        .toArray();
      for (const row of expiredGrants) {
        const grant = this.decode(row, createStoredGrant);
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
    this.state.storage.transactionSync(() => {
      this.sql.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)');
      const current =
        this.sql.exec<{ version: number }>('SELECT MAX(version) AS version FROM schema_migrations').toArray()[0]
          ?.version ?? 0;
      if (current > 2) {
        throw new OAuthStorageError('schema_mismatch', { operation: 'storage.migrate' });
      }
      if (current === 2) return;
      if (current === 0) {
        this.sql.exec(
          'CREATE TABLE records (kind TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, revision INTEGER NOT NULL, expires_at INTEGER, PRIMARY KEY(kind,key))'
        );
        this.sql.exec(
          'CREATE TABLE leases (grant_key TEXT PRIMARY KEY, value TEXT NOT NULL, fence INTEGER NOT NULL, expires_at INTEGER NOT NULL)'
        );
        this.sql.exec('CREATE TABLE fences (grant_key TEXT PRIMARY KEY, value INTEGER NOT NULL)');
        this.sql.exec(
          'CREATE TABLE replay (namespace TEXT NOT NULL, key_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(namespace,key_hash))'
        );
        this.sql.exec('CREATE INDEX records_expiry ON records(kind,expires_at)');
        this.sql.exec('INSERT INTO schema_migrations(version) VALUES (1)');
      }
      this.sql.exec(
        'CREATE TABLE aggregate_metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), namespace TEXT NOT NULL, kind TEXT NOT NULL, aggregate_key TEXT NOT NULL)'
      );
      this.sql.exec('INSERT INTO schema_migrations(version) VALUES (2)');
    });
  }

  private bindAggregate(command: DurableObjectStorageCommand): void {
    this.assertAggregateMatchesOperation(command);
    const aggregate = command.aggregate;
    const created = this.sql
      .exec(
        'INSERT OR IGNORE INTO aggregate_metadata(singleton,namespace,kind,aggregate_key) VALUES(1,?,?,?) RETURNING singleton',
        command.namespace,
        aggregate.kind,
        aggregate.key
      )
      .toArray().length;
    const stored = this.sql
      .exec<{
        namespace: string;
        kind: string;
        aggregate_key: string;
      }>('SELECT namespace,kind,aggregate_key FROM aggregate_metadata WHERE singleton=1')
      .one();
    if (
      stored.namespace !== command.namespace ||
      stored.kind !== aggregate.kind ||
      stored.aggregate_key !== aggregate.key
    ) {
      throw new OAuthStorageError('invalid_configuration', { operation: 'storage.route' });
    }
    if (created && aggregate.kind === 'user') {
      this.sql.exec(
        `CREATE INDEX IF NOT EXISTS grants_client ON records(json_extract(value,'$.value.clientId'),key) WHERE kind='grant'`
      );
      this.sql.exec(
        `CREATE INDEX IF NOT EXISTS tokens_grant ON records(json_extract(value,'$.value.grantId'),key) WHERE kind='token'`
      );
    }
  }

  private assertAggregateMatchesOperation(command: DurableObjectStorageCommand): void {
    const expected: readonly [DurableObjectStorageAggregate['kind'], string] = (() => {
      switch (command.operation) {
        case 'clients.get':
        case 'clients.replace':
          return ['client', command.clientId];
        case 'clients.create':
          return ['client', command.client.value.clientId];
        case 'grants.get':
        case 'grants.revoke':
        case 'tokens.get':
        case 'tokens.delete':
          return ['user', command.key.userId];
        case 'grants.issue':
          return ['user', command.input.grant.value.userId];
        case 'grants.list-user':
        case 'consents.get':
        case 'consents.delete':
        case 'consents.list':
          return ['user', command.userId];
        case 'grants.begin':
          return ['user', command.input.grant.userId];
        case 'grants.commit':
        case 'grants.abort':
          return ['user', command.input.lease.grant.userId];
        case 'tokens.create':
          return ['user', command.input.grant.userId];
        case 'tokens.list':
          return ['user', command.grant.userId];
        case 'consents.cas':
          return ['user', command.consent.value.userId];
        case 'replay.reserve':
          return ['replay', replayAggregate(command.reservationNamespace, command.keyHash).key];
      }
    })();
    if (expected[0] !== command.aggregate.kind || expected[1] !== command.aggregate.key) {
      throw unsupportedStorageOperation(command.operation);
    }
  }

  private executeTransaction(command: DurableObjectStorageCommand): unknown {
    switch (command.operation) {
      case 'clients.get':
        return this.readRecord('client', command.clientId, command.now, createStoredClient);
      case 'clients.create':
        return this.insert('client', command.client.value.clientId, command.client);
      case 'clients.replace':
        return this.replaceClient(command);
      case 'grants.get':
        return this.readRecord('grant', this.grantKey(command.key), command.now, createStoredGrant);
      case 'grants.issue':
        return this.issue(command.input);
      case 'grants.list-user':
        return this.listRecords('grant', command.page, command.now, (row) => this.decode(row, createStoredGrant));
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
        return this.readRecord(
          'consent',
          this.consentKey(command.userId, command.clientId, command.referenceId),
          command.now,
          createStoredConsent
        );
      case 'consents.cas':
        return this.compareAndSwapConsent(command.consent, command.expectedRevision);
      case 'consents.delete':
        return this.deleteConsent(command);
      case 'consents.list':
        return this.listRecords('consent', command.page, command.now, (row) => this.decode(row, createStoredConsent));
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
  private decode<T extends StoredClient | StoredGrant | StoredAccessToken | StoredConsent>(
    row: SqlRow,
    create: (value: T['value'], metadata: T['metadata']) => T
  ): T {
    const stored = JSON.parse(row.value) as T;
    return create(stored.value, stored.metadata);
  }
  private consentKey(userId: string, clientId: string, referenceId?: string): string {
    return JSON.stringify([userId, clientId, referenceId ?? null]);
  }
  private grantKey(key: GrantKey): string {
    return JSON.stringify([key.userId, key.grantId]);
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
  private readRecord<T extends StoredClient | StoredGrant | StoredConsent>(
    kind: string,
    key: string,
    now: number,
    create: (value: T['value'], metadata: T['metadata']) => T
  ): T | null {
    const row = this.row(kind, key);
    return row ? hideLogicallyExpired(this.decode(row, create), now) : null;
  }
  private update(
    kind: string,
    key: string,
    value: StoredClient | StoredGrant | StoredConsent,
    expectedRevision: number
  ): void {
    this.sql.exec(
      'UPDATE records SET value=?,revision=?,expires_at=? WHERE kind=? AND key=? AND revision=?',
      JSON.stringify(value),
      value.metadata.revision,
      value.metadata.expiresAt ?? null,
      kind,
      key,
      expectedRevision
    );
  }
  private readToken(key: AccessTokenKey, now: number): StoredAccessToken | null {
    const row = this.row('token', key.tokenId);
    if (!row) return null;
    const token = this.decode(row, createStoredAccessToken);
    if (token.value.userId !== key.userId || token.value.grantId !== key.grantId) return null;
    return hideLogicallyExpired(token, now);
  }
  private replaceClient(
    command: Extract<DurableObjectStorageCommand, { operation: 'clients.replace' }>
  ): ReplaceResult {
    const row = this.row('client', command.clientId);
    if (!row) return { status: 'not_found' };
    if (row.revision !== command.expectedRevision) return { status: 'conflict' };
    this.update('client', command.clientId, command.client, command.expectedRevision);
    return { status: 'updated' };
  }
  private listRecords<T>(
    kind: string,
    page: PageRequest | undefined,
    now: number,
    decode: (row: SqlRow) => T
  ): Page<T> {
    const request = createPageRequest(page);
    const limit = request.limit ?? 1000;
    const after = request.cursor ?? '';
    const rows = this.sql
      .exec<
        SqlRow & { key: string }
      >('SELECT key,value,revision,expires_at FROM records WHERE kind=? AND key>? AND (expires_at IS NULL OR expires_at>?) ORDER BY key LIMIT ?', kind, after, now, limit + 1)
      .toArray();
    const selected = rows.slice(0, limit);
    return createPage(selected.map(decode), rows.length > limit ? selected[selected.length - 1]?.key : undefined);
  }
  private compareAndSwapConsent(consent: StoredConsent, expectedRevision?: number): ReplaceConsentResult {
    const key = this.consentKey(consent.value.userId, consent.value.clientId, consent.value.referenceId);
    const row = this.row('consent', key);
    if (expectedRevision === undefined)
      return this.insert('consent', key, consent).status === 'created' ? { status: 'created' } : { status: 'conflict' };
    if (!row || row.revision !== expectedRevision) return { status: 'conflict' };
    this.update('consent', key, consent, expectedRevision);
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
    if (input.replaceExistingUserClientGrants) {
      const prior = this.sql
        .exec<
          SqlRow & { key: string }
        >("SELECT key,value,revision,expires_at FROM records WHERE kind='grant' AND json_extract(value,'$.value.clientId')=?", input.grant.value.clientId)
        .toArray();
      for (const row of prior) {
        const grant = this.decode(row, createStoredGrant);
        this.revoke({ userId: grant.value.userId, grantId: grant.value.id });
      }
    }
    this.insert('grant', key, input.grant);
    if (input.accessToken && this.insert('token', input.accessToken.value.id, input.accessToken).status !== 'created')
      throw new OAuthStorageError('conflict', { operation: 'grants.issue' });
    return { status: 'created' };
  }
  private begin(input: BeginGrantTransitionInput): unknown {
    const grant = this.readRecord('grant', this.grantKey(input.grant), input.now, createStoredGrant);
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
    this.update('grant', key, input.grant, input.lease.expectedRevision);
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
        "DELETE FROM records WHERE kind=? AND json_extract(value,'$.value.grantId')=? RETURNING key",
        'token',
        key.grantId
      )
      .toArray().length;
    this.sql.exec('DELETE FROM records WHERE kind=? AND key=?', 'grant', physical);
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
    const row = this.row('token', key.tokenId);
    if (!row) return { status: 'not_found' };
    const token = this.decode(row, createStoredAccessToken);
    if (token.value.userId !== key.userId || token.value.grantId !== key.grantId) return { status: 'not_found' };
    this.sql.exec("DELETE FROM records WHERE kind='token' AND key=?", key.tokenId);
    return { status: 'deleted' };
  }
  private listTokens(grant: GrantKey, page: PageRequest | undefined, now: number): Page<StoredAccessToken> {
    const request = createPageRequest(page);
    const limit = request.limit ?? 1000;
    const after = request.cursor ?? '';
    const rows = this.sql
      .exec<
        SqlRow & { key: string }
      >("SELECT key,value,revision,expires_at FROM records WHERE kind=? AND key>? AND json_extract(value,'$.value.grantId')=? AND (expires_at IS NULL OR expires_at>?) ORDER BY key LIMIT ?", 'token', after, grant.grantId, now, limit + 1)
      .toArray();
    const more = rows.length > limit;
    const selected = rows.slice(0, limit);
    return createPage(
      selected.map((row) => this.decode(row, createStoredAccessToken)),
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
    return { status: inserted ? 'reserved' : 'exists' };
  }
  private async syncAlarm(): Promise<void> {
    if (!this.state.storage.setAlarm) return;
    try {
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
