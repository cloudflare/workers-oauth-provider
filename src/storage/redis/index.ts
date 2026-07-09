import { defineOAuthStorageCapabilities, type OAuthStorageCapabilities } from '../capabilities';
import { OAuthStorageError, isOAuthStorageError } from '../errors';
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
  createStoredConsent,
  createStoredGrant,
  credentialIdFromSha256,
  hideLogicallyExpired,
  type AccessTokenKey,
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
  assertCompareAndSwapConsentInput,
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
  callbackIdempotencyKey,
  createGrantTransitionLease,
  transitionLeaseId,
  transitionOwnerId,
  validateBeginGrantTransitionResult,
  type AbortGrantTransitionInput,
  type AbortGrantTransitionResult,
  type BeginGrantTransitionInput,
  type BeginGrantTransitionResult,
  type CommitGrantTransitionResult,
  type GrantTransitionLease,
  type ValidatedCommitGrantTransitionInput,
} from '../transitions';

/** Atomic compare-and-swap script used for every Redis mutation. */
export const REDIS_NAMESPACE_CAS_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if ARGV[1] == '0' then
  if current ~= false then return 0 end
else
  if current == false or current ~= ARGV[2] then return 0 end
end
redis.call('SET', KEYS[1], ARGV[3])
return 1
`.trim();

/** Minimal binary-safe injected Redis client. It must target the authoritative primary. */
export interface RedisStorageClient {
  get(key: string): Promise<string | null>;
  eval(script: string, keys: readonly string[], args: readonly string[]): Promise<unknown>;
  close?(): void | Promise<void>;
}

/** Configuration for {@link redisStorage}. */
export interface RedisStorageOptions<Env> {
  readonly client: (env: Env) => RedisStorageClient | Promise<RedisStorageClient>;
  readonly namespace?: string;
  readonly now?: () => number;
  readonly randomId?: () => string;
  /** Maximum optimistic CAS retries under contention. Defaults to 64. */
  readonly maximumRetries?: number;
}

/**
 * Guarantees of the script-guarded single-namespace Redis aggregate.
 *
 * Version 1 stores one JSON state document per logical namespace. This gives
 * every mutation one Redis-script atomicity domain, at the cost of O(namespace)
 * mutation work and a practical namespace-size/throughput ceiling.
 */
export const REDIS_STORAGE_CAPABILITIES: OAuthStorageCapabilities = defineOAuthStorageCapabilities({
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

type PlainStored<T> = {
  readonly value: T;
  readonly metadata: {
    readonly schemaVersion: number;
    readonly revision: number;
    readonly createdAt: number;
    readonly expiresAt?: number;
  };
};
type GrantEntry = {
  readonly record: PlainStored<StoredGrant['value']>;
  readonly clientKind: 'registered' | 'external';
};
type ReplayEntry = { readonly expiresAt: number };
type State = {
  schemaVersion: 1;
  generation: number;
  clients: Record<string, PlainStored<StoredClient['value']>>;
  grants: Record<string, GrantEntry>;
  tokens: Record<string, PlainStored<StoredAccessToken['value']>>;
  consents: Record<string, PlainStored<StoredConsent['value']>>;
  replay: Record<string, ReplayEntry>;
  leases: Record<string, GrantTransitionLease>;
  fences: Record<string, number>;
};

/** Creates a strong single-aggregate Redis storage provider. */
export function redisStorage<Env>(options: RedisStorageOptions<Env>): OAuthStorageProvider<Env> {
  if (!options || typeof options.client !== 'function') throw new TypeError('Redis storage requires a client resolver');
  if (options.now !== undefined && typeof options.now !== 'function')
    throw new TypeError('Redis clock must be a function');
  if (options.randomId !== undefined && typeof options.randomId !== 'function') {
    throw new TypeError('Redis randomId must be a function');
  }
  const maximumRetries = options.maximumRetries ?? 64;
  if (!Number.isSafeInteger(maximumRetries) || maximumRetries < 1) {
    throw new TypeError('Redis maximumRetries must be a positive safe integer');
  }
  const namespace = defineStorageNamespace(options.namespace);
  const provider: OAuthStorageProvider<Env> = Object.freeze({
    id: 'redis',
    contractVersion: 1,
    namespace,
    capabilities: REDIS_STORAGE_CAPABILITIES,
    async open(context: OAuthStorageOpenContext<Env>): Promise<OAuthStorageConnection> {
      if (context.namespace !== namespace) {
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      }
      let client: RedisStorageClient;
      try {
        client = await options.client(context.env);
      } catch (cause) {
        throw new OAuthStorageError('unavailable', { cause, operation: 'storage.open' });
      }
      if (!client || typeof client.get !== 'function' || typeof client.eval !== 'function') {
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      }
      const connection = new RedisConnection(
        client,
        namespace,
        options.now ?? (() => Math.floor(Date.now() / 1000)),
        options.randomId ?? (() => crypto.randomUUID()),
        maximumRetries
      );
      assertStorageConnectionNamespace(provider, connection);
      return connection;
    },
  });
  return provider;
}

class RedisConnection implements OAuthStorageConnection {
  readonly clients: OAuthClientStore;
  readonly grants: OAuthGrantStore;
  readonly accessTokens: OAuthAccessTokenStore;
  readonly consents: OAuthConsentStore;
  readonly replay: OAuthReplayStore;
  readonly maintenance: OAuthMaintenanceStore;
  #closed = false;
  #closePromise: Promise<void> | undefined;
  private readonly key: string;

  constructor(
    private readonly client: RedisStorageClient,
    readonly namespace: string,
    private readonly clock: () => number,
    private readonly randomId: () => string,
    private readonly maximumRetries: number
  ) {
    this.key = `{oauth:${encodeURIComponent(namespace)}}:state:v1`;
    this.clients = Object.freeze({
      get: (id: string) => this.run('clients.get', () => this.getClient(id)),
      create: (input: CreateClientInput) => this.run('clients.create', () => this.createClient(input)),
      replace: (input: ReplaceClientInput) => this.run('clients.replace', () => this.replaceClient(input)),
      deleteWithGrants: (input: Parameters<OAuthClientStore['deleteWithGrants']>[0]) =>
        this.run('clients.deleteWithGrants', () => this.deleteClient(input)),
      list: (page?: PageRequest) => this.run('clients.list', () => this.listClients(page)),
    });
    this.grants = Object.freeze({
      get: (key: GrantKey) => this.run('grants.get', () => this.getGrant(key)),
      issue: (input: IssueGrantInput) => this.run('grants.issue', () => this.issue(input)),
      listByUser: (input: Parameters<OAuthGrantStore['listByUser']>[0]) =>
        this.run('grants.listByUser', () => this.listGrants('user', input.userId, input.page)),
      listByClient: (input: Parameters<OAuthGrantStore['listByClient']>[0]) =>
        this.run('grants.listByClient', () => this.listGrants('client', input.clientId, input.page)),
      beginTransition: (input: BeginGrantTransitionInput) =>
        this.run('grants.beginTransition', () => this.begin(input)),
      commitTransition: (input: ValidatedCommitGrantTransitionInput) =>
        this.run('grants.commitTransition', () => this.commit(input)),
      abortTransition: (input: AbortGrantTransitionInput) =>
        this.run('grants.abortTransition', () => this.abort(input)),
      revoke: (input: Parameters<OAuthGrantStore['revoke']>[0]) =>
        this.run('grants.revoke', () => this.revoke(input.grant, input.expectedRevision)),
    });
    this.accessTokens = Object.freeze({
      get: (key: AccessTokenKey) => this.run('accessTokens.get', () => this.getToken(key)),
      createForGrant: (input: IssueAccessTokenInput) =>
        this.run('accessTokens.createForGrant', () => this.createToken(input)),
      delete: (input: Parameters<OAuthAccessTokenStore['delete']>[0]) =>
        this.run('accessTokens.delete', () => this.deleteToken(input.key)),
      listByGrant: (input: Parameters<OAuthAccessTokenStore['listByGrant']>[0]) =>
        this.run('accessTokens.listByGrant', () => this.listTokens(input.grant, input.page)),
    });
    this.consents = Object.freeze({
      get: (input: Parameters<OAuthConsentStore['get']>[0]) => this.run('consents.get', () => this.getConsent(input)),
      compareAndSwap: (input: CompareAndSwapConsentInput) =>
        this.run('consents.compareAndSwap', () => this.compareAndSwapConsent(input)),
      delete: (input: Parameters<OAuthConsentStore['delete']>[0]) =>
        this.run('consents.delete', () => this.deleteConsent(input)),
      listByUser: (input: Parameters<OAuthConsentStore['listByUser']>[0]) =>
        this.run('consents.listByUser', () => this.listConsents(input.userId, input.page)),
    });
    this.replay = Object.freeze({
      reserve: (input: Parameters<OAuthReplayStore['reserve']>[0]) =>
        this.run('replay.reserve', () => this.reserveReplay(input)),
    });
    this.maintenance = Object.freeze({
      purge: (input: PurgeStorageInput) => this.run('maintenance.purge', () => this.purge(input)),
    });
  }

  close(): Promise<void> {
    if (this.#closePromise) return this.#closePromise;
    this.#closed = true;
    this.#closePromise = Promise.resolve(this.client.close?.()).catch((cause) => {
      throw new OAuthStorageError('internal', { cause, operation: 'storage.close' });
    });
    return this.#closePromise;
  }

  private now(): number {
    const value = this.clock();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new OAuthStorageError('invalid_configuration', { operation: 'storage.clock' });
    }
    return value;
  }

  private async read(): Promise<State> {
    const raw = await this.client.get(this.key);
    return decodeState(raw);
  }

  private async mutate<T>(operation: string, mutation: (state: State) => { result: T; changed: boolean }): Promise<T> {
    for (let attempt = 0; attempt < this.maximumRetries; attempt++) {
      const raw = await this.client.get(this.key);
      const state = decodeState(raw);
      const outcome = mutation(state);
      if (!outcome.changed) return outcome.result;
      state.generation++;
      const next = JSON.stringify(state);
      const committed = await this.client.eval(
        REDIS_NAMESPACE_CAS_SCRIPT,
        [this.key],
        [raw === null ? '0' : '1', raw ?? '', next]
      );
      if (committed !== 0 && committed !== 1 && committed !== '0' && committed !== '1') {
        throw new OAuthStorageError('internal', { operation });
      }
      if (Number(committed) === 1) return outcome.result;
    }
    throw new OAuthStorageError('unavailable', { operation, retryable: true });
  }

  private async getClient(id: string): Promise<StoredClient | null> {
    const record = (await this.read()).clients[clientKey(id)];
    return record ? hideLogicallyExpired(decodeClient(record), this.now()) : null;
  }

  private createClient(input: CreateClientInput): Promise<CreateResult> {
    assertCreateClientInput(input);
    return this.mutate('clients.create', (state) => {
      const id = clientKey(input.client.value.clientId);
      const current = state.clients[id];
      if (current && !expired(current, this.now())) return unchanged<CreateResult>({ status: 'conflict' });
      state.clients[id] = input.client;
      return changed<CreateResult>({ status: 'created' });
    });
  }

  private replaceClient(input: ReplaceClientInput): Promise<ReplaceResult> {
    assertReplaceClientInput(input);
    return this.mutate('clients.replace', (state) => {
      const current = state.clients[clientKey(input.clientId)];
      if (!current || expired(current, this.now())) return unchanged<ReplaceResult>({ status: 'not_found' });
      if (current.metadata.revision !== input.expectedRevision) {
        return unchanged<ReplaceResult>({ status: 'conflict' });
      }
      state.clients[clientKey(input.clientId)] = input.client;
      return changed<ReplaceResult>({ status: 'updated' });
    });
  }

  private deleteClient(input: Parameters<OAuthClientStore['deleteWithGrants']>[0]): Promise<DeleteClientResult> {
    return this.mutate('clients.deleteWithGrants', (state) => {
      const client = state.clients[clientKey(input.clientId)];
      if (!client) return unchanged<DeleteClientResult>({ status: 'not_found' });
      if (input.expectedRevision !== undefined && client.metadata.revision !== input.expectedRevision) {
        return unchanged<DeleteClientResult>({ status: 'conflict' });
      }
      let deletedGrants = 0;
      let deletedAccessTokens = 0;
      for (const [key, grant] of Object.entries(state.grants)) {
        if (grant.clientKind !== 'registered' || grant.record.value.clientId !== input.clientId) continue;
        deletedGrants++;
        deletedAccessTokens += deleteGrantChildren(state, key, grant.record.value);
        delete state.grants[key];
      }
      for (const [key, consent] of Object.entries(state.consents)) {
        if (consent.value.clientId === input.clientId) delete state.consents[key];
      }
      delete state.clients[clientKey(input.clientId)];
      return changed({ status: 'deleted', deletedGrants, deletedAccessTokens } as DeleteClientResult);
    });
  }

  private async listClients(page?: PageRequest): Promise<Page<StoredClient>> {
    const state = await this.read();
    return paginate(
      Object.entries(state.clients)
        .filter(([, record]) => !expired(record, this.now()))
        .map(([key, record]) => ({ key, value: decodeClient(record) })),
      page
    );
  }

  private async getGrant(key: GrantKey): Promise<StoredGrant | null> {
    const entry = (await this.read()).grants[grantKey(key)];
    return entry ? hideLogicallyExpired(decodeGrant(entry.record), this.now()) : null;
  }

  private issue(input: IssueGrantInput): Promise<IssueGrantResult> {
    assertIssueGrantInput(input);
    return this.mutate('grants.issue', (state) => {
      const key = grantKey({ userId: input.grant.value.userId, grantId: input.grant.value.id });
      const existingGrant = state.grants[key];
      if (existingGrant && !expired(existingGrant.record, this.now())) {
        return unchanged<IssueGrantResult>({ status: 'conflict' });
      }
      let tokenKeyValue: string | undefined;
      if (input.accessToken) {
        tokenKeyValue = tokenKey({
          userId: input.accessToken.value.userId,
          grantId: input.accessToken.value.grantId,
          tokenId: input.accessToken.value.id,
        });
        const existingToken = state.tokens[tokenKeyValue];
        if (existingToken && !expired(existingToken, this.now())) {
          return unchanged<IssueGrantResult>({ status: 'conflict' });
        }
      }
      if (input.client.kind === 'registered') {
        const client = state.clients[clientKey(input.client.clientId)];
        if (!client || expired(client, this.now())) {
          return unchanged<IssueGrantResult>({ status: 'client_not_found' });
        }
        if (client.metadata.revision !== input.client.expectedRevision) {
          return unchanged<IssueGrantResult>({ status: 'client_conflict' });
        }
      }
      if (existingGrant) {
        deleteGrantChildren(state, key, existingGrant.record.value);
        delete state.grants[key];
      }
      if (input.replaceExistingUserClientGrants) {
        for (const [priorKey, prior] of Object.entries(state.grants)) {
          if (
            prior.record.value.userId === input.grant.value.userId &&
            prior.record.value.clientId === input.grant.value.clientId
          ) {
            deleteGrantChildren(state, priorKey, prior.record.value);
            delete state.grants[priorKey];
          }
        }
      }
      state.grants[key] = { record: input.grant, clientKind: input.client.kind };
      if (tokenKeyValue && input.accessToken) state.tokens[tokenKeyValue] = input.accessToken;
      return changed<IssueGrantResult>({ status: 'created' });
    });
  }

  private async listGrants(kind: 'user' | 'client', value: string, page?: PageRequest): Promise<Page<StoredGrant>> {
    const state = await this.read();
    return paginate(
      Object.entries(state.grants)
        .filter(([, entry]) => {
          if (expired(entry.record, this.now())) return false;
          return kind === 'user' ? entry.record.value.userId === value : entry.record.value.clientId === value;
        })
        .map(([key, entry]) => ({ key, value: decodeGrant(entry.record) })),
      page
    );
  }

  private begin(input: BeginGrantTransitionInput): Promise<BeginGrantTransitionResult> {
    assertBeginGrantTransitionInput(input);
    return this.mutate('grants.beginTransition', (state) => {
      const key = grantKey(input.grant);
      const entry = state.grants[key];
      if (!entry) return unchanged<BeginGrantTransitionResult>({ status: 'not_found' });
      if (expired(entry.record, input.now)) return unchanged<BeginGrantTransitionResult>({ status: 'expired' });
      const grant = decodeGrant(entry.record);
      if (input.kind === 'authorization_code') {
        if (grant.value.authCodeId !== input.credentialId) {
          return unchanged<BeginGrantTransitionResult>({ status: 'invalid_credential' });
        }
        if (!grant.value.authCodeWrappedKey) {
          return unchanged<BeginGrantTransitionResult>({ status: 'already_consumed' });
        }
      } else {
        const current = grant.value.refreshTokenId === input.credentialId;
        const previous = grant.value.previousRefreshTokenId === input.credentialId;
        if (!current && !previous) return unchanged<BeginGrantTransitionResult>({ status: 'invalid_credential' });
        if (
          (current && !grant.value.refreshTokenWrappedKey) ||
          (previous && !grant.value.previousRefreshTokenWrappedKey)
        ) {
          return unchanged<BeginGrantTransitionResult>({ status: 'already_consumed' });
        }
      }
      const existing = state.leases[key];
      if (existing && existing.expiresAt > input.now) {
        return unchanged<BeginGrantTransitionResult>({
          status: 'busy',
          retryAfterSeconds: Math.max(1, existing.expiresAt - input.now),
        });
      }
      const fence = (state.fences[key] ?? 0) + 1;
      state.fences[key] = fence;
      const lease = createGrantTransitionLease(
        {
          id: transitionLeaseId(this.randomId()),
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
      state.leases[key] = lease;
      return changed(
        validateBeginGrantTransitionResult(input, { status: 'acquired', grant, lease }, input.leaseTtlSeconds)
      );
    });
  }

  private commit(input: ValidatedCommitGrantTransitionInput): Promise<CommitGrantTransitionResult> {
    assertCommitGrantTransitionInput(input);
    return this.mutate('grants.commitTransition', (state) => {
      const key = grantKey(input.lease.grant);
      const entry = state.grants[key];
      if (!entry) return unchanged<CommitGrantTransitionResult>({ status: 'not_found' });
      if (expired(entry.record, input.now)) return unchanged<CommitGrantTransitionResult>({ status: 'expired' });
      const lease = state.leases[key];
      if (!sameLease(lease, input.lease) || input.now >= input.lease.expiresAt) {
        return unchanged<CommitGrantTransitionResult>({ status: 'lease_lost' });
      }
      if (entry.record.metadata.revision !== input.lease.expectedRevision) {
        return unchanged<CommitGrantTransitionResult>({ status: 'conflict' });
      }
      const accessKey = tokenKey({
        userId: input.accessToken.value.userId,
        grantId: input.accessToken.value.grantId,
        tokenId: input.accessToken.value.id,
      });
      if (state.tokens[accessKey]) return unchanged<CommitGrantTransitionResult>({ status: 'conflict' });
      state.grants[key] = { ...entry, record: input.grant };
      state.tokens[accessKey] = input.accessToken;
      delete state.leases[key];
      return changed<CommitGrantTransitionResult>({ status: 'committed' });
    });
  }

  private abort(input: AbortGrantTransitionInput): Promise<AbortGrantTransitionResult> {
    return this.mutate('grants.abortTransition', (state) => {
      const key = grantKey(input.lease.grant);
      if (!state.grants[key]) return unchanged<AbortGrantTransitionResult>({ status: 'not_found' });
      if (!sameLease(state.leases[key], input.lease)) {
        return unchanged<AbortGrantTransitionResult>({ status: 'lease_lost' });
      }
      delete state.leases[key];
      return changed<AbortGrantTransitionResult>({ status: 'aborted' });
    });
  }

  private revoke(key: GrantKey, expectedRevision?: number): Promise<RevokeGrantResult> {
    return this.mutate('grants.revoke', (state) => {
      const physical = grantKey(key);
      const entry = state.grants[physical];
      if (!entry) return unchanged<RevokeGrantResult>({ status: 'not_found' });
      if (expectedRevision !== undefined && entry.record.metadata.revision !== expectedRevision) {
        return unchanged<RevokeGrantResult>({ status: 'conflict' });
      }
      const deletedAccessTokens = deleteGrantChildren(state, physical, entry.record.value);
      delete state.grants[physical];
      return changed<RevokeGrantResult>({ status: 'revoked', deletedAccessTokens });
    });
  }

  private async getToken(key: AccessTokenKey): Promise<StoredAccessToken | null> {
    const record = (await this.read()).tokens[tokenKey(key)];
    return record ? hideLogicallyExpired(decodeToken(record), this.now()) : null;
  }

  private createToken(input: IssueAccessTokenInput): Promise<IssueAccessTokenResult> {
    assertIssueAccessTokenInput(input);
    return this.mutate('accessTokens.createForGrant', (state) => {
      const grant = state.grants[grantKey(input.grant)];
      if (!grant || expired(grant.record, this.now())) {
        return unchanged<IssueAccessTokenResult>({ status: 'grant_not_found' });
      }
      if (grant.record.metadata.revision !== input.expectedGrantRevision) {
        return unchanged<IssueAccessTokenResult>({ status: 'grant_conflict' });
      }
      const key = tokenKey({
        userId: input.token.value.userId,
        grantId: input.token.value.grantId,
        tokenId: input.token.value.id,
      });
      const current = state.tokens[key];
      if (current && !expired(current, this.now())) {
        return unchanged<IssueAccessTokenResult>({ status: 'conflict' });
      }
      state.tokens[key] = input.token;
      return changed<IssueAccessTokenResult>({ status: 'created' });
    });
  }

  private deleteToken(key: AccessTokenKey): Promise<DeleteResult> {
    return this.mutate('accessTokens.delete', (state) => {
      const physical = tokenKey(key);
      if (!state.tokens[physical]) return unchanged<DeleteResult>({ status: 'not_found' });
      delete state.tokens[physical];
      return changed<DeleteResult>({ status: 'deleted' });
    });
  }

  private async listTokens(grant: GrantKey, page?: PageRequest): Promise<Page<StoredAccessToken>> {
    const state = await this.read();
    return paginate(
      Object.entries(state.tokens)
        .filter(
          ([, record]) =>
            !expired(record, this.now()) &&
            record.value.userId === grant.userId &&
            record.value.grantId === grant.grantId
        )
        .map(([key, record]) => ({ key, value: decodeToken(record) })),
      page
    );
  }

  private async getConsent(input: Parameters<OAuthConsentStore['get']>[0]): Promise<StoredConsent | null> {
    const record = (await this.read()).consents[consentKey(input)];
    return record ? hideLogicallyExpired(decodeConsent(record), this.now()) : null;
  }

  private compareAndSwapConsent(input: CompareAndSwapConsentInput): Promise<ReplaceConsentResult> {
    assertCompareAndSwapConsentInput(input);
    return this.mutate('consents.compareAndSwap', (state) => {
      const key = consentKey(input.consent.value);
      const current = state.consents[key];
      if (input.expectedRevision === undefined) {
        if (current && !expired(current, this.now())) {
          return unchanged<ReplaceConsentResult>({ status: 'conflict' });
        }
        state.consents[key] = input.consent;
        return changed<ReplaceConsentResult>({ status: 'created' });
      }
      if (!current || current.metadata.revision !== input.expectedRevision) {
        return unchanged<ReplaceConsentResult>({ status: 'conflict' });
      }
      state.consents[key] = input.consent;
      return changed<ReplaceConsentResult>({ status: 'updated' });
    });
  }

  private deleteConsent(input: Parameters<OAuthConsentStore['delete']>[0]): Promise<DeleteResult> {
    return this.mutate('consents.delete', (state) => {
      const key = consentKey(input);
      const current = state.consents[key];
      if (!current) return unchanged<DeleteResult>({ status: 'not_found' });
      if (input.expectedRevision !== undefined && current.metadata.revision !== input.expectedRevision) {
        return unchanged<DeleteResult>({ status: 'conflict' });
      }
      delete state.consents[key];
      return changed<DeleteResult>({ status: 'deleted' });
    });
  }

  private async listConsents(userId: string, page?: PageRequest): Promise<Page<StoredConsent>> {
    const state = await this.read();
    return paginate(
      Object.entries(state.consents)
        .filter(([, record]) => !expired(record, this.now()) && record.value.userId === userId)
        .map(([key, record]) => ({ key, value: decodeConsent(record) })),
      page
    );
  }

  private reserveReplay(input: Parameters<OAuthReplayStore['reserve']>[0]): Promise<ReplayReservationResult> {
    credentialIdFromSha256(input.keyHash);
    return this.mutate('replay.reserve', (state) => {
      const now = this.now();
      if (!Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now) {
        throw new OAuthStorageError('conflict', { operation: 'replay.reserve' });
      }
      const key = replayKey(input.reservationNamespace, input.keyHash);
      const current = state.replay[key];
      if (current && current.expiresAt > now) return unchanged<ReplayReservationResult>({ status: 'exists' });
      state.replay[key] = { expiresAt: input.expiresAt };
      return changed<ReplayReservationResult>({ status: 'reserved' });
    });
  }

  private purge(input: PurgeStorageInput): Promise<PurgeStorageResult> {
    if (!Number.isSafeInteger(input.limit) || input.limit < 1) throw new TypeError('Purge limit must be positive');
    return this.mutate('maintenance.purge', (state) => {
      let remaining = input.limit;
      let grantsChecked = 0;
      let grantsPurged = 0;
      let tokensChecked = 0;
      let tokensPurged = 0;
      const grantCandidates = Object.entries(state.grants)
        .filter(([, entry]) => {
          const orphaned = entry.clientKind === 'registered' && !state.clients[clientKey(entry.record.value.clientId)];
          return (
            (input.purgeExpiredGrants && expired(entry.record, input.now)) || (input.purgeOrphanedGrants && orphaned)
          );
        })
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .slice(0, remaining);
      grantsChecked = grantCandidates.length;
      remaining -= grantsChecked;
      for (const [key, entry] of grantCandidates) {
        deleteGrantChildren(state, key, entry.record.value);
        delete state.grants[key];
        grantsPurged++;
      }
      const tokenCandidates = Object.entries(state.tokens)
        .filter(([, record]) => {
          const orphaned = !state.grants[grantKey({ userId: record.value.userId, grantId: record.value.grantId })];
          return expired(record, input.now) || (input.purgeOrphanedTokens && orphaned);
        })
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .slice(0, remaining);
      tokensChecked = tokenCandidates.length;
      remaining -= tokensChecked;
      for (const [key] of tokenCandidates) {
        delete state.tokens[key];
        tokensPurged++;
      }
      const replayCandidates = Object.entries(state.replay)
        .filter(([, replay]) => replay.expiresAt <= input.now)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .slice(0, remaining);
      for (const [key] of replayCandidates) delete state.replay[key];
      const moreGrants = Object.values(state.grants).some((entry) => {
        const orphaned = entry.clientKind === 'registered' && !state.clients[clientKey(entry.record.value.clientId)];
        return (
          (input.purgeExpiredGrants && expired(entry.record, input.now)) || (input.purgeOrphanedGrants && orphaned)
        );
      });
      const moreTokens = Object.values(state.tokens).some((record) => {
        const orphaned = !state.grants[grantKey({ userId: record.value.userId, grantId: record.value.grantId })];
        return expired(record, input.now) || (input.purgeOrphanedTokens && orphaned);
      });
      const moreReplay = Object.values(state.replay).some((replay) => replay.expiresAt <= input.now);
      return {
        result: {
          grantsChecked,
          grantsPurged,
          tokensChecked,
          tokensPurged,
          done: !moreGrants && !moreTokens && !moreReplay,
        },
        changed: grantsPurged > 0 || tokensPurged > 0 || replayCandidates.length > 0,
      };
    });
  }

  private async run<T>(operation: string, callback: () => Promise<T>): Promise<T> {
    if (this.#closed) throw new OAuthStorageError('unavailable', { operation });
    try {
      return await callback();
    } catch (error) {
      if (isOAuthStorageError(error) || error instanceof TypeError) throw error;
      throw new OAuthStorageError('internal', { cause: error, operation });
    }
  }
}

function emptyState(): State {
  return {
    schemaVersion: 1,
    generation: 0,
    clients: nullMap(),
    grants: nullMap(),
    tokens: nullMap(),
    consents: nullMap(),
    replay: nullMap(),
    leases: nullMap(),
    fences: nullMap(),
  };
}

function decodeState(raw: string | null): State {
  if (raw === null) return emptyState();
  try {
    const value = requirePlainObject(JSON.parse(raw));
    if (value.schemaVersion !== 1) throw new Error('schema version');
    const generation = requireNonNegativeInteger(value.generation, 'generation');
    return {
      schemaVersion: 1,
      generation,
      clients: decodeMap(value.clients, (entry) => {
        const record = requirePlainObject(entry) as unknown as PlainStored<StoredClient['value']>;
        return decodeClient(record);
      }),
      grants: decodeMap(value.grants, (entry) => {
        const grant = requirePlainObject(entry);
        if (grant.clientKind !== 'registered' && grant.clientKind !== 'external') throw new Error('client kind');
        const record = decodeGrant(requirePlainObject(grant.record) as unknown as PlainStored<StoredGrant['value']>);
        return { record, clientKind: grant.clientKind };
      }),
      tokens: decodeMap(value.tokens, (entry) => {
        const record = requirePlainObject(entry) as unknown as PlainStored<StoredAccessToken['value']>;
        return decodeToken(record);
      }),
      consents: decodeMap(value.consents, (entry) => {
        const record = requirePlainObject(entry) as unknown as PlainStored<StoredConsent['value']>;
        return decodeConsent(record);
      }),
      replay: decodeMap(value.replay, (entry) => {
        const replay = requirePlainObject(entry);
        return { expiresAt: requireNonNegativeInteger(replay.expiresAt, 'replay expiry') };
      }),
      leases: decodeMap(value.leases, decodeLease),
      fences: decodeMap(value.fences, (entry) => requireNonNegativeInteger(entry, 'fence')),
    };
  } catch (error) {
    if (isOAuthStorageError(error)) throw error;
    throw new OAuthStorageError('schema_mismatch', { cause: error, operation: 'storage.decode' });
  }
}

function decodeMap<T>(value: unknown, decode: (entry: unknown) => T): Record<string, T> {
  const input = requirePlainObject(value);
  const output = nullMap<T>();
  for (const [key, entry] of Object.entries(input)) output[key] = decode(entry);
  return output;
}

function decodeLease(value: unknown): GrantTransitionLease {
  const lease = requirePlainObject(value);
  const grant = requirePlainObject(lease.grant);
  if (typeof grant.userId !== 'string' || typeof grant.grantId !== 'string') throw new Error('lease grant');
  if (lease.kind !== 'authorization_code' && lease.kind !== 'refresh_token') throw new Error('lease kind');
  const credentialId = credentialIdFromSha256(requireString(lease.credentialId, 'lease credential'));
  return {
    id: transitionLeaseId(requireString(lease.id, 'lease id')),
    grant: { userId: grant.userId, grantId: grant.grantId },
    kind: lease.kind,
    credentialId,
    ownerId: transitionOwnerId(requireString(lease.ownerId, 'lease owner')),
    fence: requirePositiveInteger(lease.fence, 'lease fence'),
    expectedRevision: requireNonNegativeInteger(lease.expectedRevision, 'lease revision'),
    expiresAt: requireNonNegativeInteger(lease.expiresAt, 'lease expiry'),
    callbackIdempotencyKey: callbackIdempotencyKey(requireString(lease.callbackIdempotencyKey, 'lease callback key')),
  };
}

function requirePlainObject(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('plain object');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error('unsafe prototype');
  return value as Record<string, unknown>;
}
function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string') throw new Error(name);
  return value;
}
function requireNonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error(name);
  return value as number;
}
function requirePositiveInteger(value: unknown, name: string): number {
  const number = requireNonNegativeInteger(value, name);
  if (number < 1) throw new Error(name);
  return number;
}
function nullMap<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

function decodeClient(record: PlainStored<StoredClient['value']>): StoredClient {
  return createStoredClient(record.value, record.metadata);
}
function decodeGrant(record: PlainStored<StoredGrant['value']>): StoredGrant {
  return createStoredGrant(record.value, record.metadata);
}
function decodeToken(record: PlainStored<StoredAccessToken['value']>): StoredAccessToken {
  return createStoredAccessToken(record.value, record.metadata);
}
function decodeConsent(record: PlainStored<StoredConsent['value']>): StoredConsent {
  return createStoredConsent(record.value, record.metadata);
}
function expired(record: PlainStored<unknown>, now: number): boolean {
  return record.metadata.expiresAt !== undefined && record.metadata.expiresAt <= now;
}
function clientKey(clientId: string): string {
  return JSON.stringify([clientId]);
}
function grantKey(key: GrantKey): string {
  return JSON.stringify([key.userId, key.grantId]);
}
function tokenKey(key: AccessTokenKey): string {
  return JSON.stringify([key.userId, key.grantId, key.tokenId]);
}
function consentKey(input: { userId: string; clientId: string; referenceId?: string }): string {
  return JSON.stringify([input.userId, input.clientId, input.referenceId ?? null]);
}
function replayKey(namespace: string, hash: string): string {
  return JSON.stringify([namespace, hash]);
}
function deleteGrantChildren(state: State, physicalGrantKey: string, grant: StoredGrant['value']): number {
  let count = 0;
  for (const [key, token] of Object.entries(state.tokens)) {
    if (token.value.userId === grant.userId && token.value.grantId === grant.id) {
      delete state.tokens[key];
      count++;
    }
  }
  delete state.leases[physicalGrantKey];
  return count;
}
function sameLease(current: GrantTransitionLease | undefined, expected: GrantTransitionLease): boolean {
  return (
    !!current &&
    current.id === expected.id &&
    current.ownerId === expected.ownerId &&
    current.kind === expected.kind &&
    current.credentialId === expected.credentialId &&
    current.callbackIdempotencyKey === expected.callbackIdempotencyKey &&
    current.fence === expected.fence &&
    current.expectedRevision === expected.expectedRevision &&
    current.expiresAt === expected.expiresAt
  );
}
function changed<T>(result: T): { result: T; changed: true } {
  return { result, changed: true };
}
function unchanged<T>(result: T): { result: T; changed: false } {
  return { result, changed: false };
}
function paginate<T>(items: Array<{ key: string; value: T }>, request?: PageRequest): Page<T> {
  const page = createPageRequest(request);
  const limit = page.limit ?? 1000;
  const sorted = items.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const start = page.cursor === undefined ? 0 : sorted.findIndex((item) => item.key > page.cursor!);
  const selected = sorted.slice(start < 0 ? sorted.length : start, (start < 0 ? sorted.length : start) + limit);
  const last = selected[selected.length - 1];
  const hasMore = last !== undefined && sorted.some((item) => item.key > last.key);
  return createPage(
    selected.map((item) => item.value),
    hasMore ? last.key : undefined
  );
}
