import {
  assertStorageOperationSupported,
  defineOAuthStorageCapabilities,
  type OAuthStorageCapabilities,
} from '../capabilities';
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
  DeleteClientResult,
  DeleteResult,
  IssueAccessTokenResult,
  IssueGrantResult,
  ReplaceResult,
  ReplayReservationResult,
  RevokeGrantResult,
} from '../results';
import { assertStoredAccessToken, assertStoredClient, assertStoredGrant } from '../records';
import {
  assertCreateClientInput,
  assertIssueAccessTokenInput,
  assertIssueGrantInput,
  assertIssueGrantSupported,
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
import {
  decodeKvAccessToken,
  decodeKvAccessTokenParent,
  decodeKvClient,
  decodeKvGrant,
  encodeKvRecord,
  KV_EXPIRATION_CLAMP_MARGIN_SECONDS,
  KV_MIN_EXPIRATION_TTL_SECONDS,
  kvAccessTokenPutOptions,
  kvGrantPutOptions,
} from './codec';
import {
  kvAccessTokenKey,
  kvAccessTokenPrefix,
  kvClientKey,
  kvClientPrefix,
  kvGrantKey,
  kvGrantPrefix,
  kvReplayKey,
} from './keys';

/** Static capability profile of the legacy-compatible Workers KV adapter. */
export const WORKERS_KV_STORAGE_CAPABILITIES: OAuthStorageCapabilities = defineOAuthStorageCapabilities({
  consistency: { readAfterWrite: 'eventual' },
  clients: { create: 'best_effort', replace: 'best_effort' },
  issuance: {
    grantOnly: 'best_effort',
    grantWithAccessToken: 'best_effort',
    replaceUserClientGrants: 'best_effort',
    existingGrantAccessToken: 'best_effort',
  },
  transitions: { authorizationCode: 'best_effort', refreshToken: 'best_effort' },
  replayReservation: 'best_effort',
  revocation: { accessToken: 'best_effort', grantCascade: 'best_effort', clientCascade: 'best_effort' },
  consents: { compareAndSwap: 'unsupported', delete: 'unsupported' },
  queries: {
    listClients: 'eventual',
    grantsByUser: 'eventual',
    grantsByClient: 'eventual',
    tokensByGrant: 'eventual',
    consentsByUser: 'unsupported',
    globalMaintenance: 'eventual',
  },
  expiration: { cleanup: 'native', minimumTtlSeconds: KV_MIN_EXPIRATION_TTL_SECONDS },
});

/** Configuration for {@link workersKvStorage}. */
export interface WorkersKvStorageOptions<Env> {
  /** Resolves the Workers KV binding from the request environment. */
  readonly binding: (env: Env) => KVNamespace;
  /** Logical namespace. `default` preserves all existing physical keys. */
  readonly namespace?: string;
  /** Clock used by logical expiry and physical TTL calculations. */
  readonly now?: () => number;
}

/** Creates the built-in legacy-compatible Workers KV storage provider. */
export function workersKvStorage<Env>(options: WorkersKvStorageOptions<Env>): OAuthStorageProvider<Env> {
  if (typeof options !== 'object' || options === null || typeof options.binding !== 'function') {
    throw new TypeError('Workers KV storage requires a binding resolver');
  }
  if (options.now !== undefined && typeof options.now !== 'function') {
    throw new TypeError('Workers KV storage clock must be a function');
  }
  const namespace = defineStorageNamespace(options.namespace);
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  return Object.freeze({
    id: 'cloudflare-kv',
    contractVersion: 1 as const,
    namespace,
    capabilities: WORKERS_KV_STORAGE_CAPABILITIES,
    open(context: OAuthStorageOpenContext<Env>): OAuthStorageConnection {
      if (context.namespace !== namespace) {
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      }
      let kv: KVNamespace;
      try {
        kv = options.binding(context.env);
      } catch (error) {
        throw new OAuthStorageError('invalid_configuration', {
          cause: error,
          operation: 'storage.open',
        });
      }
      if (
        !kv ||
        typeof kv.get !== 'function' ||
        typeof kv.put !== 'function' ||
        typeof kv.delete !== 'function' ||
        typeof kv.list !== 'function'
      ) {
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      }
      const connection = new WorkersKvStorageConnection(kv, namespace, now);
      assertStorageConnectionNamespace({ namespace }, connection);
      return connection;
    },
  });
}

class WorkersKvStorageConnection implements OAuthStorageConnection {
  readonly clients: OAuthClientStore;
  readonly grants: OAuthGrantStore;
  readonly accessTokens: OAuthAccessTokenStore;
  readonly consents: OAuthConsentStore;
  readonly replay: OAuthReplayStore;
  readonly maintenance: OAuthMaintenanceStore;
  #closed = false;

  constructor(
    private readonly kv: KVNamespace,
    readonly namespace: string,
    private readonly clock: () => number
  ) {
    this.clients = this.createClientStore();
    this.grants = this.createGrantStore();
    this.accessTokens = this.createAccessTokenStore();
    this.consents = this.createConsentStore();
    this.replay = this.createReplayStore();
    this.maintenance = this.createMaintenanceStore();
  }

  close(): void {
    this.#closed = true;
  }

  private createClientStore(): OAuthClientStore {
    const store: OAuthClientStore = {
      get: (clientId) => this.run('clients.get', async () => this.getClient(clientId)),
      create: (input) => this.run('clients.create', async () => this.createClient(input)),
      replace: (input) => this.run('clients.replace', async () => this.replaceClient(input)),
      deleteWithGrants: (input) => this.run('clients.deleteWithGrants', async () => this.deleteClientWithGrants(input)),
      list: (input) => this.run('clients.list', async () => this.listClients(input)),
    };
    return Object.freeze(store);
  }

  private createGrantStore(): OAuthGrantStore {
    const store: OAuthGrantStore = {
      get: (key) => this.run('grants.get', async () => this.getGrant(key)),
      issue: (input) => this.run('grants.issue', async () => this.issueGrant(input)),
      listByUser: (input) => this.run('grants.listByUser', async () => this.listGrantsByUser(input)),
      listByClient: (input) => this.run('grants.listByClient', async () => this.listGrantsByClient(input)),
      beginTransition: (input) => this.run('grants.beginTransition', async () => this.beginGrantTransition(input)),
      commitTransition: (input) => this.run('grants.commitTransition', async () => this.commitGrantTransition(input)),
      abortTransition: (input) => this.run('grants.abortTransition', async () => this.abortGrantTransition(input)),
      revoke: (input) => this.run('grants.revoke', async () => this.revokeGrant(input.grant, input.expectedRevision)),
    };
    return Object.freeze(store);
  }

  private createAccessTokenStore(): OAuthAccessTokenStore {
    const store: OAuthAccessTokenStore = {
      get: (key) => this.run('accessTokens.get', async () => this.getAccessToken(key)),
      createForGrant: (input) =>
        this.run('accessTokens.createForGrant', async () => this.createAccessTokenForGrant(input)),
      delete: (input) => this.run('accessTokens.delete', async () => this.deleteAccessToken(input.key)),
      listByGrant: (input) =>
        this.run('accessTokens.listByGrant', async () => this.listAccessTokensByGrant(input.grant, input.page)),
    };
    return Object.freeze(store);
  }

  private createConsentStore(): OAuthConsentStore {
    const store: OAuthConsentStore = {
      get: () =>
        this.run('consents.get', async () => {
          throw unsupportedStorageOperation('consents.get');
        }),
      compareAndSwap: (_input: CompareAndSwapConsentInput) =>
        this.run('consents.compareAndSwap', async () => {
          throw unsupportedStorageOperation('consents.compareAndSwap');
        }),
      delete: () =>
        this.run('consents.delete', async () => {
          throw unsupportedStorageOperation('consents.delete');
        }),
      listByUser: () =>
        this.run('consents.listByUser', async () => {
          throw unsupportedStorageOperation('consents.listByUser');
        }),
    };
    return Object.freeze(store);
  }

  private createReplayStore(): OAuthReplayStore {
    const store: OAuthReplayStore = {
      reserve: (input) => this.run('replay.reserve', async () => this.reserveReplay(input)),
    };
    return Object.freeze(store);
  }

  private createMaintenanceStore(): OAuthMaintenanceStore {
    const store: OAuthMaintenanceStore = {
      purge: (input) => this.run('maintenance.purge', async () => this.purge(input)),
    };
    return Object.freeze(store);
  }

  private async getClient(clientId: string): Promise<StoredClient | null> {
    const value = await this.kv.get(kvClientKey(this.namespace, clientId), { type: 'json' });
    return value === null ? null : hideLogicallyExpired(decodeKvClient(value), this.now());
  }

  private async createClient(input: CreateClientInput): Promise<CreateResult> {
    assertCreateClientInput(input);
    assertStoredClient(input.client);
    assertStorageOperationSupported(WORKERS_KV_STORAGE_CAPABILITIES.clients.create, 'clients.create');
    const key = kvClientKey(this.namespace, input.client.value.clientId);
    if ((await this.kv.get(key)) !== null) return { status: 'conflict' };
    await this.kv.put(key, encodeKvRecord(input.client), this.expirationOptions(input.client.metadata.expiresAt));
    return { status: 'created' };
  }

  private async replaceClient(input: ReplaceClientInput): Promise<ReplaceResult> {
    assertReplaceClientInput(input);
    assertStoredClient(input.client);
    assertStorageOperationSupported(WORKERS_KV_STORAGE_CAPABILITIES.clients.replace, 'clients.replace');
    const current = await this.getClient(input.clientId);
    if (current === null) return { status: 'not_found' };
    if (current.metadata.revision !== input.expectedRevision) return { status: 'conflict' };
    await this.kv.put(
      kvClientKey(this.namespace, input.clientId),
      encodeKvRecord(input.client),
      this.expirationOptions(input.client.metadata.expiresAt)
    );
    return { status: 'updated' };
  }

  private async listClients(input: PageRequest = {}): Promise<Page<StoredClient>> {
    return this.listDecoded(kvClientPrefix(this.namespace), input, (value) =>
      hideLogicallyExpired(decodeKvClient(value), this.now())
    );
  }

  private async deleteClientWithGrants(input: {
    readonly clientId: string;
    readonly expectedRevision?: number;
  }): Promise<DeleteClientResult> {
    const client = await this.getClient(input.clientId);
    if (
      client !== null &&
      input.expectedRevision !== undefined &&
      input.expectedRevision !== client.metadata.revision
    ) {
      return { status: 'conflict' };
    }
    let deletedGrants = 0;
    let deletedAccessTokens = 0;
    const grants: GrantKey[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.list(kvGrantPrefix(this.namespace), { cursor });
      for (const key of page.keys) {
        const raw = await this.kv.get(key.name, { type: 'json' });
        if (raw === null) continue;
        const grant = decodeKvGrant(raw);
        if (grant.value.clientId === input.clientId) {
          grants.push({ userId: grant.value.userId, grantId: grant.value.id });
        }
      }
      cursor = page.cursor;
    } while (cursor !== undefined);
    for (const grant of grants) {
      const result = await this.revokeGrant(grant, undefined);
      if (result.status === 'revoked') {
        deletedGrants++;
        deletedAccessTokens += result.deletedAccessTokens;
      }
    }
    await this.kv.delete(kvClientKey(this.namespace, input.clientId));
    return client === null && deletedGrants === 0
      ? { status: 'not_found' }
      : { status: 'deleted', deletedGrants, deletedAccessTokens };
  }

  private async getGrant(key: GrantKey): Promise<StoredGrant | null> {
    const grant = await this.getGrantRaw(key);
    return grant === null ? null : hideLogicallyExpired(grant, this.now());
  }

  private async getGrantRaw(key: GrantKey): Promise<StoredGrant | null> {
    const value = await this.kv.get(kvGrantKey(this.namespace, key), { type: 'json' });
    return value === null ? null : decodeKvGrant(value);
  }

  private async issueGrant(input: IssueGrantInput): Promise<IssueGrantResult> {
    assertIssueGrantInput(input);
    assertIssueGrantSupported(WORKERS_KV_STORAGE_CAPABILITIES, input);
    assertStoredGrant(input.grant);
    if (input.accessToken !== undefined) assertStoredAccessToken(input.accessToken);
    const key = kvGrantKey(this.namespace, {
      userId: input.grant.value.userId,
      grantId: input.grant.value.id,
    });
    if ((await this.kv.get(key)) !== null) return { status: 'conflict' };
    if (input.client.kind === 'registered') {
      const client = await this.getClient(input.client.clientId);
      if (client === null) return { status: 'client_not_found' };
      if (client.metadata.revision !== input.client.expectedRevision) return { status: 'client_conflict' };
    }

    let priorGrants: StoredGrant[] = [];
    if (input.replaceExistingUserClientGrants === true) {
      priorGrants = await this.collectUserClientGrants(
        input.grant.value.userId,
        input.grant.value.clientId,
        input.grant.value.id,
        input.replacementPageSize
      );
    }

    await this.putGrant(input.grant);
    if (input.accessToken !== undefined) await this.putAccessToken(input.accessToken);
    for (const prior of priorGrants) {
      try {
        await this.revokeGrant({ userId: prior.value.userId, grantId: prior.value.id }, undefined);
      } catch {
        // Preserve legacy semantics: once new issuance succeeds, replacement
        // cleanup is best-effort and must not fail authorization.
      }
    }
    return { status: 'created' };
  }

  private async listGrantsByUser(input: {
    readonly userId: string;
    readonly page?: PageRequest;
  }): Promise<Page<StoredGrant>> {
    return this.listGrantRecords(kvGrantPrefix(this.namespace, input.userId), input.page);
  }

  private async listGrantsByClient(input: {
    readonly clientId: string;
    readonly page?: PageRequest;
  }): Promise<Page<StoredGrant>> {
    return this.listDecoded(kvGrantPrefix(this.namespace), input.page, (value) => {
      const grant = hideLogicallyExpired(decodeKvGrant(value), this.now());
      return grant?.value.clientId === input.clientId ? grant : null;
    });
  }

  /**
   * Returns an advisory compatibility lease. KV cannot exclude another caller,
   * persist a monotonic fence, or make commit atomic; the descriptor therefore
   * advertises `best_effort`, never `strong`.
   */
  private async beginGrantTransition(input: BeginGrantTransitionInput): Promise<BeginGrantTransitionResult> {
    assertBeginGrantTransitionInput(input);
    const guarantee =
      input.kind === 'authorization_code'
        ? WORKERS_KV_STORAGE_CAPABILITIES.transitions.authorizationCode
        : WORKERS_KV_STORAGE_CAPABILITIES.transitions.refreshToken;
    assertStorageOperationSupported(guarantee, 'grants.beginTransition');
    const grant = await this.getGrantRaw(input.grant);
    if (grant === null) return { status: 'not_found' };
    if (grant.metadata.expiresAt !== undefined && grant.metadata.expiresAt <= input.now) {
      return { status: 'expired' };
    }

    if (input.kind === 'authorization_code') {
      if (grant.value.authCodeId !== input.credentialId) return { status: 'invalid_credential' };
      if (grant.value.authCodeWrappedKey === undefined) return { status: 'already_consumed' };
    } else {
      const current = grant.value.refreshTokenId === input.credentialId;
      const previous = grant.value.previousRefreshTokenId === input.credentialId;
      if (!current && !previous) return { status: 'invalid_credential' };
      if (current && grant.value.refreshTokenWrappedKey === undefined) return { status: 'invalid_credential' };
      if (previous && grant.value.previousRefreshTokenWrappedKey === undefined) return { status: 'invalid_credential' };
    }

    const lease = createGrantTransitionLease(
      {
        id: transitionLeaseId(this.randomId()),
        grant: input.grant,
        kind: input.kind,
        credentialId: input.credentialId,
        ownerId: input.ownerId,
        fence: 1,
        expectedRevision: grant.metadata.revision,
        expiresAt: input.now + input.leaseTtlSeconds,
        callbackIdempotencyKey: input.callbackIdempotencyKey,
      },
      input.now,
      input.leaseTtlSeconds
    );
    return validateBeginGrantTransitionResult(input, { status: 'acquired', grant, lease }, input.leaseTtlSeconds);
  }

  private async commitGrantTransition(
    input: ValidatedCommitGrantTransitionInput
  ): Promise<CommitGrantTransitionResult> {
    assertCommitGrantTransitionInput(input);
    const current = await this.getGrant(input.lease.grant);
    if (current === null) return { status: 'not_found' };
    if (input.now >= input.lease.expiresAt) return { status: 'lease_lost' };
    if (current.metadata.revision !== input.lease.expectedRevision) return { status: 'conflict' };
    const credentialStillMatches =
      input.lease.kind === 'authorization_code'
        ? current.value.authCodeId === input.lease.credentialId && current.value.authCodeWrappedKey !== undefined
        : (current.value.refreshTokenId === input.lease.credentialId &&
            current.value.refreshTokenWrappedKey !== undefined) ||
          (current.value.previousRefreshTokenId === input.lease.credentialId &&
            current.value.previousRefreshTokenWrappedKey !== undefined);
    if (!credentialStillMatches) return { status: 'conflict' };
    await this.putGrant(input.grant);
    await this.putAccessToken(input.accessToken);
    return { status: 'committed' };
  }

  private async abortGrantTransition(_input: AbortGrantTransitionInput): Promise<AbortGrantTransitionResult> {
    return { status: 'aborted' };
  }

  private async revokeGrant(key: GrantKey, expectedRevision?: number): Promise<RevokeGrantResult> {
    const current = await this.getGrantRaw(key);
    if (current === null) return { status: 'not_found' };
    if (expectedRevision !== undefined && current.metadata.revision !== expectedRevision) {
      return { status: 'conflict' };
    }
    let deletedAccessTokens = 0;
    while (true) {
      const page = await this.list(kvAccessTokenPrefix(this.namespace, key), {});
      if (page.keys.length === 0) break;
      await Promise.all(page.keys.map(({ name }) => this.kv.delete(name)));
      deletedAccessTokens += page.keys.length;
      if (page.cursor === undefined) break;
      // Restart after deletion so offset-style test doubles cannot skip keys.
    }
    await this.kv.delete(kvGrantKey(this.namespace, key));
    return { status: 'revoked', deletedAccessTokens };
  }

  private async getAccessToken(key: AccessTokenKey): Promise<StoredAccessToken | null> {
    const value = await this.kv.get(kvAccessTokenKey(this.namespace, key), { type: 'json' });
    return value === null ? null : hideLogicallyExpired(decodeKvAccessToken(value), this.now());
  }

  private async createAccessTokenForGrant(input: IssueAccessTokenInput): Promise<IssueAccessTokenResult> {
    assertIssueAccessTokenInput(input);
    assertStorageOperationSupported(
      WORKERS_KV_STORAGE_CAPABILITIES.issuance.existingGrantAccessToken,
      'accessTokens.createForGrant'
    );
    assertStoredAccessToken(input.token);
    const grant = await this.getGrant(input.grant);
    if (grant === null) return { status: 'grant_not_found' };
    if (grant.metadata.revision !== input.expectedGrantRevision) return { status: 'grant_conflict' };
    const key: AccessTokenKey = {
      userId: input.token.value.userId,
      grantId: input.token.value.grantId,
      tokenId: input.token.value.id,
    };
    if ((await this.kv.get(kvAccessTokenKey(this.namespace, key))) !== null) return { status: 'conflict' };
    await this.putAccessToken(input.token);
    return { status: 'created' };
  }

  private async deleteAccessToken(key: AccessTokenKey): Promise<DeleteResult> {
    const physicalKey = kvAccessTokenKey(this.namespace, key);
    if ((await this.kv.get(physicalKey)) === null) return { status: 'not_found' };
    await this.kv.delete(physicalKey);
    return { status: 'deleted' };
  }

  private async listAccessTokensByGrant(grant: GrantKey, page?: PageRequest): Promise<Page<StoredAccessToken>> {
    return this.listDecoded(kvAccessTokenPrefix(this.namespace, grant), page, (value) =>
      hideLogicallyExpired(decodeKvAccessToken(value), this.now())
    );
  }

  private async reserveReplay(input: {
    readonly reservationNamespace: string;
    readonly keyHash: AccessTokenKey['tokenId'];
    readonly expiresAt: number;
  }): Promise<ReplayReservationResult> {
    assertStorageOperationSupported(WORKERS_KV_STORAGE_CAPABILITIES.replayReservation, 'replay.reserve');
    if (
      input.reservationNamespace.length < 1 ||
      input.reservationNamespace.length > 128 ||
      input.reservationNamespace.trim() !== input.reservationNamespace ||
      /[\u0000-\u001f\u007f]/.test(input.reservationNamespace)
    ) {
      throw new OAuthStorageError('invalid_configuration', { operation: 'replay.reserve' });
    }
    credentialIdFromSha256(input.keyHash);
    const now = this.now();
    if (!Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now) {
      throw new OAuthStorageError('conflict', { operation: 'replay.reserve' });
    }
    const key = kvReplayKey(this.namespace, input.reservationNamespace, input.keyHash);
    if ((await this.kv.get(key)) !== null) return { status: 'exists' };
    const expirationTtl = Math.max(
      KV_MIN_EXPIRATION_TTL_SECONDS + KV_EXPIRATION_CLAMP_MARGIN_SECONDS,
      input.expiresAt - now
    );
    await this.kv.put(key, '1', { expirationTtl });
    return { status: 'reserved' };
  }

  private async purge(input: PurgeStorageInput): Promise<PurgeStorageResult> {
    if (!Number.isSafeInteger(input.limit) || input.limit < 1 || !Number.isSafeInteger(input.now)) {
      throw new OAuthStorageError('invalid_configuration', { operation: 'maintenance.purge' });
    }
    const result: PurgeStorageResult = {
      grantsChecked: 0,
      grantsPurged: 0,
      tokensChecked: 0,
      tokensPurged: 0,
      done: false,
    };

    let grantsDone = !(input.purgeExpiredGrants || input.purgeOrphanedGrants);
    let grantCursor: string | undefined;
    const knownClients = new Map<string, boolean>();
    while (!grantsDone && result.grantsChecked < input.limit) {
      const page = await this.list(kvGrantPrefix(this.namespace), {
        limit: Math.min(1000, input.limit - result.grantsChecked),
        ...(grantCursor === undefined ? {} : { cursor: grantCursor }),
      });
      let deletedFromPage = false;
      for (const key of page.keys) {
        (result as { grantsChecked: number }).grantsChecked++;
        const value = await this.kv.get(key.name, { type: 'json' });
        if (value === null) continue;
        const grant = decodeKvGrant(value);
        let shouldPurge =
          input.purgeExpiredGrants && grant.metadata.expiresAt !== undefined && grant.metadata.expiresAt <= input.now;
        if (!shouldPurge && input.purgeOrphanedGrants && !isClientMetadataUrl(grant.value.clientId)) {
          let exists = knownClients.get(grant.value.clientId);
          if (exists === undefined) {
            exists = (await this.kv.get(kvClientKey(this.namespace, grant.value.clientId))) !== null;
            knownClients.set(grant.value.clientId, exists);
          }
          shouldPurge = !exists;
        }
        if (shouldPurge) {
          const revoked = await this.revokeGrant({ userId: grant.value.userId, grantId: grant.value.id }, undefined);
          if (revoked.status === 'revoked') {
            (result as { grantsPurged: number }).grantsPurged++;
            deletedFromPage = true;
          }
        }
      }
      grantsDone = page.cursor === undefined;
      grantCursor = deletedFromPage ? undefined : page.cursor;
    }
    if (!grantsDone) return result;

    let tokensDone = !input.purgeOrphanedTokens;
    let tokenCursor: string | undefined;
    const knownGrants = new Map<string, boolean>();
    while (!tokensDone && result.tokensChecked < input.limit) {
      const page = await this.list(kvAccessTokenPrefix(this.namespace), {
        limit: Math.min(1000, input.limit - result.tokensChecked),
        ...(tokenCursor === undefined ? {} : { cursor: tokenCursor }),
      });
      let deletedFromPage = false;
      for (const key of page.keys) {
        (result as { tokensChecked: number }).tokensChecked++;
        const value = await this.kv.get(key.name, { type: 'json' });
        if (value === null) continue;
        const token = decodeKvAccessTokenParent(value);
        const grantKey = kvGrantKey(this.namespace, token);
        let exists = knownGrants.get(grantKey);
        if (exists === undefined) {
          exists = (await this.kv.get(grantKey)) !== null;
          knownGrants.set(grantKey, exists);
        }
        if (!exists) {
          await this.kv.delete(key.name);
          (result as { tokensPurged: number }).tokensPurged++;
          deletedFromPage = true;
        }
      }
      tokensDone = page.cursor === undefined;
      tokenCursor = deletedFromPage ? undefined : page.cursor;
    }
    return { ...result, done: tokensDone };
  }

  private async putGrant(grant: StoredGrant): Promise<void> {
    await this.kv.put(
      kvGrantKey(this.namespace, { userId: grant.value.userId, grantId: grant.value.id }),
      encodeKvRecord(grant),
      kvGrantPutOptions(grant, this.now())
    );
  }

  private async putAccessToken(token: StoredAccessToken): Promise<void> {
    await this.kv.put(
      kvAccessTokenKey(this.namespace, {
        userId: token.value.userId,
        grantId: token.value.grantId,
        tokenId: token.value.id,
      }),
      encodeKvRecord(token),
      kvAccessTokenPutOptions(token)
    );
  }

  private async listGrantRecords(prefix: string, page: PageRequest = {}): Promise<Page<StoredGrant>> {
    return this.listDecoded(prefix, page, (value) => hideLogicallyExpired(decodeKvGrant(value), this.now()));
  }

  private async listDecoded<T>(
    prefix: string,
    page: PageRequest | undefined,
    decode: (value: unknown) => T | null
  ): Promise<Page<T>> {
    const request = createPageRequest(page);
    const limit = request.limit ?? 1000;
    const items: T[] = [];
    let cursor = request.cursor;
    do {
      const previousCursor = cursor;
      const listed = await this.list(prefix, {
        limit: limit - items.length,
        ...(cursor === undefined ? {} : { cursor }),
      });
      for (const key of listed.keys) {
        const value = await this.kv.get(key.name, { type: 'json' });
        if (value === null) continue;
        const record = decode(value);
        if (record !== null) items.push(record);
      }
      cursor = listed.cursor;
      if (cursor !== undefined && cursor === previousCursor) {
        throw new OAuthStorageError('internal', { operation: 'storage.list' });
      }
    } while (items.length < limit && cursor !== undefined);
    return createPage(items, cursor);
  }

  private async collectUserClientGrants(
    userId: string,
    clientId: string,
    exceptGrantId: string,
    pageSize?: number
  ): Promise<StoredGrant[]> {
    const records: StoredGrant[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.listGrantsByUser({ userId, page: { cursor, limit: pageSize } });
      records.push(
        ...page.items.filter((grant) => grant.value.clientId === clientId && grant.value.id !== exceptGrantId)
      );
      cursor = page.cursor;
    } while (cursor !== undefined);
    return records;
  }

  private expirationOptions(expiresAt?: number): { readonly expirationTtl: number } | undefined {
    if (expiresAt === undefined) return undefined;
    const expirationTtl = expiresAt - this.now();
    if (expirationTtl < KV_MIN_EXPIRATION_TTL_SECONDS) {
      throw new OAuthStorageError('conflict', { operation: 'storage.expiration' });
    }
    return { expirationTtl };
  }

  private async list(
    prefix: string,
    page: PageRequest
  ): Promise<{
    readonly keys: readonly { readonly name: string }[];
    readonly cursor?: string;
  }> {
    const result = await this.kv.list({
      prefix,
      ...(page.limit === undefined ? {} : { limit: page.limit }),
      ...(page.cursor === undefined ? {} : { cursor: page.cursor }),
    });
    return {
      keys: result.keys.map(({ name }) => ({ name })),
      ...('cursor' in result && result.cursor ? { cursor: result.cursor } : {}),
    };
  }

  private now(): number {
    const value = this.clock();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new OAuthStorageError('invalid_configuration', { operation: 'storage.clock' });
    }
    return value;
  }

  private randomId(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
  }

  private async run<T>(operation: string, callback: () => Promise<T>): Promise<T> {
    if (this.#closed) throw new OAuthStorageError('unavailable', { operation });
    try {
      return await callback();
    } catch (error) {
      if (isOAuthStorageError(error)) throw error;
      const message = error instanceof Error ? error.message : '';
      if (/\b429\b/.test(message)) {
        throw new OAuthStorageError('rate_limited', { cause: error, operation });
      }
      throw new OAuthStorageError('internal', { cause: error, operation });
    }
  }
}

function isClientMetadataUrl(clientId: string): boolean {
  try {
    const url = new URL(clientId);
    return url.protocol === 'https:' && url.pathname !== '/';
  } catch {
    return false;
  }
}
