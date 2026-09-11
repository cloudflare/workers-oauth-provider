/**
 * Workers KV storage adapter. This is the default backend and preserves the
 * physical key layout documented in `storage-schema.md`, so existing
 * deployments need no migration.
 */
import type { ClientInfo, Grant, PurgeOptions, PurgeResult, Token } from '../../oauth-provider';
import {
  OAuthStorageError,
  isOAuthStorageError,
  type AccessTokenKey,
  type BeginGrantTransitionInput,
  type BeginGrantTransitionResult,
  type CommitGrantTransitionInput,
  type CommitGrantTransitionResult,
  type GrantKey,
  type GrantTransitionLease,
  type OAuthStorage,
  type OAuthStorageProvider,
  type Page,
  type PageRequest,
} from '../index';

/**
 * Cloudflare KV rejects `put` calls whose expiration is less than 60 seconds
 * away. Near-expiry writes are clamped above this floor with a small margin
 * because KV validates against its own clock at write time.
 */
export const KV_MIN_EXPIRATION_TTL_SECONDS = 60;
const KV_EXPIRATION_CLAMP_MARGIN_SECONDS = 5;

const CLIENT_PREFIX = 'client:';
const GRANT_PREFIX = 'grant:';
const TOKEN_PREFIX = 'token:';
const REPLAY_PREFIX = 'enterprise-jti:';

export interface WorkersKvStorageOptions<Env> {
  /** Resolves the Workers KV binding from the request environment. */
  readonly binding: (env: Env) => KVNamespace;
}

export function workersKvStorage<Env>(options: WorkersKvStorageOptions<Env>): OAuthStorageProvider<Env> {
  if (typeof options?.binding !== 'function') {
    throw new TypeError('Workers KV storage requires a binding resolver');
  }
  return Object.freeze({
    id: 'cloudflare-kv',
    minimumTtlSeconds: KV_MIN_EXPIRATION_TTL_SECONDS,
    open(env: Env): OAuthStorage {
      let kv: KVNamespace;
      try {
        kv = options.binding(env);
      } catch (cause) {
        throw new OAuthStorageError('invalid_configuration', { cause, operation: 'storage.open' });
      }
      if (typeof kv?.get !== 'function' || typeof kv.put !== 'function' || typeof kv.list !== 'function') {
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      }
      return new WorkersKvStorage(kv);
    },
  });
}

interface ListPage {
  readonly keys: readonly { readonly name: string }[];
  readonly cursor?: string;
}

class WorkersKvStorage implements OAuthStorage {
  readonly clients: OAuthStorage['clients'];
  readonly grants: OAuthStorage['grants'];
  readonly accessTokens: OAuthStorage['accessTokens'];
  readonly replay: OAuthStorage['replay'];
  readonly maintenance: OAuthStorage['maintenance'];

  constructor(private readonly kv: KVNamespace) {
    this.clients = {
      get: (clientId) => this.run(() => this.kv.get<ClientInfo>(`${CLIENT_PREFIX}${clientId}`, { type: 'json' })),
      put: (client, expiresAt) =>
        this.run(() => this.kv.put(`${CLIENT_PREFIX}${client.clientId}`, JSON.stringify(client), this.ttl(expiresAt))),
      deleteWithGrants: (clientId) => this.run(() => this.deleteClientWithGrants(clientId)),
      list: (page) => this.run(() => this.listDecoded<ClientInfo>(CLIENT_PREFIX, page)),
    };
    this.grants = {
      get: (key) => this.run(() => this.kv.get<Grant>(grantKey(key), { type: 'json' })),
      put: (grant, expiresAt) => this.run(() => this.putGrant(grant, expiresAt)),
      listByUser: (userId, page) => this.run(() => this.listDecoded<Grant>(`${GRANT_PREFIX}${userId}:`, page)),
      beginTransition: (input) => this.run(() => this.beginTransition(input)),
      commitTransition: (input) => this.run(() => this.commitTransition(input)),
      abortTransition: async () => {},
      revoke: (key) => this.run(() => this.revokeGrant(key)),
    };
    this.accessTokens = {
      get: (key) => this.run(() => this.kv.get<Token>(tokenKey(key), { type: 'json' })),
      put: (token) => this.run(() => this.putToken(token)),
      delete: (key) => this.run(() => this.kv.delete(tokenKey(key))),
    };
    this.replay = {
      reserve: (key, expiresAt) => this.run(() => this.reserveReplay(key, expiresAt)),
    };
    this.maintenance = {
      purge: (options) => this.run(() => this.purge(options)),
    };
  }

  /** KV rate limiting surfaces as a retryable storage error; other failures propagate as-is. */
  private async run<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (isOAuthStorageError(error)) throw error;
      const message = error instanceof Error ? error.message : '';
      if (/\b429\b/.test(message)) throw new OAuthStorageError('rate_limited', { cause: error });
      throw error;
    }
  }

  private ttl(expiresAt: number | undefined): { expirationTtl: number } | undefined {
    if (expiresAt === undefined) return undefined;
    return { expirationTtl: expiresAt - now() };
  }

  private async putGrant(grant: Grant, expiresAt: number | undefined): Promise<void> {
    // Absolute expirations are clamped above KV's minimum so a freshly issued
    // grant with a very short remaining lifetime is still writable.
    const options =
      expiresAt === undefined
        ? {}
        : {
            expiration: Math.max(expiresAt, now() + KV_MIN_EXPIRATION_TTL_SECONDS + KV_EXPIRATION_CLAMP_MARGIN_SECONDS),
          };
    await this.kv.put(grantKey({ userId: grant.userId, grantId: grant.id }), JSON.stringify(grant), options);
  }

  private async putToken(token: Token): Promise<void> {
    await this.kv.put(
      tokenKey({ userId: token.userId, grantId: token.grantId, tokenId: token.id }),
      JSON.stringify(token),
      {
        expirationTtl: token.expiresAt - token.createdAt,
      }
    );
  }

  /**
   * KV cannot exclude a concurrent caller, so the lease is advisory: begin
   * verifies the presented credential against the stored grant and commit
   * re-verifies it before writing.
   */
  private async beginTransition(input: BeginGrantTransitionInput): Promise<BeginGrantTransitionResult> {
    const grant = await this.kv.get<Grant>(grantKey(input.grant), { type: 'json' });
    if (!grant) return { status: 'not_found' };
    const state = credentialState(grant, input.kind, input.credentialId);
    if (state !== 'valid') return { status: state };
    const lease: GrantTransitionLease = {
      grant: input.grant,
      kind: input.kind,
      credentialId: input.credentialId,
      fence: 0,
      expiresAt: input.now + input.leaseTtlSeconds,
    };
    return { status: 'acquired', grant, lease };
  }

  private async commitTransition(input: CommitGrantTransitionInput): Promise<CommitGrantTransitionResult> {
    const current = await this.kv.get<Grant>(grantKey(input.lease.grant), { type: 'json' });
    if (!current) return { status: 'not_found' };
    if (credentialState(current, input.lease.kind, input.lease.credentialId) !== 'valid') return { status: 'conflict' };
    await this.putGrant(input.grant, input.grantExpiresAt);
    await this.putToken(input.accessToken);
    return { status: 'committed' };
  }

  private async revokeGrant(key: GrantKey): Promise<void> {
    // Delete every access token under the grant, paging past 1000 keys, then the grant itself.
    let cursor: string | undefined;
    do {
      const page = await this.list(`${TOKEN_PREFIX}${key.userId}:${key.grantId}:`, { cursor });
      await Promise.all(page.keys.map(({ name }) => this.kv.delete(name)));
      cursor = page.cursor;
    } while (cursor !== undefined);
    await this.kv.delete(grantKey(key));
  }

  private async deleteClientWithGrants(clientId: string): Promise<void> {
    // Grants are keyed by user, so revoking a client's grants scans every grant.
    let cursor: string | undefined;
    do {
      const page = await this.list(GRANT_PREFIX, { cursor });
      for (const { name } of page.keys) {
        const grant = await this.kv.get<Grant>(name, { type: 'json' });
        if (grant?.clientId === clientId) await this.revokeGrant({ userId: grant.userId, grantId: grant.id });
      }
      cursor = page.cursor;
    } while (cursor !== undefined);

    // Token exchange can issue a token to this client below a source grant owned
    // by another client, so exchanged tokens are swept separately.
    cursor = undefined;
    do {
      const page = await this.list(TOKEN_PREFIX, { cursor });
      for (const { name } of page.keys) {
        const token = await this.kv.get<Token>(name, { type: 'json' });
        if (token?.grant?.clientId === clientId) await this.kv.delete(name);
      }
      cursor = page.cursor;
    } while (cursor !== undefined);

    await this.kv.delete(`${CLIENT_PREFIX}${clientId}`);
  }

  private async reserveReplay(key: string, expiresAt: number): Promise<'reserved' | 'exists'> {
    const physicalKey = `${REPLAY_PREFIX}${key}`;
    if ((await this.kv.get(physicalKey)) !== null) return 'exists';
    // A marker outliving its assertion only tightens replay detection.
    await this.kv.put(physicalKey, '1', {
      expirationTtl: Math.max(KV_MIN_EXPIRATION_TTL_SECONDS, expiresAt - now()),
    });
    return 'reserved';
  }

  private async purge(options: Required<PurgeOptions>): Promise<PurgeResult> {
    const { batchSize, purgeOrphanedGrants, purgeExpiredGrants, purgeOrphanedTokens } = options;
    const current = now();
    const result: PurgeResult = { grantsChecked: 0, grantsPurged: 0, tokensChecked: 0, tokensPurged: 0, done: false };
    const knownGoodClients = new Set<string>();
    const knownMissingClients = new Set<string>();
    const clientExists = async (clientId: string): Promise<boolean> => {
      if (knownGoodClients.has(clientId)) return true;
      if (knownMissingClients.has(clientId)) return false;
      const exists = (await this.kv.get(`${CLIENT_PREFIX}${clientId}`)) !== null;
      (exists ? knownGoodClients : knownMissingClients).add(clientId);
      return exists;
    };

    // Phase 1: grant sweep
    if (purgeOrphanedGrants || purgeExpiredGrants) {
      let cursor: string | undefined;
      let grantsDone = false;
      while (!grantsDone && result.grantsChecked < batchSize) {
        const page = await this.list(GRANT_PREFIX, { cursor, limit: Math.min(1000, batchSize - result.grantsChecked) });
        for (const { name } of page.keys) {
          if (result.grantsChecked >= batchSize) break;
          result.grantsChecked++;
          const grant = await this.kv.get<Grant>(name, { type: 'json' });
          if (!grant) continue;
          let shouldPurge = purgeExpiredGrants && grant.expiresAt !== undefined && current >= grant.expiresAt;
          // Orphan check skips CIMD clients, whose URL client IDs are never stored.
          if (!shouldPurge && purgeOrphanedGrants && !isClientMetadataUrl(grant.clientId)) {
            shouldPurge = !(await clientExists(grant.clientId));
          }
          if (shouldPurge) {
            await this.revokeGrant({ userId: grant.userId, grantId: grant.id });
            result.grantsPurged++;
          }
        }
        grantsDone = page.cursor === undefined;
        cursor = page.cursor;
      }
      if (!grantsDone) return result;
    }

    // Phase 2: token sweep
    if (purgeOrphanedTokens) {
      const knownGoodGrants = new Set<string>();
      const knownMissingGrants = new Set<string>();
      let cursor: string | undefined;
      let tokensDone = false;
      while (!tokensDone && result.tokensChecked < batchSize) {
        const page = await this.list(TOKEN_PREFIX, { cursor, limit: Math.min(1000, batchSize - result.tokensChecked) });
        for (const { name } of page.keys) {
          if (result.tokensChecked >= batchSize) break;
          result.tokensChecked++;
          const token = await this.kv.get<Token>(name, { type: 'json' });
          if (!token) continue;
          const parent = grantKey({ userId: token.userId, grantId: token.grantId });
          let shouldPurge = knownMissingGrants.has(parent);
          if (!shouldPurge && !knownGoodGrants.has(parent)) {
            const exists = (await this.kv.get(parent)) !== null;
            (exists ? knownGoodGrants : knownMissingGrants).add(parent);
            shouldPurge = !exists;
          }
          // Exchanged tokens may be owned by a different client than their backing grant.
          const owner = token.grant?.clientId;
          if (!shouldPurge && owner && !isClientMetadataUrl(owner)) shouldPurge = !(await clientExists(owner));
          if (shouldPurge) {
            await this.kv.delete(name);
            result.tokensPurged++;
          }
        }
        tokensDone = page.cursor === undefined;
        cursor = page.cursor;
      }
      if (!tokensDone) return result;
    }

    result.done = true;
    return result;
  }

  private async listDecoded<T>(prefix: string, page?: PageRequest): Promise<Page<T>> {
    const listed = await this.list(prefix, page ?? {});
    const items: T[] = [];
    await Promise.all(
      listed.keys.map(async ({ name }) => {
        const value = await this.kv.get<T>(name, { type: 'json' });
        if (value) items.push(value);
      })
    );
    return { items, ...(listed.cursor === undefined ? {} : { cursor: listed.cursor }) };
  }

  private async list(prefix: string, page: PageRequest): Promise<ListPage> {
    const result = await this.kv.list({
      prefix,
      ...(page.limit === undefined ? {} : { limit: page.limit }),
      ...(page.cursor === undefined ? {} : { cursor: page.cursor }),
    });
    return {
      keys: result.keys.map(({ name }) => ({ name })),
      ...(result.list_complete ? {} : { cursor: result.cursor }),
    };
  }
}

function credentialState(
  grant: Grant,
  kind: BeginGrantTransitionInput['kind'],
  credentialId: string
): 'valid' | 'invalid_credential' | 'already_consumed' {
  if (kind === 'authorization_code') {
    if (grant.authCodeId !== credentialId) return 'invalid_credential';
    return grant.authCodeWrappedKey === undefined ? 'already_consumed' : 'valid';
  }
  const current = grant.refreshTokenId === credentialId && grant.refreshTokenWrappedKey !== undefined;
  const previous = grant.previousRefreshTokenId === credentialId && grant.previousRefreshTokenWrappedKey !== undefined;
  return current || previous ? 'valid' : 'invalid_credential';
}

function grantKey(key: GrantKey): string {
  return `${GRANT_PREFIX}${key.userId}:${key.grantId}`;
}

function tokenKey(key: AccessTokenKey): string {
  return `${TOKEN_PREFIX}${key.userId}:${key.grantId}:${key.tokenId}`;
}

function isClientMetadataUrl(clientId: string): boolean {
  try {
    const url = new URL(clientId);
    return url.protocol === 'https:' && url.pathname !== '/';
  } catch {
    return false;
  }
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}
