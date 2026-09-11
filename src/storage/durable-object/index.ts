/**
 * Durable Object SQLite storage adapter.
 *
 * A user's grants, access tokens, and grant transitions live in one Durable
 * Object per user, so code exchange and refresh rotation are serialized with
 * strong read-after-write. Registered clients get one object each, and replay
 * markers are spread over 256 shards. There is no global index: listing all
 * clients, deleting a client across users, and global purging are unsupported.
 */
import { DurableObject } from 'cloudflare:workers';

import type { ClientInfo, Grant, Token } from '../../oauth-provider';
import {
  OAuthStorageError,
  isOAuthStorageError,
  unsupportedStorageOperation,
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

/** Which Durable Object a command is routed to. */
export type StorageAggregate =
  | { readonly kind: 'user'; readonly key: string }
  | { readonly kind: 'client'; readonly key: string }
  | { readonly kind: 'replay'; readonly key: string };

/** RPC-safe command executed inside one Durable Object transaction. */
export type StorageCommand =
  | { readonly op: 'clients.get'; readonly clientId: string }
  | { readonly op: 'clients.put'; readonly client: ClientInfo; readonly expiresAt?: number }
  | { readonly op: 'grants.get'; readonly key: GrantKey }
  | { readonly op: 'grants.put'; readonly grant: Grant; readonly expiresAt?: number }
  | { readonly op: 'grants.list'; readonly clientId?: string; readonly page?: PageRequest }
  | { readonly op: 'grants.begin'; readonly input: BeginGrantTransitionInput }
  | { readonly op: 'grants.commit'; readonly input: CommitGrantTransitionInput }
  | { readonly op: 'grants.abort'; readonly lease: GrantTransitionLease }
  | { readonly op: 'grants.revoke'; readonly key: GrantKey }
  | { readonly op: 'tokens.get'; readonly key: AccessTokenKey }
  | { readonly op: 'tokens.put'; readonly token: Token }
  | { readonly op: 'tokens.delete'; readonly key: AccessTokenKey }
  | { readonly op: 'replay.reserve'; readonly key: string; readonly expiresAt: number; readonly now: number };

/** The subset of a `DurableObjectNamespace<OAuthStorageObject>` the adapter uses. */
export interface OAuthStorageObjectNamespace {
  getByName(name: string): { execute(command: StorageCommand): Promise<unknown> };
}

export interface DurableObjectSqliteStorageOptions<Env> {
  /** Resolves the `OAuthStorageObject` namespace binding from the request environment. */
  readonly binding: (env: Env) => OAuthStorageObjectNamespace;
}

export function durableObjectSqliteStorage<Env>(
  options: DurableObjectSqliteStorageOptions<Env>
): OAuthStorageProvider<Env> {
  if (typeof options?.binding !== 'function') {
    throw new TypeError('Durable Object storage requires a binding resolver');
  }
  return Object.freeze({
    id: 'durable-object-sqlite',
    minimumTtlSeconds: 0,
    open(env: Env): OAuthStorage {
      let namespace: OAuthStorageObjectNamespace;
      try {
        namespace = options.binding(env);
      } catch (cause) {
        throw new OAuthStorageError('invalid_configuration', { cause, operation: 'storage.open' });
      }
      if (typeof namespace?.getByName !== 'function') {
        throw new OAuthStorageError('invalid_configuration', { operation: 'storage.open' });
      }
      return new DurableObjectStorage(namespace);
    },
  });
}

/** Object names hash the routing key so user and client identifiers never appear in object metadata. */
export async function storageObjectName(aggregate: StorageAggregate): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify([aggregate.kind, aggregate.key]));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `oauth-do:${aggregate.kind}:${hash}`;
}

function replayAggregate(key: string): StorageAggregate {
  // One shard per first digest byte bounds object count while keeping
  // set-if-absent serialization for each complete identifier.
  return { kind: 'replay', key: key.slice(0, 2) };
}

class DurableObjectStorage implements OAuthStorage {
  readonly clients: OAuthStorage['clients'];
  readonly grants: OAuthStorage['grants'];
  readonly accessTokens: OAuthStorage['accessTokens'];
  readonly replay: OAuthStorage['replay'];
  readonly maintenance: OAuthStorage['maintenance'];

  constructor(private readonly namespace: OAuthStorageObjectNamespace) {
    const user = (userId: string): StorageAggregate => ({ kind: 'user', key: userId });
    const client = (clientId: string): StorageAggregate => ({ kind: 'client', key: clientId });
    this.clients = {
      get: (clientId) => this.call(client(clientId), { op: 'clients.get', clientId }),
      put: (record, expiresAt) => this.call(client(record.clientId), { op: 'clients.put', client: record, expiresAt }),
      deleteWithGrants: async () => {
        throw unsupportedStorageOperation('clients.deleteWithGrants');
      },
      list: async () => {
        throw unsupportedStorageOperation('clients.list');
      },
    };
    this.grants = {
      get: (key) => this.call(user(key.userId), { op: 'grants.get', key }),
      put: (grant, expiresAt) => this.call(user(grant.userId), { op: 'grants.put', grant, expiresAt }),
      listByUser: (userId, page) => this.call(user(userId), { op: 'grants.list', page }),
      listByUserAndClient: (userId, clientId, page) => this.call(user(userId), { op: 'grants.list', clientId, page }),
      beginTransition: (input) => this.call(user(input.grant.userId), { op: 'grants.begin', input }),
      commitTransition: (input) => this.call(user(input.lease.grant.userId), { op: 'grants.commit', input }),
      abortTransition: (lease) => this.call(user(lease.grant.userId), { op: 'grants.abort', lease }),
      revoke: (key) => this.call(user(key.userId), { op: 'grants.revoke', key }),
    };
    this.accessTokens = {
      get: (key) => this.call(user(key.userId), { op: 'tokens.get', key }),
      put: (token) => this.call(user(token.userId), { op: 'tokens.put', token }),
      delete: (key) => this.call(user(key.userId), { op: 'tokens.delete', key }),
    };
    this.replay = {
      reserve: (key, expiresAt) =>
        this.call(replayAggregate(key), { op: 'replay.reserve', key, expiresAt, now: Math.floor(Date.now() / 1000) }),
    };
    this.maintenance = {
      purge: async () => {
        throw unsupportedStorageOperation('maintenance.purge');
      },
    };
  }

  private async call<T>(aggregate: StorageAggregate, command: StorageCommand): Promise<T> {
    try {
      const stub = this.namespace.getByName(await storageObjectName(aggregate));
      return (await stub.execute(command)) as T;
    } catch (error) {
      if (isOAuthStorageError(error)) throw error;
      throw error;
    }
  }
}

type RecordRow = { key: string; value: string; expires_at: number | null };

/**
 * One keyed aggregate with its own SQLite database. Export this class from
 * the Worker and bind it as a SQLite-backed Durable Object.
 */
export class OAuthStorageObject extends DurableObject {
  constructor(ctx: DurableObjectState, env: Cloudflare.Env) {
    super(ctx, env);
    this.ctx.blockConcurrencyWhile(async () => this.initialize());
  }

  private initialize(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS records (
        kind TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        expires_at INTEGER,
        PRIMARY KEY (kind, key)
      );
      CREATE INDEX IF NOT EXISTS records_expiry ON records (kind, expires_at);
      CREATE INDEX IF NOT EXISTS grants_client ON records (json_extract(value, '$.clientId'), key) WHERE kind = 'grant';
      CREATE INDEX IF NOT EXISTS tokens_grant ON records (json_extract(value, '$.grantId'), key) WHERE kind = 'token';
      CREATE TABLE IF NOT EXISTS leases (
        grant_key TEXT PRIMARY KEY,
        fence INTEGER NOT NULL,
        kind TEXT NOT NULL,
        credential_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS fences (grant_key TEXT PRIMARY KEY, value INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS replay (key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
    `);
  }

  async execute(command: StorageCommand): Promise<unknown> {
    const result = this.ctx.storage.transactionSync(() => this.run(command));
    await this.scheduleCleanup();
    return result;
  }

  /** Physically removes expired records; the provider still checks logical expiry on every read. */
  async alarm(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    this.ctx.storage.transactionSync(() => {
      const sql = this.ctx.storage.sql;
      for (const row of sql
        .exec<RecordRow>("SELECT key, value, expires_at FROM records WHERE kind = 'grant' AND expires_at <= ?", now)
        .toArray()) {
        const grant = JSON.parse(row.value) as Grant;
        this.revoke({ userId: grant.userId, grantId: grant.id });
      }
      sql.exec("DELETE FROM records WHERE kind IN ('client', 'token') AND expires_at <= ?", now);
      sql.exec('DELETE FROM leases WHERE expires_at <= ?', now);
      sql.exec('DELETE FROM replay WHERE expires_at <= ?', now);
    });
    await this.scheduleCleanup();
  }

  private run(command: StorageCommand): unknown {
    switch (command.op) {
      case 'clients.get':
        return this.read<ClientInfo>('client', command.clientId);
      case 'clients.put':
        this.write('client', command.client.clientId, command.client, command.expiresAt);
        return undefined;
      case 'grants.get':
        return this.read<Grant>('grant', grantKey(command.key));
      case 'grants.put':
        this.write(
          'grant',
          grantKey({ userId: command.grant.userId, grantId: command.grant.id }),
          command.grant,
          command.expiresAt
        );
        return undefined;
      case 'grants.list':
        return this.listGrants(command.clientId, command.page);
      case 'grants.begin':
        return this.begin(command.input);
      case 'grants.commit':
        return this.commit(command.input);
      case 'grants.abort':
        this.abort(command.lease);
        return undefined;
      case 'grants.revoke':
        this.revoke(command.key);
        return undefined;
      case 'tokens.get':
        return this.readToken(command.key);
      case 'tokens.put':
        this.write('token', command.token.id, command.token, command.token.expiresAt);
        return undefined;
      case 'tokens.delete':
        if (this.readToken(command.key))
          this.ctx.storage.sql.exec("DELETE FROM records WHERE kind = 'token' AND key = ?", command.key.tokenId);
        return undefined;
      case 'replay.reserve':
        return this.reserveReplay(command.key, command.expiresAt, command.now);
    }
  }

  private read<T>(kind: string, key: string): T | null {
    const row = this.ctx.storage.sql
      .exec<RecordRow>('SELECT key, value, expires_at FROM records WHERE kind = ? AND key = ?', kind, key)
      .toArray()[0];
    return row ? (JSON.parse(row.value) as T) : null;
  }

  private write(kind: string, key: string, value: unknown, expiresAt: number | undefined): void {
    this.ctx.storage.sql.exec(
      'INSERT OR REPLACE INTO records (kind, key, value, expires_at) VALUES (?, ?, ?, ?)',
      kind,
      key,
      JSON.stringify(value),
      expiresAt ?? null
    );
  }

  private readToken(key: AccessTokenKey): Token | null {
    const token = this.read<Token>('token', key.tokenId);
    return token && token.userId === key.userId && token.grantId === key.grantId ? token : null;
  }

  /** Served by the `grants_client` partial index when `clientId` is given, so grant replacement never scans a user's other clients. */
  private listGrants(clientId: string | undefined, page: PageRequest | undefined): Page<Grant> {
    const limit = page?.limit ?? 1000;
    const after = page?.cursor ?? '';
    const rows =
      clientId === undefined
        ? this.ctx.storage.sql
            .exec<RecordRow>(
              "SELECT key, value, expires_at FROM records WHERE kind = 'grant' AND key > ? ORDER BY key LIMIT ?",
              after,
              limit + 1
            )
            .toArray()
        : this.ctx.storage.sql
            .exec<RecordRow>(
              "SELECT key, value, expires_at FROM records WHERE kind = 'grant' AND json_extract(value, '$.clientId') = ? AND key > ? ORDER BY key LIMIT ?",
              clientId,
              after,
              limit + 1
            )
            .toArray();
    const selected = rows.slice(0, limit);
    return {
      items: selected.map((row) => JSON.parse(row.value) as Grant),
      ...(rows.length > limit ? { cursor: selected[selected.length - 1]!.key } : {}),
    };
  }

  private begin(input: BeginGrantTransitionInput): BeginGrantTransitionResult {
    const sql = this.ctx.storage.sql;
    const key = grantKey(input.grant);
    const grant = this.read<Grant>('grant', key);
    if (!grant) return { status: 'not_found' };
    if (input.kind === 'authorization_code') {
      if (grant.authCodeId !== input.credentialId) return { status: 'invalid_credential' };
      if (!grant.authCodeWrappedKey) return { status: 'already_consumed' };
    } else {
      const current = grant.refreshTokenId === input.credentialId && !!grant.refreshTokenWrappedKey;
      const previous = grant.previousRefreshTokenId === input.credentialId && !!grant.previousRefreshTokenWrappedKey;
      if (!current && !previous) return { status: 'invalid_credential' };
    }
    const existing = sql
      .exec<{ expires_at: number }>('SELECT expires_at FROM leases WHERE grant_key = ?', key)
      .toArray()[0];
    if (existing && existing.expires_at > input.now) {
      return { status: 'busy', retryAfterSeconds: Math.max(1, existing.expires_at - input.now) };
    }
    const fence =
      (sql.exec<{ value: number }>('SELECT value FROM fences WHERE grant_key = ?', key).toArray()[0]?.value ?? 0) + 1;
    sql.exec('INSERT OR REPLACE INTO fences (grant_key, value) VALUES (?, ?)', key, fence);
    const lease: GrantTransitionLease = {
      grant: input.grant,
      kind: input.kind,
      credentialId: input.credentialId,
      fence,
      expiresAt: input.now + input.leaseTtlSeconds,
    };
    sql.exec(
      'INSERT OR REPLACE INTO leases (grant_key, fence, kind, credential_id, expires_at) VALUES (?, ?, ?, ?, ?)',
      key,
      fence,
      lease.kind,
      lease.credentialId,
      lease.expiresAt
    );
    return { status: 'acquired', grant, lease };
  }

  private holdsLease(lease: GrantTransitionLease): boolean {
    const row = this.ctx.storage.sql
      .exec<{
        fence: number;
        credential_id: string;
        kind: string;
      }>('SELECT fence, credential_id, kind FROM leases WHERE grant_key = ?', grantKey(lease.grant))
      .toArray()[0];
    return !!row && row.fence === lease.fence && row.credential_id === lease.credentialId && row.kind === lease.kind;
  }

  private commit(input: CommitGrantTransitionInput): CommitGrantTransitionResult {
    const key = grantKey(input.lease.grant);
    if (!this.read<Grant>('grant', key)) return { status: 'not_found' };
    if (input.now >= input.lease.expiresAt || !this.holdsLease(input.lease)) return { status: 'conflict' };
    this.write('grant', key, input.grant, input.grantExpiresAt);
    this.write('token', input.accessToken.id, input.accessToken, input.accessToken.expiresAt);
    this.ctx.storage.sql.exec('DELETE FROM leases WHERE grant_key = ? AND fence = ?', key, input.lease.fence);
    return { status: 'committed' };
  }

  private abort(lease: GrantTransitionLease): void {
    if (this.holdsLease(lease)) {
      this.ctx.storage.sql.exec(
        'DELETE FROM leases WHERE grant_key = ? AND fence = ?',
        grantKey(lease.grant),
        lease.fence
      );
    }
  }

  private revoke(key: GrantKey): void {
    const sql = this.ctx.storage.sql;
    const physical = grantKey(key);
    sql.exec("DELETE FROM records WHERE kind = 'token' AND json_extract(value, '$.grantId') = ?", key.grantId);
    sql.exec("DELETE FROM records WHERE kind = 'grant' AND key = ?", physical);
    sql.exec('DELETE FROM leases WHERE grant_key = ?', physical);
  }

  private reserveReplay(key: string, expiresAt: number, now: number): 'reserved' | 'exists' {
    const sql = this.ctx.storage.sql;
    sql.exec('DELETE FROM replay WHERE key = ? AND expires_at <= ?', key, now);
    const inserted = sql
      .exec('INSERT OR IGNORE INTO replay (key, expires_at) VALUES (?, ?) RETURNING key', key, expiresAt)
      .toArray().length;
    return inserted ? 'reserved' : 'exists';
  }

  private async scheduleCleanup(): Promise<void> {
    const row = this.ctx.storage.sql
      .exec<{ next: number | null }>(
        `SELECT MIN(expires_at) AS next FROM (
          SELECT expires_at FROM records WHERE expires_at IS NOT NULL
          UNION ALL SELECT expires_at FROM leases
          UNION ALL SELECT expires_at FROM replay
        )`
      )
      .toArray()[0];
    const desired = row?.next == null ? null : row.next * 1000;
    const current = await this.ctx.storage.getAlarm();
    if (desired === null) {
      if (current !== null) await this.ctx.storage.deleteAlarm();
    } else if (current !== desired) {
      await this.ctx.storage.setAlarm(desired);
    }
  }
}

function grantKey(key: GrantKey): string {
  return JSON.stringify([key.userId, key.grantId]);
}
