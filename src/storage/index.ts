/**
 * Backend-neutral storage contract for the OAuth provider.
 *
 * The provider never touches a binding directly: every client, grant, access
 * token, and replay marker goes through an {@link OAuthStorage} obtained from
 * the configured {@link OAuthStorageProvider}. Records cross this boundary in
 * their canonical provider shapes; adapters own only physical layout,
 * expiration, and the atomicity of grant transitions.
 */
import type { ClientInfo, Grant, PurgeOptions, PurgeResult, Token } from '../oauth-provider';

/** Identifies a grant without exposing a physical backend key. */
export interface GrantKey {
  readonly userId: string;
  readonly grantId: string;
}

/** Identifies an access token by the SHA-256 hash of the token string. */
export interface AccessTokenKey extends GrantKey {
  readonly tokenId: string;
}

/** Opaque pagination request. Cursors are adapter-specific. */
export interface PageRequest {
  readonly limit?: number;
  readonly cursor?: string;
}

/** One page of records; `cursor` is absent when the scan is complete. */
export interface Page<T> {
  readonly items: readonly T[];
  readonly cursor?: string;
}

/** The one-time credential whose consumption a grant transition serializes. */
export type GrantTransitionKind = 'authorization_code' | 'refresh_token';

/**
 * Authority over one presented authorization code or refresh token. A strong
 * adapter fences the lease so a stale commit cannot overwrite a newer grant;
 * the KV adapter's lease is advisory.
 */
export interface GrantTransitionLease {
  readonly grant: GrantKey;
  readonly kind: GrantTransitionKind;
  /** SHA-256 hash of the presented code or refresh token. */
  readonly credentialId: string;
  readonly fence: number;
  readonly expiresAt: number;
}

export interface BeginGrantTransitionInput {
  readonly grant: GrantKey;
  readonly kind: GrantTransitionKind;
  readonly credentialId: string;
  readonly now: number;
  readonly leaseTtlSeconds: number;
}

export type BeginGrantTransitionResult =
  | { readonly status: 'acquired'; readonly grant: Grant; readonly lease: GrantTransitionLease }
  | { readonly status: 'busy'; readonly retryAfterSeconds: number }
  | { readonly status: 'invalid_credential' }
  | { readonly status: 'already_consumed' }
  | { readonly status: 'not_found' };

export interface CommitGrantTransitionInput {
  readonly lease: GrantTransitionLease;
  /** Complete successor of the leased grant. */
  readonly grant: Grant;
  /** Physical lifetime of the successor grant, when it has one. */
  readonly grantExpiresAt?: number;
  /** Access token created atomically with the successor grant. */
  readonly accessToken: Token;
  readonly now: number;
}

export type CommitGrantTransitionResult =
  | { readonly status: 'committed' }
  | { readonly status: 'conflict' }
  | { readonly status: 'not_found' };

/** Registered-client records. Client ID Metadata Document clients are never stored. */
export interface OAuthClientStore {
  get(clientId: string): Promise<ClientInfo | null>;
  /** Creates or replaces a client. `expiresAt` is the registration's physical lifetime. */
  put(client: ClientInfo, expiresAt?: number): Promise<void>;
  /**
   * Deletes a client together with every grant issued to it and every access
   * token it owns across all users. Throws `unsupported_operation` on an
   * adapter without a global index.
   */
  deleteWithGrants(clientId: string): Promise<void>;
  /** Lists registered clients. Throws `unsupported_operation` without a global index. */
  list(page?: PageRequest): Promise<Page<ClientInfo>>;
}

export interface OAuthGrantStore {
  get(key: GrantKey): Promise<Grant | null>;
  /** Creates a grant. `expiresAt` is its physical lifetime, when it has one. */
  put(grant: Grant, expiresAt?: number): Promise<void>;
  listByUser(userId: string, page?: PageRequest): Promise<Page<Grant>>;
  /**
   * Lists one user's grants issued to one client. An indexed adapter bounds the
   * work to that client's grants; when absent the provider scans `listByUser`.
   */
  listByUserAndClient?(userId: string, clientId: string, page?: PageRequest): Promise<Page<Grant>>;
  beginTransition(input: BeginGrantTransitionInput): Promise<BeginGrantTransitionResult>;
  commitTransition(input: CommitGrantTransitionInput): Promise<CommitGrantTransitionResult>;
  abortTransition(lease: GrantTransitionLease): Promise<void>;
  /** Deletes a grant and every access token issued under it. */
  revoke(key: GrantKey): Promise<void>;
}

export interface OAuthAccessTokenStore {
  get(key: AccessTokenKey): Promise<Token | null>;
  put(token: Token): Promise<void>;
  delete(key: AccessTokenKey): Promise<void>;
}

/** Atomic set-if-absent markers for one-time identifiers such as EMA `jti` values. */
export interface OAuthReplayStore {
  reserve(key: string, expiresAt: number): Promise<'reserved' | 'exists'>;
}

export interface OAuthMaintenanceStore {
  /** Bounded global sweep of expired and orphaned records. Throws `unsupported_operation` without a global index. */
  purge(options: Required<PurgeOptions>): Promise<PurgeResult>;
}

/** All stores for one Worker environment. */
export interface OAuthStorage {
  readonly clients: OAuthClientStore;
  readonly grants: OAuthGrantStore;
  readonly accessTokens: OAuthAccessTokenStore;
  readonly replay: OAuthReplayStore;
  readonly maintenance: OAuthMaintenanceStore;
}

export interface OAuthStorageProvider<Env = Cloudflare.Env> {
  /** Stable adapter identifier used in configuration errors. */
  readonly id: string;
  /** Smallest physical lifetime the backend accepts for a token or grant write. */
  readonly minimumTtlSeconds: number;
  /** Resolves the backend bindings from the environment. Must be cheap; called per operation. */
  open(env: Env): OAuthStorage;
}

export type OAuthStorageErrorCode = 'rate_limited' | 'unsupported_operation' | 'invalid_configuration';

/** Typed storage failure. Backend details stay in the non-enumerable `cause`. */
export class OAuthStorageError extends Error {
  readonly code: OAuthStorageErrorCode;
  /** Whether retrying the same operation may succeed. */
  readonly retryable: boolean;
  readonly operation?: string;
  declare readonly cause?: unknown;

  constructor(code: OAuthStorageErrorCode, options: { readonly operation?: string; readonly cause?: unknown } = {}) {
    super(`OAuth storage operation failed (${code})`);
    this.name = 'OAuthStorageError';
    this.code = code;
    this.retryable = code === 'rate_limited';
    if (options.operation !== undefined) this.operation = options.operation;
    if (options.cause !== undefined) {
      Object.defineProperty(this, 'cause', { value: options.cause, enumerable: false });
    }
  }
}

export function isOAuthStorageError(error: unknown): error is OAuthStorageError {
  return error instanceof OAuthStorageError;
}

export function unsupportedStorageOperation(operation: string): OAuthStorageError {
  return new OAuthStorageError('unsupported_operation', { operation });
}
