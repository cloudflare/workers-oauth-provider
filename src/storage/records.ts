import type { ClientInfo, Grant, Token } from '../oauth-provider';

/** Unix time in whole seconds at the storage boundary. */
export type UnixSeconds = number;

/** A SHA-256 credential digest. The original credential must never cross the storage boundary. */
export type CredentialId = string & { readonly __credentialId: unique symbol };

/** Metadata kept outside canonical OAuth values so legacy payloads can remain byte-compatible. */
export interface StorageMetadata {
  /** Record schema understood by the adapter. Legacy Workers KV records use version zero. */
  readonly schemaVersion: number;
  /** Monotonically increasing version used by guarded mutations. */
  readonly revision: number;
  /** Time at which the record was first created. */
  readonly createdAt: UnixSeconds;
  /** Logical expiration time. Native backend TTL is cleanup only. */
  readonly expiresAt?: UnixSeconds;
}

/** A canonical OAuth value paired with backend-neutral storage metadata. */
export interface Stored<T> {
  /**
   * Canonical value owned by the OAuth engine. Callers must not mutate it after
   * creating the envelope; adapters treat it as immutable.
   */
  readonly value: Readonly<T>;
  /** Backend-neutral metadata that adapters may store separately from the value. */
  readonly metadata: Readonly<StorageMetadata>;
}

/** Stored-client shape with its optional secret constrained to a digest. */
export type StorageClient = Omit<ClientInfo, 'clientSecret'> & {
  readonly clientSecret?: CredentialId;
};

/** Stored-grant shape with every credential field constrained to a digest. */
export type StorageGrant = Omit<Grant, 'authCodeId' | 'refreshTokenId' | 'previousRefreshTokenId'> & {
  readonly authCodeId?: CredentialId;
  readonly refreshTokenId?: CredentialId;
  readonly previousRefreshTokenId?: CredentialId;
};

/** Stored access-token shape with its identifier constrained to a digest. */
export type StorageAccessToken = Omit<Token, 'id'> & {
  readonly id: CredentialId;
};

/** Persistent user consent. This is reserved for the basic OIDC/consent roadmap. */
export interface OAuthConsent {
  /** Resource-owner identifier. */
  readonly userId: string;
  /** OAuth client identifier. */
  readonly clientId: string;
  /** Optional application-defined consent grouping key. */
  readonly referenceId?: string;
  /** Granted OAuth scopes. */
  readonly scope: readonly string[];
  /** Last consent update time. */
  readonly updatedAt: UnixSeconds;
}

const STORED_RECORD_KIND: unique symbol = Symbol('OAuthStoredRecordKind');

type ValidatedStored<T, Kind extends string> = Stored<T> & {
  readonly [STORED_RECORD_KIND]: Kind;
};

/** A validated stored dynamically registered client. */
export type StoredClient = ValidatedStored<StorageClient, 'client'>;

/** A validated stored authorization grant. */
export type StoredGrant = ValidatedStored<StorageGrant, 'grant'>;

/** A validated stored access token. */
export type StoredAccessToken = ValidatedStored<StorageAccessToken, 'access_token'>;

/** A validated stored persistent consent. */
export type StoredConsent = ValidatedStored<OAuthConsent, 'consent'>;

/** Initial revision for a newly inserted mutable record. */
export const INITIAL_STORAGE_REVISION = 0;

/** Identifies a grant without exposing a physical backend key. */
export interface GrantKey {
  /** Resource-owner identifier. */
  readonly userId: string;
  /** Grant identifier. */
  readonly grantId: string;
}

/** Identifies an access token by its one-way token identifier. */
export interface AccessTokenKey extends GrantKey {
  /** SHA-256 identifier of the access token. */
  readonly tokenId: CredentialId;
}

/**
 * Identifies whether grant creation is guarded by a stored client record.
 *
 * CIMD clients are fetched by the OAuth engine and are not persisted by storage.
 */
export type ClientReference =
  | {
      readonly kind: 'registered';
      readonly clientId: string;
      /** Revision that must still exist when a strong adapter creates the grant. */
      readonly expectedRevision: number;
    }
  | {
      readonly kind: 'external';
      readonly clientId: string;
    };

/** Creates a branded credential ID from the lowercase SHA-256 hex form used by the provider. */
export function credentialIdFromSha256(value: string): CredentialId {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError('Credential ID must be a lowercase SHA-256 digest');
  }
  return value as CredentialId;
}

/** Creates a validated stored-client envelope. */
export function createStoredClient(value: StorageClient, metadata: StorageMetadata): StoredClient {
  assertNonEmpty(value.clientId, 'clientId');
  if (value.clientSecret !== undefined) credentialIdFromSha256(value.clientSecret);
  return createValidatedStored(Object.freeze({ ...value }), metadata, 'client');
}

/** Creates a validated stored-grant envelope with digest-only credential identifiers. */
export function createStoredGrant(value: StorageGrant, metadata: StorageMetadata): StoredGrant {
  assertNonEmpty(value.id, 'grant.id');
  assertNonEmpty(value.userId, 'grant.userId');
  assertNonEmpty(value.clientId, 'grant.clientId');
  for (const credential of [value.authCodeId, value.refreshTokenId, value.previousRefreshTokenId]) {
    if (credential !== undefined) credentialIdFromSha256(credential);
  }
  if (metadata.createdAt !== value.createdAt || metadata.expiresAt !== value.expiresAt) {
    throw new TypeError('Grant metadata timestamps must match the canonical grant');
  }
  return createValidatedStored(Object.freeze({ ...value }), metadata, 'grant');
}

/** Creates a validated stored access-token envelope with a digest-only identifier. */
export function createStoredAccessToken(value: StorageAccessToken, metadata: StorageMetadata): StoredAccessToken {
  credentialIdFromSha256(value.id);
  assertNonEmpty(value.userId, 'token.userId');
  assertNonEmpty(value.grantId, 'token.grantId');
  if (metadata.createdAt !== value.createdAt || metadata.expiresAt !== value.expiresAt) {
    throw new TypeError('Access-token metadata timestamps must match the canonical token');
  }
  return createValidatedStored(
    Object.freeze({ ...value, grant: Object.freeze({ ...value.grant }) }),
    metadata,
    'access_token'
  );
}

/** Creates a validated stored-consent envelope. */
export function createStoredConsent(value: OAuthConsent, metadata: StorageMetadata): StoredConsent {
  assertNonEmpty(value.userId, 'consent.userId');
  assertNonEmpty(value.clientId, 'consent.clientId');
  if (metadata.createdAt > value.updatedAt) {
    throw new TypeError('Consent update time cannot predate record creation');
  }
  return createValidatedStored(
    Object.freeze({ ...value, scope: Object.freeze([...value.scope]) }),
    metadata,
    'consent'
  );
}

/** Returns whether a record is logically expired at the supplied time. */
export function isLogicallyExpired(record: Stored<unknown>, now: UnixSeconds): boolean {
  assertUnixSeconds(now, 'now');
  return record.metadata.expiresAt !== undefined && record.metadata.expiresAt <= now;
}

/** Returns null for a logically expired record. */
export function hideLogicallyExpired<T>(record: Stored<T> | null, now: UnixSeconds): Stored<T> | null {
  return record !== null && isLogicallyExpired(record, now) ? null : record;
}

/**
 * Creates a frozen generic metadata envelope.
 *
 * Domain stores accept the branded envelopes from the domain-specific
 * factories above. This generic helper is useful to adapter codecs before they
 * validate a decoded domain value.
 */
export function createStored<T>(value: T, metadata: StorageMetadata): Stored<T> {
  validateStorageMetadata(metadata);
  return Object.freeze({
    value,
    metadata: Object.freeze({ ...metadata }),
  });
}

/** Asserts that a new record uses the documented initial revision. */
export function assertInitialStorageRevision(record: Stored<unknown>): void {
  if (record.metadata.revision !== INITIAL_STORAGE_REVISION) {
    throw new TypeError(`New storage records must use revision ${INITIAL_STORAGE_REVISION}`);
  }
}

/** Asserts that a replacement record is the immediate successor of a guarded revision. */
export function assertNextStorageRevision(expectedRevision: number, replacement: Stored<unknown>): void {
  assertNonNegativeSafeInteger(expectedRevision, 'expectedRevision');
  if (replacement.metadata.revision !== expectedRevision + 1) {
    throw new TypeError('Replacement storage revision must immediately follow expectedRevision');
  }
}

/** Returns whether a value was created by a domain-specific stored-record factory. */
export function isValidatedStoredRecord(
  value: unknown
): value is StoredClient | StoredGrant | StoredAccessToken | StoredConsent {
  return validatedStoredRecordKind(value) !== undefined;
}

/** Asserts that a record came from {@link createStoredClient}. */
export function assertStoredClient(value: unknown): asserts value is StoredClient {
  assertStoredRecordKind(value, 'client');
}

/** Asserts that a record came from {@link createStoredGrant}. */
export function assertStoredGrant(value: unknown): asserts value is StoredGrant {
  assertStoredRecordKind(value, 'grant');
}

/** Asserts that a record came from {@link createStoredAccessToken}. */
export function assertStoredAccessToken(value: unknown): asserts value is StoredAccessToken {
  assertStoredRecordKind(value, 'access_token');
}

/** Asserts that a record came from {@link createStoredConsent}. */
export function assertStoredConsent(value: unknown): asserts value is StoredConsent {
  assertStoredRecordKind(value, 'consent');
}

function createValidatedStored<T, Kind extends string>(
  value: T,
  metadata: StorageMetadata,
  kind: Kind
): ValidatedStored<T, Kind> {
  const envelope = createStored(value, metadata);
  return Object.freeze(
    Object.defineProperty({ ...envelope }, STORED_RECORD_KIND, {
      value: kind,
      enumerable: false,
      configurable: false,
      writable: false,
    })
  ) as ValidatedStored<T, Kind>;
}

function validatedStoredRecordKind(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null || !(STORED_RECORD_KIND in value)) return undefined;
  const kind = (value as { readonly [STORED_RECORD_KIND]?: unknown })[STORED_RECORD_KIND];
  return typeof kind === 'string' ? kind : undefined;
}

function assertStoredRecordKind(value: unknown, expected: string): void {
  if (validatedStoredRecordKind(value) !== expected) {
    throw new TypeError(`Expected a validated stored ${expected} record`);
  }
}

function validateStorageMetadata(metadata: StorageMetadata): void {
  assertNonNegativeSafeInteger(metadata.schemaVersion, 'schemaVersion');
  assertNonNegativeSafeInteger(metadata.revision, 'revision');
  assertUnixSeconds(metadata.createdAt, 'createdAt');
  if (metadata.expiresAt !== undefined) assertUnixSeconds(metadata.expiresAt, 'expiresAt');
}

function assertUnixSeconds(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative Unix timestamp in whole seconds`);
  }
}

function assertNonNegativeSafeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer`);
  }
}

function assertNonEmpty(value: string, name: string): void {
  if (value.length === 0) throw new TypeError(`${name} must not be empty`);
}
