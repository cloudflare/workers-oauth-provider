import { assertStorageOperationSupported, type MutationGuarantee, type OAuthStorageCapabilities } from './capabilities';
import { unsupportedStorageOperation } from './errors';
import type { Page, PageRequest } from './pagination';
import {
  assertInitialStorageRevision,
  assertNextStorageRevision,
  assertStoredAccessToken,
  assertStoredClient,
  assertStoredConsent,
  assertStoredGrant,
  type AccessTokenKey,
  type ClientReference,
  type CredentialId,
  type GrantKey,
  type StoredAccessToken,
  type StoredClient,
  type StoredConsent,
  type StoredGrant,
  type UnixSeconds,
} from './records';
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
} from './results';
import type {
  AbortGrantTransitionInput,
  AbortGrantTransitionResult,
  BeginGrantTransitionInput,
  BeginGrantTransitionResult,
  CommitGrantTransitionResult,
  ValidatedCommitGrantTransitionInput,
} from './transitions';

const STORE_INPUT_KIND: unique symbol = Symbol('OAuthStoreInputKind');

type ValidatedInput<T, Kind extends string> = Readonly<T> & {
  readonly [STORE_INPUT_KIND]: Kind;
};

/** Validated insert-if-absent input for a registered client. */
export type CreateClientInput = ValidatedInput<{ readonly client: StoredClient }, 'create_client'>;

/** Validated immediate-successor replacement input for a registered client. */
export type ReplaceClientInput = ValidatedInput<
  {
    readonly clientId: string;
    readonly expectedRevision: number;
    readonly client: StoredClient;
  },
  'replace_client'
>;

/** Validated input for composite initial grant issuance. */
export type IssueGrantInput = ValidatedInput<
  {
    /** Stored or externally resolved client authority for this grant. */
    readonly client: ClientReference;
    /** New grant record at the initial revision. */
    readonly grant: StoredGrant;
    /** Optional first token, included in the composite operation. */
    readonly accessToken?: StoredAccessToken;
    /** Atomically revoke earlier grants for this user/client pair when supported. */
    readonly replaceExistingUserClientGrants?: boolean;
  },
  'issue_grant'
>;

/** Validated input for token exchange on an existing active grant. */
export type IssueAccessTokenInput = ValidatedInput<
  {
    readonly grant: GrantKey;
    readonly expectedGrantRevision: number;
    readonly token: StoredAccessToken;
  },
  'issue_access_token'
>;

/** Validated input for persistent-consent compare-and-swap. */
export type CompareAndSwapConsentInput = ValidatedInput<
  {
    readonly consent: StoredConsent;
    /** Omit only for insert-if-absent. */
    readonly expectedRevision?: number;
  },
  'compare_and_swap_consent'
>;

/** Creates a validated insert-if-absent registered-client plan. */
export function createClientInput(client: StoredClient): CreateClientInput {
  assertStoredClient(client);
  assertInitialStorageRevision(client);
  return brandInput({ client }, 'create_client');
}

/** Asserts that input came from {@link createClientInput}. */
export function assertCreateClientInput(value: unknown): asserts value is CreateClientInput {
  assertStoreInputKind(value, 'create_client');
}

/** Creates a validated immediate-successor registered-client replacement plan. */
export function replaceClientInput(
  clientId: string,
  expectedRevision: number,
  client: StoredClient
): ReplaceClientInput {
  assertStoredClient(client);
  if (clientId.length === 0 || client.value.clientId !== clientId) {
    throw new TypeError('Replacement client identity must match clientId');
  }
  assertNextStorageRevision(expectedRevision, client);
  return brandInput({ clientId, expectedRevision, client }, 'replace_client');
}

/** Asserts that input came from {@link replaceClientInput}. */
export function assertReplaceClientInput(value: unknown): asserts value is ReplaceClientInput {
  assertStoreInputKind(value, 'replace_client');
}

/**
 * Creates a validated composite grant-issuance plan.
 *
 * A returned `created` result means every requested effect completed. A
 * best-effort adapter may leave partial effects only when it throws a storage
 * error; it must never return `created` for a partial plan. Strong guarantees
 * cover the complete plan, including the registered-client guard.
 */
export function issueGrantInput(input: {
  readonly client: ClientReference;
  readonly grant: StoredGrant;
  readonly accessToken?: StoredAccessToken;
  readonly replaceExistingUserClientGrants?: boolean;
}): IssueGrantInput {
  assertStoredGrant(input.grant);
  assertInitialStorageRevision(input.grant);
  if (input.client.kind !== 'registered' && input.client.kind !== 'external') {
    throw new TypeError('Invalid client reference kind');
  }
  if (input.client.clientId !== input.grant.value.clientId) {
    throw new TypeError('Grant client must match the client reference');
  }
  if (input.client.kind === 'registered') {
    assertNonNegativeSafeInteger(input.client.expectedRevision, 'expectedClientRevision');
  }
  if (
    input.replaceExistingUserClientGrants !== undefined &&
    typeof input.replaceExistingUserClientGrants !== 'boolean'
  ) {
    throw new TypeError('replaceExistingUserClientGrants must be a boolean');
  }
  if (input.accessToken !== undefined) {
    assertStoredAccessToken(input.accessToken);
    assertInitialStorageRevision(input.accessToken);
    assertTokenBelongsToGrant(input.accessToken, input.grant);
  }
  return brandInput({ ...input }, 'issue_grant');
}

/** Asserts that input came from {@link issueGrantInput}. */
export function assertIssueGrantInput(value: unknown): asserts value is IssueGrantInput {
  assertStoreInputKind(value, 'issue_grant');
}

/** Returns the one composite capability governing a validated grant-issuance plan. */
export function getIssueGrantGuarantee(
  capabilities: OAuthStorageCapabilities,
  input: IssueGrantInput
): MutationGuarantee {
  if (input.replaceExistingUserClientGrants === true) {
    return capabilities.issuance.replaceUserClientGrants;
  }
  return input.accessToken === undefined ? capabilities.issuance.grantOnly : capabilities.issuance.grantWithAccessToken;
}

/** Throws before adapter I/O when a composite grant-issuance plan is unavailable. */
export function assertIssueGrantSupported(capabilities: OAuthStorageCapabilities, input: IssueGrantInput): void {
  assertStorageOperationSupported(getIssueGrantGuarantee(capabilities, input), 'grants.issue');
}

/** Creates a validated existing-grant access-token issuance plan. */
export function issueAccessTokenInput(input: {
  readonly grant: GrantKey;
  readonly expectedGrantRevision: number;
  readonly token: StoredAccessToken;
}): IssueAccessTokenInput {
  assertStoredAccessToken(input.token);
  assertNonNegativeSafeInteger(input.expectedGrantRevision, 'expectedGrantRevision');
  assertInitialStorageRevision(input.token);
  if (input.token.value.userId !== input.grant.userId || input.token.value.grantId !== input.grant.grantId) {
    throw new TypeError('Access token must belong to the guarded grant');
  }
  return brandInput({ ...input, grant: Object.freeze({ ...input.grant }) }, 'issue_access_token');
}

/** Asserts that input came from {@link issueAccessTokenInput}. */
export function assertIssueAccessTokenInput(value: unknown): asserts value is IssueAccessTokenInput {
  assertStoreInputKind(value, 'issue_access_token');
}

/** Creates a validated persistent-consent compare-and-swap plan. */
export function compareAndSwapConsentInput(input: {
  readonly consent: StoredConsent;
  readonly expectedRevision?: number;
}): CompareAndSwapConsentInput {
  assertStoredConsent(input.consent);
  if (input.expectedRevision === undefined) assertInitialStorageRevision(input.consent);
  else assertNextStorageRevision(input.expectedRevision, input.consent);
  return brandInput({ ...input }, 'compare_and_swap_consent');
}

/** Asserts that input came from {@link compareAndSwapConsentInput}. */
export function assertCompareAndSwapConsentInput(value: unknown): asserts value is CompareAndSwapConsentInput {
  assertStoreInputKind(value, 'compare_and_swap_consent');
}

/** Dynamically registered client operations. External CIMD clients are not stored here. */
export interface OAuthClientStore {
  /** Returns a registered client or null; logically expired clients are returned as null. */
  get(clientId: string): Promise<StoredClient | null>;
  /** Inserts a registered client only when the client ID is absent. */
  create(input: CreateClientInput): Promise<CreateResult>;
  /** Replaces a registered client only at the expected revision. */
  replace(input: ReplaceClientInput): Promise<ReplaceResult>;
  /**
   * Deletes a registered client and all child grants and tokens. A strong
   * implementation excludes concurrent registered-client grant creation.
   * When unsupported, reject with `unsupportedStorageOperation` before I/O.
   */
  deleteWithGrants(input: {
    readonly clientId: string;
    readonly expectedRevision?: number;
  }): Promise<DeleteClientResult>;
  /** Lists non-expired registered clients using an adapter-owned cursor. */
  list(input?: PageRequest): Promise<Page<StoredClient>>;
}

/** Grant issuance, transitions, indexed queries, and cascade revocation. */
export interface OAuthGrantStore {
  /** Returns a non-expired grant or null. */
  get(key: GrantKey): Promise<StoredGrant | null>;
  /** Performs one validated composite issue plan. */
  issue(input: IssueGrantInput): Promise<IssueGrantResult>;
  /** Lists non-expired grants owned by one user. */
  listByUser(input: { readonly userId: string; readonly page?: PageRequest }): Promise<Page<StoredGrant>>;
  /** Lists non-expired grants issued to one client. */
  listByClient(input: { readonly clientId: string; readonly page?: PageRequest }): Promise<Page<StoredGrant>>;
  /**
   * Acquires fenced authority over one presented code or refresh token. When
   * unsupported, reject with `unsupportedStorageOperation` before I/O.
   */
  beginTransition(input: BeginGrantTransitionInput): Promise<BeginGrantTransitionResult>;
  /** Commits a validated next grant revision and token under a current lease. */
  commitTransition(input: ValidatedCommitGrantTransitionInput): Promise<CommitGrantTransitionResult>;
  /** Releases a still-current lease without changing the grant. */
  abortTransition(input: AbortGrantTransitionInput): Promise<AbortGrantTransitionResult>;
  /**
   * Revokes a grant and all child access tokens. Returned counts are effects
   * observed by the adapter; only a strong capability promises an atomic total.
   */
  revoke(input: { readonly grant: GrantKey; readonly expectedRevision?: number }): Promise<RevokeGrantResult>;
}

/** Immutable access-token operations. */
export interface OAuthAccessTokenStore {
  /** Returns a non-expired access-token record or null. */
  get(key: AccessTokenKey): Promise<StoredAccessToken | null>;
  /**
   * Creates a token only while the backing grant exists at the expected
   * revision. When unsupported, reject before I/O.
   */
  createForGrant(input: IssueAccessTokenInput): Promise<IssueAccessTokenResult>;
  /** Deletes one access-token record. */
  delete(input: { readonly key: AccessTokenKey }): Promise<DeleteResult>;
  /** Lists non-expired access tokens belonging to one grant. */
  listByGrant(input: { readonly grant: GrantKey; readonly page?: PageRequest }): Promise<Page<StoredAccessToken>>;
}

/** Persistent-consent compare-and-swap operations. */
export interface OAuthConsentStore {
  /** Returns non-expired consent for the normalized user/client/reference tuple. */
  get(input: {
    readonly userId: string;
    readonly clientId: string;
    readonly referenceId?: string;
  }): Promise<StoredConsent | null>;
  /** Creates or replaces consent only when the supplied revision condition holds. */
  compareAndSwap(input: CompareAndSwapConsentInput): Promise<ReplaceConsentResult>;
  /** Deletes consent only when the supplied revision, if any, still matches. */
  delete(input: {
    readonly userId: string;
    readonly clientId: string;
    readonly referenceId?: string;
    readonly expectedRevision?: number;
  }): Promise<DeleteResult>;
  /** Lists non-expired persistent consents owned by one user. */
  listByUser(input: { readonly userId: string; readonly page?: PageRequest }): Promise<Page<StoredConsent>>;
}

/** Atomic replay-reservation operations. */
export interface OAuthReplayStore {
  /**
   * Reserves a hashed one-time identifier until logical expiry. A get followed
   * by a put is best-effort. When unsupported, reject before I/O.
   */
  reserve(input: {
    readonly reservationNamespace: string;
    readonly keyHash: CredentialId;
    readonly expiresAt: UnixSeconds;
  }): Promise<ReplayReservationResult>;
}

/** Result of one bounded physical-cleanup pass. */
export interface PurgeExpiredResult {
  readonly deleted: number;
  readonly cursor?: string;
  readonly done: boolean;
}

/** Adapter-owned bounded physical cleanup. */
export interface OAuthMaintenanceStore {
  /**
   * Removes expired or orphaned physical state. When unsupported, reject with
   * `unsupportedStorageOperation` before I/O.
   */
  purgeExpired(input: {
    readonly now: UnixSeconds;
    readonly limit: number;
    readonly cursor?: string;
  }): Promise<PurgeExpiredResult>;
}

/** Standard no-side-effect implementation for an unsupported async store method. */
export async function rejectUnsupportedStorageOperation(operation: string): Promise<never> {
  throw unsupportedStorageOperation(operation);
}

function assertTokenBelongsToGrant(token: StoredAccessToken, grant: StoredGrant): void {
  if (token.value.userId !== grant.value.userId || token.value.grantId !== grant.value.id) {
    throw new TypeError('Access token must belong to the issued grant');
  }
  if (token.value.grant.clientId !== grant.value.clientId) {
    throw new TypeError('Access-token client must match the issued grant');
  }
}

function brandInput<T, Kind extends string>(value: T, kind: Kind): ValidatedInput<T, Kind> {
  return Object.freeze(
    Object.defineProperty({ ...value }, STORE_INPUT_KIND, {
      value: kind,
      enumerable: false,
      configurable: false,
      writable: false,
    })
  ) as ValidatedInput<T, Kind>;
}

function assertStoreInputKind(value: unknown, expected: string): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    !(STORE_INPUT_KIND in value) ||
    (value as { readonly [STORE_INPUT_KIND]?: unknown })[STORE_INPUT_KIND] !== expected
  ) {
    throw new TypeError(`Expected validated ${expected} input`);
  }
}

function assertNonNegativeSafeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer`);
  }
}
