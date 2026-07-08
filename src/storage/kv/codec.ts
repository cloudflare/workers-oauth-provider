import type { ClientInfo, Grant, Token } from '../../oauth-provider';
import {
  createStoredAccessToken,
  createStoredClient,
  createStoredGrant,
  credentialIdFromSha256,
  type StorageAccessToken,
  type StorageClient,
  type StorageGrant,
  type StoredAccessToken,
  type StoredClient,
  type StoredGrant,
} from '../records';

/** Fixed lifetime of a pending authorization-code grant in the legacy KV schema. */
export const KV_AUTHORIZATION_CODE_TTL_SECONDS = 600;

/** Minimum relative or absolute lifetime accepted by Workers KV. */
export const KV_MIN_EXPIRATION_TTL_SECONDS = 60;

/** Margin used when clamping an absolute expiration against KV clock skew. */
export const KV_EXPIRATION_CLAMP_MARGIN_SECONDS = 5;

/** Decodes and validates a legacy Workers KV client JSON value. */
export function decodeKvClient(value: unknown): StoredClient {
  const client = assertRecord(value, 'client') as unknown as ClientInfo;
  validateClient(client);
  if (client.clientSecret !== undefined) credentialIdFromSha256(client.clientSecret);
  // Validation above proves the branded field without rebuilding the object,
  // preserving legacy JSON property order and unknown fields.
  const storageClient = client as StorageClient;
  return createStoredClient(storageClient, {
    schemaVersion: 0,
    revision: 0,
    createdAt: normalizeTimestamp(client.registrationDate),
  });
}

/** Decodes and validates a legacy Workers KV grant JSON value. */
export function decodeKvGrant(value: unknown): StoredGrant {
  const grant = assertRecord(value, 'grant') as unknown as Grant;
  validateGrant(grant);
  for (const credential of [grant.authCodeId, grant.refreshTokenId, grant.previousRefreshTokenId]) {
    if (credential !== undefined) credentialIdFromSha256(credential);
  }
  // Validation above proves the branded fields without rebuilding the object,
  // preserving legacy JSON property order and unknown fields.
  const storageGrant = grant as StorageGrant;
  const pendingCodeExpiry =
    grant.expiresAt === undefined && grant.authCodeId !== undefined && grant.authCodeWrappedKey !== undefined
      ? grant.createdAt + KV_AUTHORIZATION_CODE_TTL_SECONDS
      : undefined;
  return createStoredGrant(storageGrant, {
    schemaVersion: 0,
    revision: 0,
    createdAt: grant.createdAt,
    expiresAt: grant.expiresAt ?? pendingCodeExpiry,
  });
}

/** Decodes the parent identity needed for best-effort legacy cleanup. */
export function decodeKvAccessTokenParent(value: unknown): { readonly userId: string; readonly grantId: string } {
  const token = assertRecord(value, 'access token');
  assertString(token.userId, 'token.userId');
  assertString(token.grantId, 'token.grantId');
  return { userId: token.userId, grantId: token.grantId };
}

/** Decodes and validates a legacy Workers KV access-token JSON value. */
export function decodeKvAccessToken(value: unknown): StoredAccessToken {
  const token = assertRecord(value, 'access token') as unknown as Token;
  validateAccessToken(token);
  const storageToken: StorageAccessToken = {
    ...token,
    id: credentialIdFromSha256(token.id),
  };
  return createStoredAccessToken(storageToken, {
    schemaVersion: 0,
    revision: 0,
    createdAt: token.createdAt,
    expiresAt: token.expiresAt,
  });
}

/** Serializes only the canonical value, preserving the legacy JSON schema. */
export function encodeKvRecord(record: StoredClient | StoredGrant | StoredAccessToken): string {
  return JSON.stringify(record.value);
}

/** Selects the legacy physical expiration options for a grant write. */
export function kvGrantPutOptions(
  grant: StoredGrant,
  now: number
): { readonly expirationTtl: number } | { readonly expiration: number } | undefined {
  if (
    grant.value.expiresAt === undefined &&
    grant.value.authCodeId !== undefined &&
    grant.value.authCodeWrappedKey !== undefined
  ) {
    return { expirationTtl: KV_AUTHORIZATION_CODE_TTL_SECONDS };
  }
  if (grant.value.expiresAt === undefined) return undefined;
  return {
    expiration: Math.max(
      grant.value.expiresAt,
      now + KV_MIN_EXPIRATION_TTL_SECONDS + KV_EXPIRATION_CLAMP_MARGIN_SECONDS
    ),
  };
}

/** Selects the legacy relative TTL for an access-token write. */
export function kvAccessTokenPutOptions(token: StoredAccessToken): { readonly expirationTtl: number } {
  const expirationTtl = token.value.expiresAt - token.value.createdAt;
  if (!Number.isSafeInteger(expirationTtl) || expirationTtl < KV_MIN_EXPIRATION_TTL_SECONDS) {
    throw new TypeError(`Workers KV access-token TTL must be at least ${KV_MIN_EXPIRATION_TTL_SECONDS} seconds`);
  }
  return { expirationTtl };
}

function validateClient(client: ClientInfo): void {
  assertString(client.clientId, 'client.clientId');
  assertStringArray(client.redirectUris, 'client.redirectUris');
  assertString(client.tokenEndpointAuthMethod, 'client.tokenEndpointAuthMethod');
  for (const [name, value] of Object.entries({
    clientSecret: client.clientSecret,
    clientName: client.clientName,
    logoUri: client.logoUri,
    clientUri: client.clientUri,
    policyUri: client.policyUri,
    tosUri: client.tosUri,
    jwksUri: client.jwksUri,
  })) {
    if (value !== undefined) assertString(value, `client.${name}`);
  }
  for (const [name, value] of Object.entries({
    contacts: client.contacts,
    grantTypes: client.grantTypes,
    responseTypes: client.responseTypes,
  })) {
    if (value !== undefined) assertStringArray(value, `client.${name}`);
  }
  if (client.registrationDate !== undefined) assertUnixSeconds(client.registrationDate, 'client.registrationDate');
  if (client.i18n !== undefined) {
    if (typeof client.i18n !== 'object' || client.i18n === null || Array.isArray(client.i18n)) {
      throw new TypeError('Invalid Workers KV client.i18n');
    }
    for (const value of Object.values(client.i18n)) assertString(value, 'client.i18n value');
  }
}

function validateGrant(grant: Grant): void {
  assertString(grant.id, 'grant.id');
  assertString(grant.clientId, 'grant.clientId');
  assertString(grant.userId, 'grant.userId');
  assertStringArray(grant.scope, 'grant.scope');
  assertString(grant.encryptedProps, 'grant.encryptedProps');
  assertUnixSeconds(grant.createdAt, 'grant.createdAt');
  if (grant.expiresAt !== undefined) assertUnixSeconds(grant.expiresAt, 'grant.expiresAt');
  for (const [name, value] of Object.entries({
    authCodeId: grant.authCodeId,
    authCodeWrappedKey: grant.authCodeWrappedKey,
    refreshTokenId: grant.refreshTokenId,
    refreshTokenWrappedKey: grant.refreshTokenWrappedKey,
    previousRefreshTokenId: grant.previousRefreshTokenId,
    previousRefreshTokenWrappedKey: grant.previousRefreshTokenWrappedKey,
    codeChallenge: grant.codeChallenge,
    codeChallengeMethod: grant.codeChallengeMethod,
  })) {
    if (value !== undefined) assertString(value, `grant.${name}`);
  }
  assertStringOrStringArray(grant.resource, 'grant.resource');
}

function validateAccessToken(token: Token): void {
  assertString(token.id, 'token.id');
  assertString(token.grantId, 'token.grantId');
  assertString(token.userId, 'token.userId');
  assertUnixSeconds(token.createdAt, 'token.createdAt');
  assertUnixSeconds(token.expiresAt, 'token.expiresAt');
  if (token.expiresAt < token.createdAt) throw new TypeError('Invalid Workers KV token expiration');
  assertStringArray(token.scope, 'token.scope');
  assertString(token.wrappedEncryptionKey, 'token.wrappedEncryptionKey');
  assertStringOrStringArray(token.audience, 'token.audience');
  if (token.grant !== undefined) {
    if (typeof token.grant !== 'object' || token.grant === null || Array.isArray(token.grant)) {
      throw new TypeError('Invalid Workers KV token.grant');
    }
    assertString(token.grant.clientId, 'token.grant.clientId');
    assertStringArray(token.grant.scope, 'token.grant.scope');
    assertString(token.grant.encryptedProps, 'token.grant.encryptedProps');
  }
}

function assertString(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string') throw new TypeError(`Invalid Workers KV ${name}`);
}

function assertStringArray(value: unknown, name: string): asserts value is string[] {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
    throw new TypeError(`Invalid Workers KV ${name}`);
  }
}

function assertStringOrStringArray(value: unknown, name: string): void {
  if (value === undefined || typeof value === 'string') return;
  assertStringArray(value, name);
}

function assertUnixSeconds(value: unknown, name: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`Invalid Workers KV ${name}`);
  }
}

function assertRecord(value: unknown, kind: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`Invalid Workers KV ${kind} record`);
  }
  return value as Record<string, unknown>;
}

function normalizeTimestamp(value: number | undefined): number {
  return Number.isSafeInteger(value) && value !== undefined && value >= 0 ? value : 0;
}
