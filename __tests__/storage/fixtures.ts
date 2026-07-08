import {
  createStoredAccessToken,
  createStoredClient,
  createStoredGrant,
  credentialIdFromSha256,
  type OAuthStorageCapabilities,
  type StorageAccessToken,
  type StorageGrant,
  type StoredAccessToken,
  type StoredClient,
  type StoredGrant,
} from '../../src/storage';

export const DIGEST_A = credentialIdFromSha256('a'.repeat(64));
export const DIGEST_B = credentialIdFromSha256('b'.repeat(64));
export const DIGEST_C = credentialIdFromSha256('c'.repeat(64));

export function storedClient(revision = 0): StoredClient {
  return createStoredClient(
    {
      clientId: 'client-1',
      redirectUris: ['https://client.example/callback'],
      tokenEndpointAuthMethod: 'none',
    },
    {
      schemaVersion: 1,
      revision,
      createdAt: 100,
    }
  );
}

export function storedGrant(revision = 0, overrides: Partial<StorageGrant> = {}): StoredGrant {
  const value: StorageGrant = {
    id: 'grant-1',
    clientId: 'client-1',
    userId: 'user-1',
    scope: ['read'],
    metadata: {},
    encryptedProps: 'ciphertext',
    createdAt: 100,
    expiresAt: 500,
    refreshTokenId: DIGEST_A,
    ...overrides,
  };
  return createStoredGrant(value, {
    schemaVersion: 1,
    revision,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
  });
}

export function storedAccessToken(revision = 0, overrides: Partial<StorageAccessToken> = {}): StoredAccessToken {
  const value: StorageAccessToken = {
    id: DIGEST_B,
    grantId: 'grant-1',
    userId: 'user-1',
    createdAt: 110,
    expiresAt: 300,
    scope: ['read'],
    wrappedEncryptionKey: 'wrapped-key',
    grant: {
      clientId: 'client-1',
      scope: ['read'],
      encryptedProps: 'ciphertext',
    },
    ...overrides,
  };
  return createStoredAccessToken(value, {
    schemaVersion: 1,
    revision,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
  });
}

export function storageCapabilities(overrides: Partial<OAuthStorageCapabilities> = {}): OAuthStorageCapabilities {
  return {
    consistency: { readAfterWrite: 'eventual' },
    clients: {
      create: 'best_effort',
      replace: 'best_effort',
    },
    issuance: {
      grantOnly: 'best_effort',
      grantWithAccessToken: 'best_effort',
      replaceUserClientGrants: 'best_effort',
      existingGrantAccessToken: 'best_effort',
    },
    transitions: {
      authorizationCode: 'best_effort',
      refreshToken: 'best_effort',
    },
    replayReservation: 'best_effort',
    revocation: {
      accessToken: 'best_effort',
      grantCascade: 'best_effort',
      clientCascade: 'best_effort',
    },
    consents: {
      compareAndSwap: 'unsupported',
      delete: 'unsupported',
    },
    queries: {
      listClients: 'eventual',
      grantsByUser: 'eventual',
      grantsByClient: 'eventual',
      tokensByGrant: 'eventual',
      consentsByUser: 'unsupported',
      globalMaintenance: 'eventual',
    },
    expiration: {
      cleanup: 'native',
      minimumTtlSeconds: 60,
    },
    ...overrides,
  };
}
