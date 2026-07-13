import { describe, expect, it } from 'vitest';
import {
  assertInitialStorageRevision,
  assertNextStorageRevision,
  createPage,
  createPageRequest,
  createStored,
  createStoredAccessToken,
  createStoredClient,
  createStoredGrant,
  credentialIdFromSha256,
  hideLogicallyExpired,
  isLogicallyExpired,
} from '../../src/storage';
import type { Grant } from '../../src/oauth-provider';
import { DIGEST_A, storedAccessToken, storedClient, storedGrant } from './fixtures';

const grant: Grant = {
  id: 'grant-1',
  clientId: 'client-1',
  userId: 'user-1',
  scope: ['read'],
  metadata: {},
  encryptedProps: 'ciphertext',
  createdAt: 100,
};

describe('OAuth storage records', () => {
  it('accepts only the provider SHA-256 credential identifier form', () => {
    const digest = 'a'.repeat(64);
    expect(credentialIdFromSha256(digest)).toBe(digest);
    expect(() => credentialIdFromSha256('raw-token')).toThrow(TypeError);
    expect(() => credentialIdFromSha256('A'.repeat(64))).toThrow(TypeError);
    expect(() => credentialIdFromSha256('a'.repeat(63))).toThrow(TypeError);
  });

  it('keeps canonical values outside frozen storage metadata', () => {
    const stored = createStored(grant, {
      schemaVersion: 0,
      revision: 0,
      createdAt: 100,
      expiresAt: 200,
    });

    expect(stored.value).toBe(grant);
    expect(Object.isFrozen(stored)).toBe(true);
    expect(Object.isFrozen(stored.metadata)).toBe(true);
    expect(stored.metadata.schemaVersion).toBe(0);
  });

  it('validates credential-bearing domain records before storage', () => {
    expect(storedClient().value.clientId).toBe('client-1');
    expect(storedGrant().value.refreshTokenId).toBe(DIGEST_A);
    expect(storedAccessToken().value.id).toHaveLength(64);

    expect(() =>
      createStoredClient(
        {
          clientId: 'client-1',
          clientSecret: 'raw-client-secret' as never,
          redirectUris: [],
          tokenEndpointAuthMethod: 'client_secret_basic',
        },
        { schemaVersion: 1, revision: 0, createdAt: 100 }
      )
    ).toThrow(TypeError);
    expect(() =>
      createStoredGrant(
        {
          ...storedGrant().value,
          refreshTokenId: 'raw-refresh-token' as never,
        },
        { schemaVersion: 1, revision: 0, createdAt: 100, expiresAt: 500 }
      )
    ).toThrow(TypeError);
    expect(() =>
      createStoredAccessToken(
        {
          ...storedAccessToken().value,
          id: 'raw-access-token' as never,
        },
        { schemaVersion: 1, revision: 0, createdAt: 110, expiresAt: 300 }
      )
    ).toThrow(TypeError);
  });

  it('requires canonical and envelope timestamps to agree', () => {
    expect(() =>
      createStoredGrant(storedGrant().value, {
        schemaVersion: 1,
        revision: 0,
        createdAt: 101,
        expiresAt: 500,
      })
    ).toThrow(TypeError);
    expect(() =>
      createStoredAccessToken(storedAccessToken().value, {
        schemaVersion: 1,
        revision: 0,
        createdAt: 110,
        expiresAt: 301,
      })
    ).toThrow(TypeError);
  });

  it('enforces initial and immediate-successor revisions', () => {
    expect(() => assertInitialStorageRevision(storedClient(0))).not.toThrow();
    expect(() => assertInitialStorageRevision(storedClient(1))).toThrow(TypeError);
    expect(() => assertNextStorageRevision(2, storedClient(3))).not.toThrow();
    expect(() => assertNextStorageRevision(2, storedClient(2))).toThrow(TypeError);
    expect(() => assertNextStorageRevision(2, storedClient(4))).toThrow(TypeError);
  });

  it('uses logical expiration at the exact boundary', () => {
    const stored = createStored(grant, {
      schemaVersion: 1,
      revision: 2,
      createdAt: 100,
      expiresAt: 200,
    });

    expect(isLogicallyExpired(stored, 199)).toBe(false);
    expect(isLogicallyExpired(stored, 200)).toBe(true);
    expect(hideLogicallyExpired(stored, 200)).toBeNull();
    expect(hideLogicallyExpired(stored, 199)).toBe(stored);
    expect(hideLogicallyExpired(null, 200)).toBeNull();
  });

  it.each([
    [{ schemaVersion: -1, revision: 0, createdAt: 0 }, 'schema version'],
    [{ schemaVersion: 0, revision: -1, createdAt: 0 }, 'revision'],
    [{ schemaVersion: 0, revision: 0, createdAt: 0.5 }, 'fractional timestamp'],
    [{ schemaVersion: 0, revision: 0, createdAt: 0, expiresAt: -1 }, 'negative expiry'],
  ])('rejects invalid metadata: %s (%s)', (metadata, _description) => {
    expect(() => createStored(grant, metadata)).toThrow(TypeError);
  });
});

describe('OAuth storage pagination', () => {
  it('validates and freezes requests and pages', () => {
    const request = createPageRequest({ limit: 50, cursor: 'opaque' });
    const page = createPage([grant], 'next');

    expect(request).toEqual({ limit: 50, cursor: 'opaque' });
    expect(Object.isFrozen(request)).toBe(true);
    expect(Object.isFrozen(page)).toBe(true);
    expect(Object.isFrozen(page.items)).toBe(true);
    expect(page.cursor).toBe('next');
  });

  it.each([{ limit: 0 }, { limit: -1 }, { limit: 1.5 }, { cursor: '' }])(
    'rejects an invalid request: %j',
    (request) => {
      expect(() => createPageRequest(request)).toThrow(TypeError);
    }
  );

  it('rejects an empty page cursor', () => {
    expect(() => createPage([], '')).toThrow(TypeError);
  });
});
