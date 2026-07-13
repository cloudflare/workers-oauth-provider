import { describe, expect, it } from 'vitest';
import { createStoredGrant, type StorageGrant } from '../../src/storage';
import {
  decodeKvAccessToken,
  decodeKvClient,
  decodeKvGrant,
  encodeKvRecord,
  kvAccessTokenPutOptions,
  kvGrantPutOptions,
} from '../../src/storage/kv/codec';
import { DIGEST_A, storedAccessToken, storedClient, storedGrant } from './fixtures';

describe('Workers KV legacy codec', () => {
  it('round-trips canonical JSON without storage metadata', () => {
    for (const record of [storedClient(), storedGrant(), storedAccessToken()]) {
      const encoded = encodeKvRecord(record);
      expect(JSON.parse(encoded)).toEqual(record.value);
      expect(encoded).not.toContain('schemaVersion');
      expect(encoded).not.toContain('revision');
    }
  });

  it('decodes existing schema-zero records with digest-only credential fields', () => {
    const client = decodeKvClient(storedClient().value);
    const grant = decodeKvGrant(storedGrant().value);
    const token = decodeKvAccessToken(storedAccessToken().value);

    expect(client.metadata).toEqual({ schemaVersion: 0, revision: 0, createdAt: 0 });
    expect(grant.metadata).toEqual({ schemaVersion: 0, revision: 0, createdAt: 100, expiresAt: 500 });
    expect(token.metadata).toEqual({ schemaVersion: 0, revision: 0, createdAt: 110, expiresAt: 300 });
    expect(grant.value.refreshTokenId).toBe(DIGEST_A);
    expect(encodeKvRecord(client)).toBe(JSON.stringify(storedClient().value));
    expect(encodeKvRecord(grant)).toBe(JSON.stringify(storedGrant().value));
    expect(encodeKvRecord(token)).toBe(JSON.stringify(storedAccessToken().value));
  });

  it('derives the fixed logical and physical lifetime for a pending authorization code', () => {
    const value: StorageGrant = {
      ...storedGrant().value,
      expiresAt: undefined,
      refreshTokenId: undefined,
      authCodeId: DIGEST_A,
      authCodeWrappedKey: 'wrapped-code-key',
    };
    const pending = createStoredGrant(value, {
      schemaVersion: 1,
      revision: 0,
      createdAt: 100,
      expiresAt: 700,
    });
    const decoded = decodeKvGrant(value);

    expect(decoded.metadata.expiresAt).toBe(700);
    expect(kvGrantPutOptions(pending, 100)).toEqual({ expirationTtl: 600 });
  });

  it('uses the existing absolute grant clamp and relative access-token TTL', () => {
    expect(kvGrantPutOptions(storedGrant(), 450)).toEqual({ expiration: 515 });
    expect(kvGrantPutOptions(storedGrant(), 100)).toEqual({ expiration: 500 });
    expect(kvAccessTokenPutOptions(storedAccessToken())).toEqual({ expirationTtl: 190 });
  });

  it.each([
    ['missing client auth method', () => decodeKvClient({ clientId: 'client-1', redirectUris: [] })],
    [
      'non-array redirect URIs',
      () => decodeKvClient({ ...storedClient().value, redirectUris: 'https://client.example' }),
    ],
    ['invalid client contacts', () => decodeKvClient({ ...storedClient().value, contacts: [42] })],
    ['invalid localized metadata', () => decodeKvClient({ ...storedClient().value, i18n: [] })],
    ['raw refresh token', () => decodeKvGrant({ ...storedGrant().value, refreshTokenId: 'raw-token' })],
    ['invalid grant scopes', () => decodeKvGrant({ ...storedGrant().value, scope: 'read' })],
    ['invalid grant timestamp', () => decodeKvGrant({ ...storedGrant().value, createdAt: -1 })],
    ['invalid grant resource', () => decodeKvGrant({ ...storedGrant().value, resource: 42 })],
    ['raw access token', () => decodeKvAccessToken({ ...storedAccessToken().value, id: 'raw-token' })],
    ['invalid token scopes', () => decodeKvAccessToken({ ...storedAccessToken().value, scope: 'read' })],
    ['invalid token grant', () => decodeKvAccessToken({ ...storedAccessToken().value, grant: null })],
    [
      'invalid nested grant scopes',
      () =>
        decodeKvAccessToken({
          ...storedAccessToken().value,
          grant: { ...storedAccessToken().value.grant, scope: [42] },
        }),
    ],
    ['token expiring before creation', () => decodeKvAccessToken({ ...storedAccessToken().value, expiresAt: 100 })],
    ['non-object grant', () => decodeKvGrant(null)],
  ])('rejects malformed record: %s', (_name, decode) => {
    expect(decode).toThrow(TypeError);
  });
});
