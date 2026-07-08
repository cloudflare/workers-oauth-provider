import { describe, expect, it } from 'vitest';
import {
  assertStorageOperationSupported,
  defineOAuthStorageCapabilities,
  getStorageCapability,
  MUTATION_CAPABILITY_PATHS,
  QUERY_CAPABILITY_PATHS,
  STORAGE_CAPABILITY_PATHS,
  type OAuthStorageCapabilities,
} from '../../src/storage';
import { storageCapabilities } from './fixtures';

describe('OAuth storage capabilities', () => {
  it('copies and deeply freezes a valid descriptor', () => {
    const input = storageCapabilities();
    const capabilities = defineOAuthStorageCapabilities(input);

    expect(capabilities).not.toBe(input);
    expect(capabilities.clients).not.toBe(input.clients);
    expect(Object.isFrozen(capabilities)).toBe(true);
    expect(Object.isFrozen(capabilities.clients)).toBe(true);
    expect(Object.isFrozen(capabilities.expiration)).toBe(true);
    expect(() => {
      (capabilities.clients as { create: string }).create = 'strong';
    }).toThrow();

    (input.clients as unknown as { create: string }).create = 'strong';
    expect(capabilities.clients.create).toBe('best_effort');
  });

  it('enumerates each semantic capability path exactly once', () => {
    expect(new Set(STORAGE_CAPABILITY_PATHS).size).toBe(STORAGE_CAPABILITY_PATHS.length);
    expect(STORAGE_CAPABILITY_PATHS).toEqual([...MUTATION_CAPABILITY_PATHS, ...QUERY_CAPABILITY_PATHS]);
    expect(STORAGE_CAPABILITY_PATHS).toHaveLength(21);
  });

  it('reads mutation and query capabilities by typed path', () => {
    const capabilities = defineOAuthStorageCapabilities(storageCapabilities());

    expect(getStorageCapability(capabilities, 'transitions.refreshToken')).toBe('best_effort');
    expect(getStorageCapability(capabilities, 'queries.consentsByUser')).toBe('unsupported');
    expect(getStorageCapability(capabilities, 'consistency.readAfterWrite')).toBe('eventual');
  });

  it.each([
    [
      'invalid mutation guarantee',
      (value: OAuthStorageCapabilities) => ((value.clients as unknown as { create: string }).create = 'eventual'),
    ],
    [
      'unsupported read-after-write guarantee',
      (value: OAuthStorageCapabilities) =>
        ((value.consistency as unknown as { readAfterWrite: string }).readAfterWrite = 'unsupported'),
    ],
    [
      'negative minimum TTL',
      (value: OAuthStorageCapabilities) =>
        ((value.expiration as unknown as { minimumTtlSeconds: number }).minimumTtlSeconds = -1),
    ],
    [
      'fractional minimum TTL',
      (value: OAuthStorageCapabilities) =>
        ((value.expiration as unknown as { minimumTtlSeconds: number }).minimumTtlSeconds = 1.5),
    ],
  ])('rejects %s', (_name, mutate) => {
    const value = storageCapabilities();
    mutate(value);
    expect(() => defineOAuthStorageCapabilities(value)).toThrow(TypeError);
  });

  it('throws before I/O for an unsupported mutation', () => {
    expect(() => assertStorageOperationSupported('unsupported', 'replay.reserve')).toThrowError(
      expect.objectContaining({ code: 'unsupported_operation', operation: 'replay.reserve' })
    );
    expect(() => assertStorageOperationSupported('best_effort', 'replay.reserve')).not.toThrow();
  });

  it('permits unsupported optional queries', () => {
    const capabilities = defineOAuthStorageCapabilities(
      storageCapabilities({
        queries: {
          listClients: 'unsupported',
          grantsByUser: 'unsupported',
          grantsByClient: 'unsupported',
          tokensByGrant: 'unsupported',
          consentsByUser: 'unsupported',
          globalMaintenance: 'unsupported',
        },
      })
    );

    expect(capabilities.queries.globalMaintenance).toBe('unsupported');
  });
});
