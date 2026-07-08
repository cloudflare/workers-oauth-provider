import { describe, expect, it } from 'vitest';
import {
  assertStorageConnectionNamespace,
  createOAuthStorageOpenContext,
  defineStorageNamespace,
  validateOAuthStorageProvider,
  type OAuthStorageProvider,
} from '../../src/storage';
import { storageCapabilities } from './fixtures';

function provider(overrides: Partial<OAuthStorageProvider<{ value: number }>> = {}): OAuthStorageProvider<{
  value: number;
}> {
  return {
    id: 'cloudflare-kv',
    contractVersion: 1,
    namespace: 'default',
    capabilities: storageCapabilities(),
    open: async () => {
      throw new Error('not used');
    },
    ...overrides,
  };
}

describe('OAuth storage lifecycle', () => {
  it('validates provider identity and namespace', () => {
    expect(() => validateOAuthStorageProvider(provider())).not.toThrow();
    expect(defineStorageNamespace()).toBe('default');
    expect(defineStorageNamespace('tenant_1')).toBe('tenant_1');
    expect(() => validateOAuthStorageProvider(provider({ id: ' Invalid ' }))).toThrow(TypeError);
    expect(() => validateOAuthStorageProvider(provider({ contractVersion: 2 as never }))).toThrow(TypeError);
    expect(() => defineStorageNamespace(' tenant ')).toThrow(TypeError);
    expect(() => defineStorageNamespace('a'.repeat(129))).toThrow(TypeError);
  });

  it('creates request-scoped context from the provider namespace', () => {
    const value = createOAuthStorageOpenContext({
      provider: provider({ namespace: 'tenant-1' }),
      env: { value: 1 },
      operationId: 'request_123',
      kind: 'request',
    });

    expect(value).toEqual({
      env: { value: 1 },
      namespace: 'tenant-1',
      operationId: 'request_123',
      kind: 'request',
    });
    expect(Object.isFrozen(value)).toBe(true);
  });

  it('rejects unsafe operation IDs and mismatched connection namespaces', () => {
    expect(() =>
      createOAuthStorageOpenContext({
        provider: provider(),
        env: { value: 1 },
        operationId: 'raw token:value',
        kind: 'request',
      })
    ).toThrow(TypeError);
    expect(() => assertStorageConnectionNamespace({ namespace: 'tenant-1' }, { namespace: 'tenant-2' })).toThrow(
      TypeError
    );
    expect(() => assertStorageConnectionNamespace({ namespace: 'tenant-1' }, { namespace: 'tenant-1' })).not.toThrow();
  });
});
