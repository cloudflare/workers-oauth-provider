import { describe, expect, it } from 'vitest';
import { isOAuthStorageError, OAuthStorageError, unsupportedStorageOperation } from '../../src/storage';

describe('OAuthStorageError', () => {
  it.each([
    ['unavailable', true],
    ['timeout', true],
    ['rate_limited', true],
    ['conflict', false],
    ['schema_mismatch', false],
    ['unsupported_operation', false],
    ['invalid_configuration', false],
    ['internal', false],
  ] as const)('assigns the default retryability for %s', (code, retryable) => {
    expect(new OAuthStorageError(code).retryable).toBe(retryable);
  });

  it('retains a backend cause without serializing or exposing it in the message', () => {
    const cause = new Error('postgres://secret-host/private?password=secret');
    const error = new OAuthStorageError('unavailable', {
      cause,
      operation: 'grants.issue',
    });

    expect(error.cause).toBe(cause);
    expect(Object.keys(error)).not.toContain('cause');
    expect(error.message).toBe('OAuth storage operation failed (unavailable)');
    expect(JSON.parse(JSON.stringify(error))).toEqual({
      name: 'OAuthStorageError',
      code: 'unavailable',
      retryable: true,
      operation: 'grants.issue',
    });
    expect(JSON.stringify(error)).not.toContain('secret');
    expect(isOAuthStorageError(error)).toBe(true);
    expect(isOAuthStorageError(cause)).toBe(false);
  });

  it('allows a deliberate retryability override', () => {
    expect(new OAuthStorageError('internal', { retryable: true }).retryable).toBe(true);
  });

  it.each(['', 'not_real', 42, null])('rejects unknown runtime error code %j', (code) => {
    expect(() => new OAuthStorageError(code as never)).toThrow(TypeError);
  });

  it.each(['', 'token:raw-secret', 'grants issue', 'A'.repeat(81), 42, null])(
    'rejects unsafe operation name %j',
    (operation) => {
      expect(() => new OAuthStorageError('internal', { operation: operation as never })).toThrow(TypeError);
    }
  );

  it('creates the standard unsupported-operation failure', () => {
    const error = unsupportedStorageOperation('consents.compareAndSwap');
    expect(error).toMatchObject({
      code: 'unsupported_operation',
      retryable: false,
      operation: 'consents.compareAndSwap',
    });
  });
});
