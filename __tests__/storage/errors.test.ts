import { describe, expect, it } from 'vitest';
import { isOAuthStorageError, OAuthStorageError, unsupportedStorageOperation } from '../../src/storage';

describe('OAuthStorageError', () => {
  it('is retryable only for rate limiting', () => {
    expect(new OAuthStorageError('rate_limited').retryable).toBe(true);
    expect(new OAuthStorageError('unsupported_operation').retryable).toBe(false);
    expect(new OAuthStorageError('invalid_configuration').retryable).toBe(false);
  });

  it('keeps the backend cause out of the message and serialized form', () => {
    const cause = new Error('KV PUT failed: 429 Too Many Requests');
    const error = new OAuthStorageError('rate_limited', { cause, operation: 'grants.put' });

    expect(error.cause).toBe(cause);
    expect(Object.keys(error)).not.toContain('cause');
    expect(error.message).toBe('OAuth storage operation failed (rate_limited)');
    expect(JSON.stringify(error)).not.toContain('429');
    expect(isOAuthStorageError(error)).toBe(true);
    expect(isOAuthStorageError(cause)).toBe(false);
  });

  it('creates the standard unsupported-operation failure', () => {
    expect(unsupportedStorageOperation('clients.list')).toMatchObject({
      code: 'unsupported_operation',
      retryable: false,
      operation: 'clients.list',
    });
  });
});
