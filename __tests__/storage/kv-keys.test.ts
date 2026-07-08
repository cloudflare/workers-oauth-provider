import { describe, expect, it } from 'vitest';
import { credentialIdFromSha256 } from '../../src/storage';
import {
  kvAccessTokenKey,
  kvAccessTokenPrefix,
  kvClientKey,
  kvClientPrefix,
  kvGrantKey,
  kvGrantPrefix,
  kvNamespacePrefix,
  kvReplayKey,
} from '../../src/storage/kv/keys';

describe('Workers KV physical keys', () => {
  const tokenId = credentialIdFromSha256('a'.repeat(64));

  it('preserves every legacy key in the default namespace', () => {
    expect(kvNamespacePrefix('default')).toBe('');
    expect(kvClientKey('default', 'client-1')).toBe('client:client-1');
    expect(kvClientPrefix('default')).toBe('client:');
    expect(kvGrantKey('default', { userId: 'user-1', grantId: 'grant-1' })).toBe('grant:user-1:grant-1');
    expect(kvGrantPrefix('default', 'user-1')).toBe('grant:user-1:');
    expect(kvGrantPrefix('default')).toBe('grant:');
    expect(kvAccessTokenKey('default', { userId: 'user-1', grantId: 'grant-1', tokenId })).toBe(
      `token:user-1:grant-1:${tokenId}`
    );
    expect(kvAccessTokenPrefix('default', { userId: 'user-1', grantId: 'grant-1' })).toBe('token:user-1:grant-1:');
    expect(kvReplayKey('default', 'ema-jti', tokenId)).toBe(`enterprise-jti:${tokenId}`);
  });

  it('prefixes and encodes non-default namespaces', () => {
    expect(kvClientKey('tenant:one', 'client-1')).toBe('oauth:tenant%3Aone:client:client-1');
    expect(kvReplayKey('tenant:one', 'custom:replay', tokenId)).toBe(
      `oauth:tenant%3Aone:replay:custom%3Areplay:${tokenId}`
    );
  });
});
