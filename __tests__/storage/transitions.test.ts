import { describe, expect, it } from 'vitest';
import {
  beginGrantTransitionInput,
  callbackIdempotencyKey,
  commitGrantTransitionInput,
  createGrantTransitionLease,
  deriveCallbackIdempotencyKey,
  transitionLeaseId,
  transitionOwnerId,
  validateBeginGrantTransitionResult,
  type BeginGrantTransitionInput,
  type GrantTransitionLease,
} from '../../src/storage';
import { DIGEST_A, DIGEST_B, storedAccessToken, storedGrant } from './fixtures';

function lease(overrides: Partial<GrantTransitionLease> = {}): GrantTransitionLease {
  const base: GrantTransitionLease = {
    id: transitionLeaseId('lease-1'),
    grant: { userId: 'user-1', grantId: 'grant-1' },
    kind: 'refresh_token',
    credentialId: DIGEST_A,
    ownerId: transitionOwnerId('owner-1'),
    fence: 3,
    expectedRevision: 2,
    expiresAt: 130,
    callbackIdempotencyKey: callbackIdempotencyKey('c'.repeat(64)),
  };
  return { ...base, ...overrides };
}

async function beginInput(
  overrides: Partial<Parameters<typeof beginGrantTransitionInput>[0]> = {}
): Promise<BeginGrantTransitionInput> {
  return beginGrantTransitionInput({
    namespace: 'default',
    grant: { userId: 'user-1', grantId: 'grant-1' },
    kind: 'refresh_token',
    credentialId: DIGEST_A,
    ownerId: transitionOwnerId('owner-1'),
    leaseTtlSeconds: 60,
    now: 100,
    ...overrides,
  });
}

describe('OAuth grant transition leases', () => {
  it('creates a frozen bounded lease with a monotonic fence', () => {
    const value = createGrantTransitionLease(lease(), 100, 60);

    expect(value.fence).toBe(3);
    expect(value.expiresAt).toBe(130);
    expect(Object.isFrozen(value)).toBe(true);
    expect(Object.isFrozen(value.grant)).toBe(true);
  });

  it.each([
    ['zero fence', { fence: 0 }],
    ['negative revision', { expectedRevision: -1 }],
    ['expired', { expiresAt: 100 }],
    ['too long', { expiresAt: 161 }],
    ['empty user', { grant: { userId: '', grantId: 'grant-1' } }],
    ['empty grant', { grant: { userId: 'user-1', grantId: '' } }],
    ['invalid kind', { kind: 'device_code' as never }],
    ['raw credential', { credentialId: 'raw-token' as never }],
    ['raw callback key', { callbackIdempotencyKey: 'not-a-digest' as never }],
  ])('rejects %s', (_name, overrides) => {
    expect(() => createGrantTransitionLease(lease(overrides), 100, 60)).toThrow(TypeError);
  });

  it('rejects invalid clock and maximum TTL inputs', () => {
    expect(() => createGrantTransitionLease(lease(), -1, 60)).toThrow(TypeError);
    expect(() => createGrantTransitionLease(lease(), 100, 0)).toThrow(TypeError);
  });

  it.each([
    ['lease', transitionLeaseId],
    ['owner', transitionOwnerId],
  ] as const)('brands bounded non-empty %s identifiers', (_name, factory) => {
    expect(factory('opaque')).toBe('opaque');
    expect(() => factory('')).toThrow(TypeError);
    expect(() => factory(' leading')).toThrow(TypeError);
    expect(() => factory('a'.repeat(129))).toThrow(TypeError);
  });

  it('requires callback keys to be SHA-256 digests', () => {
    expect(callbackIdempotencyKey('c'.repeat(64))).toHaveLength(64);
    expect(() => callbackIdempotencyKey('opaque')).toThrow(TypeError);
  });
});

describe('OAuth grant transition plans', () => {
  it('derives the same callback key across lease owners and reacquisition', async () => {
    const first = await beginInput({ ownerId: transitionOwnerId('owner-1') });
    const second = await beginInput({ ownerId: transitionOwnerId('owner-2') });

    expect(first.callbackIdempotencyKey).toBe(second.callbackIdempotencyKey);
    expect(first.callbackIdempotencyKey).toHaveLength(64);
  });

  it('binds callback keys to namespace, grant, kind, and credential digest', async () => {
    const base = await deriveCallbackIdempotencyKey({
      namespace: 'default',
      grant: { userId: 'user-1', grantId: 'grant-1' },
      kind: 'refresh_token',
      credentialId: DIGEST_A,
    });
    const variants = await Promise.all([
      deriveCallbackIdempotencyKey({
        namespace: 'other',
        grant: { userId: 'user-1', grantId: 'grant-1' },
        kind: 'refresh_token',
        credentialId: DIGEST_A,
      }),
      deriveCallbackIdempotencyKey({
        namespace: 'default',
        grant: { userId: 'user-1', grantId: 'grant-2' },
        kind: 'refresh_token',
        credentialId: DIGEST_A,
      }),
      deriveCallbackIdempotencyKey({
        namespace: 'default',
        grant: { userId: 'user-1', grantId: 'grant-1' },
        kind: 'authorization_code',
        credentialId: DIGEST_A,
      }),
      deriveCallbackIdempotencyKey({
        namespace: 'default',
        grant: { userId: 'user-1', grantId: 'grant-1' },
        kind: 'refresh_token',
        credentialId: DIGEST_B,
      }),
    ]);

    expect(new Set([base, ...variants]).size).toBe(5);
  });

  it('validates an acquired adapter lease against its begin input', async () => {
    const input = await beginInput();
    const acquired = validateBeginGrantTransitionResult(
      input,
      {
        status: 'acquired',
        grant: storedGrant(2),
        lease: lease({
          callbackIdempotencyKey: input.callbackIdempotencyKey,
          credentialId: input.credentialId,
          ownerId: input.ownerId,
        }),
      },
      60
    );

    expect(acquired.status).toBe('acquired');
    expect(() =>
      validateBeginGrantTransitionResult(
        input,
        {
          status: 'acquired',
          grant: storedGrant(2),
          lease: lease({ callbackIdempotencyKey: callbackIdempotencyKey('d'.repeat(64)) }),
        },
        60
      )
    ).toThrow(TypeError);
  });

  it('accepts only an immediate successor grant and matching access token', () => {
    const input = commitGrantTransitionInput({
      lease: lease(),
      now: 110,
      grant: storedGrant(3),
      accessToken: storedAccessToken(0),
    });

    expect(input.grant.metadata.revision).toBe(3);
    expect(Object.isFrozen(input)).toBe(true);
  });

  it.each([
    ['same revision', () => storedGrant(2), () => storedAccessToken(0)],
    ['skipped revision', () => storedGrant(4), () => storedAccessToken(0)],
    ['different grant ID', () => storedGrant(3, { id: 'grant-2' }), () => storedAccessToken(0)],
    ['different token grant', () => storedGrant(3), () => storedAccessToken(0, { grantId: 'grant-2' })],
    ['different user', () => storedGrant(3), () => storedAccessToken(0, { userId: 'user-2' })],
    ['non-initial token revision', () => storedGrant(3), () => storedAccessToken(1)],
  ])('rejects a commit with %s', (_name, nextGrant, token) => {
    expect(() =>
      commitGrantTransitionInput({
        lease: lease(),
        now: 110,
        grant: nextGrant(),
        accessToken: token(),
      })
    ).toThrow(TypeError);
  });

  it('rejects a commit at or after lease expiry', () => {
    expect(() =>
      commitGrantTransitionInput({
        lease: lease(),
        now: 130,
        grant: storedGrant(3),
        accessToken: storedAccessToken(0),
      })
    ).toThrow(TypeError);
  });
});
