import { describe, expect, it } from 'vitest';
import { MAX_USER_ID_BYTES, fitsKvKey, isValidUserId, parseCredentialIds } from '../src/oauth-storage-keys';

const GRANT_ID = 'g'.repeat(16);
const SECRET = 's'.repeat(32);
const TOKEN_ID = '0'.repeat(64);

describe('user IDs', () => {
  it('are bounded by the longest key that holds one, an access token key', () => {
    expect(MAX_USER_ID_BYTES).toBe(424);
    expect(fitsKvKey(`token:${'u'.repeat(MAX_USER_ID_BYTES)}:${GRANT_ID}:${TOKEN_ID}`)).toBe(true);
    expect(fitsKvKey(`token:${'u'.repeat(MAX_USER_ID_BYTES + 1)}:${GRANT_ID}:${TOKEN_ID}`)).toBe(false);
  });

  it('are measured in UTF-8 bytes, not characters', () => {
    expect(isValidUserId('\u00e9'.repeat(212))).toBe(true); // 424 bytes
    expect(isValidUserId('\u00e9'.repeat(213))).toBe(false); // 426 bytes
  });

  it.each([
    ['empty', ''],
    ['containing ":"', 'tenant:user'],
    ['not a string', 42],
  ])('are refused when %s', (_label, userId) => {
    expect(isValidUserId(userId)).toBe(false);
  });
});

describe('parseCredentialIds', () => {
  it('reads the user and grant IDs of a credential this provider could have issued', () => {
    expect(parseCredentialIds(`user-1:${GRANT_ID}:${SECRET}`)).toEqual({ userId: 'user-1', grantId: GRANT_ID });
    // Grants issued before 1.2 could have an empty user ID; the lookup decides whether one exists.
    expect(parseCredentialIds(`:${GRANT_ID}:${SECRET}`)).toEqual({ userId: '', grantId: GRANT_ID });
  });

  it.each([
    ['two parts', `user:${SECRET}`],
    ['four parts, as a legacy user ID containing ":" gives', `tenant:user:${GRANT_ID}:${SECRET}`],
    ['a user ID too long for its access token key', `${'u'.repeat(425)}:${GRANT_ID}:${SECRET}`],
    ['a grant ID of another length', `user:grant:${SECRET}`],
    ['a grant ID outside the generated alphabet', `user:${'g'.repeat(15)}.:${SECRET}`],
  ])('returns null for %s', (_label, credential) => {
    expect(parseCredentialIds(credential)).toBeNull();
  });
});
