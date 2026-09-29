/**
 * The identifiers that go into this provider's KV keys, and the bounds that keep every key
 * storable. Cloudflare KV rejects a key over 512 bytes by throwing, not by reporting it missing, so
 * each identifier is bounded where it enters: a user ID when a grant is issued, and a code, token
 * or client ID from a request before anything is looked up. A request value too long for any key
 * names nothing that was ever stored, so it's unknown.
 */

/** Cloudflare KV rejects a key longer than this many UTF-8 bytes, by throwing rather than missing. */
export const MAX_KV_KEY_BYTES = 512;

/** Length of a grant ID. */
export const GRANT_ID_LENGTH = 16;

/** A grant ID as this provider has always generated them: `generateRandomString()`'s alphabet. */
export const ISSUED_GRANT_ID_PATTERN = new RegExp(`^[A-Za-z0-9_-]{${GRANT_ID_LENGTH}}$`);

/** Length of a token ID: a SHA-256 digest in hex. */
const TOKEN_ID_LENGTH = 64;

/**
 * The longest user ID, in UTF-8 bytes. The longest key holding one is an access token's,
 * `token:{userId}:{grantId}:{tokenId}`, which takes 88 bytes besides the user ID.
 */
export const MAX_USER_ID_BYTES =
  MAX_KV_KEY_BYTES - ('token:'.length + ':'.length + GRANT_ID_LENGTH + ':'.length + TOKEN_ID_LENGTH);

/** Whether `value` is at most `maxBytes` long in UTF-8. A UTF-16 code unit is at least one byte. */
function fitsUtf8Bytes(value: string, maxBytes: number): boolean {
  return value.length <= maxBytes && new TextEncoder().encode(value).byteLength <= maxBytes;
}

/** Whether KV can hold `key`. */
export function fitsKvKey(key: string): boolean {
  return fitsUtf8Bytes(key, MAX_KV_KEY_BYTES);
}

/**
 * Whether a grant can be issued to `userId`: non-empty, without `:`, which separates the parts of
 * issued tokens and keys, and at most {@link MAX_USER_ID_BYTES} long, so every key holding it fits.
 */
export function isValidUserId(userId: unknown): userId is string {
  return (
    typeof userId === 'string' && userId.length > 0 && !userId.includes(':') && fitsUtf8Bytes(userId, MAX_USER_ID_BYTES)
  );
}

/** The user and grant an authorization code, refresh token or access token belongs to. */
export interface CredentialIds {
  readonly userId: string;
  readonly grantId: string;
}

/**
 * Reads the user and grant IDs from an authorization code, refresh token or access token
 * (`{userId}:{grantId}:{secret}`), or returns null when no credential this provider issued has its
 * shape: not three parts, a user ID longer than any key can hold, or a grant ID this provider
 * doesn't generate. Every key built from the result fits KV.
 */
export function parseCredentialIds(credential: string): CredentialIds | null {
  const parts = credential.split(':');
  if (parts.length !== 3) return null;
  const [userId, grantId] = parts;
  // Only the length, not isValidUserId(): before 1.2 a grant could be issued to an empty user ID.
  if (!fitsUtf8Bytes(userId, MAX_USER_ID_BYTES) || !ISSUED_GRANT_ID_PATTERN.test(grantId)) return null;
  return { userId, grantId };
}
