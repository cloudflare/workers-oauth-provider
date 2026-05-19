/**
 * JWK selection and ID-JAG signature verification.
 *
 * `selectJwk` is a pure picker; `verifyIdJagSignature` is the I/O-bearing
 * WebCrypto call. Both operate over the already-fetched JWKS — the actual
 * fetching lives behind `EmaJwksProvider`.
 */

import { getJwtCryptoAlgorithms } from '../oauth-provider';
import { type EmaSupportedAlg } from './constants';
import { err, ok, type EmaValidationError, type Result } from './result';
import type { JsonWebKeySet, OAuthJsonWebKey } from './types';

/**
 * Pick a signing key from a JWKS that matches the assertion header.
 *
 * Filters by:
 *   - `kid` (if the assertion header carries one)
 *   - JWK `use === 'sig'` (when present)
 *   - JWK `key_ops` containing `verify` (when present)
 *   - JWK `alg` matching (when present)
 *   - `kty` compatible with the requested `alg`
 *
 * If the assertion has a `kid`, the first matching key wins. Without a `kid`,
 * we only return a key if exactly one candidate matches — otherwise the
 * selection is ambiguous and we reject (caller may then force-refresh JWKS).
 */
export function selectJwk(
  jwks: JsonWebKeySet,
  alg: EmaSupportedAlg,
  kid: string | undefined
): Result<OAuthJsonWebKey, EmaValidationError> {
  const keys = jwks.keys ?? [];
  const matching = keys.filter((key) => {
    if (kid && key.kid !== kid) return false;
    if (key.alg && key.alg !== alg) return false;
    if (key.use && key.use !== 'sig') return false;
    if (Array.isArray(key.key_ops) && !key.key_ops.includes('verify')) return false;
    if (alg.startsWith('RS') && key.kty !== 'RSA') return false;
    if (alg.startsWith('ES') && key.kty !== 'EC') return false;
    return true;
  });

  if (kid) {
    const picked = matching[0];
    if (!picked) return err({ reason: 'no_matching_key', kid });
    return ok(picked);
  }

  if (matching.length !== 1) {
    return err({ reason: 'no_matching_key' });
  }

  return ok(matching[0]);
}

interface VerifyInput {
  alg: EmaSupportedAlg;
  jwk: OAuthJsonWebKey;
  signingInput: Uint8Array;
  signature: Uint8Array;
}

/**
 * Verify an ID-JAG's compact-JWS signature using WebCrypto.
 *
 * Returns `false` on any WebCrypto-level failure (import or verify).
 * The caller is responsible for mapping `false` to the appropriate
 * `EmaValidationError`.
 */
export async function verifyIdJagSignature(input: VerifyInput): Promise<boolean> {
  try {
    const { importAlgorithm, verifyAlgorithm } = getJwtCryptoAlgorithms(input.alg);
    const key = await crypto.subtle.importKey('jwk', input.jwk, importAlgorithm, false, ['verify']);
    return await crypto.subtle.verify(verifyAlgorithm, key, input.signature, input.signingInput);
  } catch {
    return false;
  }
}
