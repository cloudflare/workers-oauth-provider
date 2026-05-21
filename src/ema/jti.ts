/**
 * JTI replay-protection store.
 *
 * Uses the provider's `OAUTH_KV` binding. KV is eventually-consistent and
 * does not provide compare-and-set, so two concurrent requests with the
 * same `jti` can both observe "not seen" and succeed — the trade-off
 * accepted for the default. Other claim checks (signature, `exp`, `nbf`,
 * `aud`, `resource`, client binding) constrain the practical attack window.
 */

import { sha256Hex } from './util';
import type { EmaJtiMarkResult, EmaJtiStore } from './types';

/** Storage key prefix for replay markers. Stable across versions. */
const EMA_JTI_KV_PREFIX = 'enterprise-jti:';

/**
 * Create the default KV-backed JTI store. KV TTL handles cleanup.
 */
export function createKvJtiStore(): EmaJtiStore {
  return {
    async markUsed({ issuer, jti, exp, now, env }) {
      const ttl = Math.max(1, exp - now);
      const jtiHash = await sha256Hex(`${issuer}\n${jti}`);
      const key = `${EMA_JTI_KV_PREFIX}${jtiHash}`;
      const existing = await env.OAUTH_KV.get(key);
      if (existing) {
        return { ok: false, reason: 'replayed' };
      }
      await env.OAUTH_KV.put(key, '1', { expirationTtl: ttl });
      return { ok: true };
    },
  };
}

/**
 * Translate an `EmaJtiStore.markUsed` result into the in-band Result type
 * used by the EMA pipeline.
 */
export function jtiMarkResultToResult(
  result: EmaJtiMarkResult,
  jti: string
): import('./result').Result<void, import('./result').EmaValidationError> {
  if (result.ok) return { ok: true, value: undefined };
  return { ok: false, error: { reason: 'replayed', jti } };
}
