/**
 * Default `EmaJtiStore`: KV-backed `jti` replay marker.
 *
 * KV is eventually-consistent and does not provide compare-and-set, so two
 * concurrent requests with the same `jti` can both observe "not seen" and
 * succeed — the trade-off accepted here. Surrounding claim checks
 * (signature, `exp`, `nbf`, `aud`, `resource`, client binding) constrain
 * the practical attack window.
 */

import { EMA_JTI_MIN_TTL_SECONDS } from './constants';
import { err, ok } from './result';
import type { EmaJtiStore } from './types';
import { sha256Hex } from './util';

/** Storage key prefix for replay markers. Stable across versions. */
const EMA_JTI_KV_PREFIX = 'enterprise-jti:';

/**
 * Create the default KV-backed JTI store. KV TTL handles cleanup.
 *
 * @param keyPrefix Storage key prefix, so each kind of assertion keeps its own replay namespace.
 */
export function createKvJtiStore(keyPrefix: string = EMA_JTI_KV_PREFIX): EmaJtiStore {
  return {
    async markUsed({ issuer, jti, exp, now, env }) {
      // KV rejects a sub-60s expirationTtl and an assertion in its last minute is
      // still valid; a marker outliving its assertion only tightens replay detection.
      const ttl = Math.max(EMA_JTI_MIN_TTL_SECONDS, exp - now);
      const jtiHash = await sha256Hex(`${issuer}\n${jti}`);
      const key = `${keyPrefix}${jtiHash}`;
      const existing = await env.OAUTH_KV.get(key);
      if (existing) {
        return err({ reason: 'replayed', jti });
      }
      await env.OAUTH_KV.put(key, '1', { expirationTtl: ttl });
      return ok(undefined);
    },
  };
}
