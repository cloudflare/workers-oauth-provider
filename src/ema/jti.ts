/**
 * Default `EmaJtiStore`: KV-backed `jti` replay marker.
 *
 * KV is eventually-consistent and does not provide compare-and-set, so two
 * concurrent requests with the same `jti` can both observe "not seen" and
 * succeed — the trade-off accepted here. Surrounding claim checks
 * (signature, `exp`, `nbf`, `aud`, `resource`, client binding) constrain
 * the practical attack window.
 */

import { err, ok } from './result';
import type { EmaJtiStore } from './types';
import { sha256Hex } from './util';

/** Storage key prefix for replay markers. Stable across versions. */
const EMA_JTI_KV_PREFIX = 'enterprise-jti:';

/** Create the default KV-backed JTI store. KV TTL handles cleanup. */
export function createKvJtiStore(): EmaJtiStore {
  return {
    async markUsed({ issuer, jti, exp, now, env }) {
      const ttl = Math.max(1, exp - now);
      const jtiHash = await sha256Hex(`${issuer}\n${jti}`);
      const key = `${EMA_JTI_KV_PREFIX}${jtiHash}`;
      const existing = await env.OAUTH_KV.get(key);
      if (existing) {
        return err({ reason: 'replayed', jti });
      }
      await env.OAUTH_KV.put(key, '1', { expirationTtl: ttl });
      return ok(undefined);
    },
  };
}
