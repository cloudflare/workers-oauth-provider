/**
 * JWKS provider — fetches IdP signing keys with caching and a force-refresh
 * cool-down to defend against attackers that spam random `kid` values to
 * amplify load on the IdP's JWKS endpoint.
 *
 * The default implementation is a closure over an in-memory `Map`. Deployers
 * who need a stronger cache (e.g. shared across isolates) can supply a
 * custom `EmaJwksProvider` via `EmaOptions.jwksProvider`.
 */

import {
  EMA_DEFAULT_JWKS_CACHE_TTL_SECONDS,
  EMA_JWKS_FETCH_TIMEOUT_MS,
  EMA_JWKS_FORCE_REFRESH_COOLDOWN_SECONDS,
  EMA_JWKS_MAX_SIZE_BYTES,
} from './constants';
import type { EmaJwksFetchResult, EmaJwksProvider, EmaTrustedIssuer, JsonWebKeySet, OAuthJsonWebKey } from './types';

interface JwksCacheEntry {
  jwks: JsonWebKeySet;
  expiresAt: number;
  /** Earliest time at which a force-refresh against the IdP is permitted. */
  nextForceRefreshAllowedAt: number;
}

interface DefaultJwksProviderOptions {
  /** Cache TTL in seconds; defaults to `EMA_DEFAULT_JWKS_CACHE_TTL_SECONDS`. */
  cacheTtlSeconds?: number;
  /** Optional override of the fetch implementation (mainly for tests). */
  fetchImpl?: typeof fetch;
}

/**
 * Create the default JWKS provider — a closure with its own private cache.
 */
export function createDefaultJwksProvider(opts: DefaultJwksProviderOptions = {}): EmaJwksProvider {
  const cache = new Map<string, JwksCacheEntry>();
  const cacheTtl = opts.cacheTtlSeconds ?? EMA_DEFAULT_JWKS_CACHE_TTL_SECONDS;
  const httpFetch = opts.fetchImpl ?? fetch;

  return {
    async fetch(issuer, { forceRefresh, now }) {
      const cached = cache.get(issuer.issuer);

      if (!forceRefresh && cached && cached.expiresAt > now) {
        return { ok: true, jwks: cached.jwks };
      }

      // Anti-DoS: serve the cached JWKS rather than spam the IdP when a
      // force-refresh is requested too soon after the previous one.
      if (forceRefresh && cached && cached.nextForceRefreshAllowedAt > now) {
        return { ok: true, jwks: cached.jwks };
      }

      const abortController = new AbortController();
      const timeoutId = setTimeout(() => abortController.abort(), EMA_JWKS_FETCH_TIMEOUT_MS);

      try {
        const response = await httpFetch(issuer.jwksUri, {
          headers: { Accept: 'application/json' },
          signal: abortController.signal,
          cf: { cacheEverything: true },
        } as RequestInit);

        if (!response.ok) {
          return { ok: false, reason: 'fetch_failed', status: response.status };
        }

        const contentLength = response.headers.get('content-length');
        if (contentLength && parseInt(contentLength, 10) > EMA_JWKS_MAX_SIZE_BYTES) {
          return { ok: false, reason: 'fetch_failed', status: response.status };
        }

        const rawJwks = await readJsonWithSizeLimit(response, EMA_JWKS_MAX_SIZE_BYTES);
        if (!rawJwks.ok) return rawJwks;
        if (!Array.isArray(rawJwks.value.keys)) {
          return { ok: false, reason: 'fetch_failed' };
        }

        const jwks: JsonWebKeySet = { keys: rawJwks.value.keys as OAuthJsonWebKey[] };
        cache.set(issuer.issuer, {
          jwks,
          expiresAt: now + cacheTtl,
          nextForceRefreshAllowedAt: now + EMA_JWKS_FORCE_REFRESH_COOLDOWN_SECONDS,
        });
        return { ok: true, jwks };
      } catch {
        return { ok: false, reason: 'fetch_failed' };
      } finally {
        clearTimeout(timeoutId);
      }
    },
  };
}

/**
 * Streaming JSON reader that rejects responses exceeding `maxBytes`.
 * Bounds memory consumption before we attempt to JSON-parse the body.
 */
async function readJsonWithSizeLimit(
  response: Response,
  maxBytes: number
): Promise<EmaJwksReadResult> {
  if (!response.body) return { ok: false, reason: 'fetch_failed' };

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        reader.cancel();
        return { ok: false, reason: 'fetch_failed' };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const parsed = JSON.parse(new TextDecoder().decode(merged));
    if (typeof parsed !== 'object' || parsed === null) {
      return { ok: false, reason: 'fetch_failed' };
    }
    return { ok: true, value: parsed as { keys?: unknown } };
  } catch {
    return { ok: false, reason: 'fetch_failed' };
  }
}

type EmaJwksReadResult =
  | { ok: true; value: { keys?: unknown } }
  | { ok: false; reason: 'fetch_failed' };

// Re-export the wire-level Result type so callers don't have to dig.
export type { EmaJwksFetchResult, EmaJwksProvider } from './types';

/**
 * Translate an `EmaJwksProvider` adapter result into the in-band Result type
 * used by the EMA pipeline. Local helper for `OAuthProviderImpl.fetchJwks`.
 */
export function jwksFetchResultToResult(
  result: EmaJwksFetchResult
): import('./result').Result<JsonWebKeySet, import('./result').EmaValidationError> {
  if (result.ok) {
    return { ok: true, value: result.jwks };
  }
  if (result.reason === 'force_refresh_throttled') {
    // Shouldn't reach the pipeline; treat as cache-hit upstream. If it does,
    // surface as a fetch failure rather than crash.
    return { ok: false, error: { reason: 'jwks_fetch_failed' } };
  }
  return { ok: false, error: { reason: 'jwks_fetch_failed', status: result.status } };
}
