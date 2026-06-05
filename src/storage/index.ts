/**
 * Storage resolution.
 *
 * Resolves the `storage` option into an {@link OAuthStorage} for a request.
 * Defaults to Workers KV (`env.OAUTH_KV`), behaviour-identical to before.
 */

import { KvStorage } from './kv';
import type { OAuthStorage } from './types';

export { KvStorage } from './kv';
export type {
  OAuthStorage,
  StorageListKey,
  StorageListOptions,
  StorageListResult,
  StoragePutOptions,
} from './types';

/** Hardcoded default KV binding name. */
const KV_BINDING = 'OAUTH_KV';

/** Per-`env` memoization for the default KV wrapper. */
const defaultKvCache = new WeakMap<object, OAuthStorage>();

/**
 * Resolve {@link OAuthStorage} for this request.
 *
 * - `storage` option → use the provided storage instance directly.
 * - No `storage` option → default KV provider over `env.OAUTH_KV`.
 */
export function resolveStorage(storage: OAuthStorage | undefined, env: any): OAuthStorage {
  if (storage) return storage;

  const key = (env ?? {}) as object;
  const cached = defaultKvCache.get(key);
  if (cached) return cached;

  const kv = env?.[KV_BINDING] as KVNamespace | undefined;
  if (!kv) {
    throw new TypeError(
      `OAuth storage requires the '${KV_BINDING}' KV namespace binding, ` +
        `or pass a 'storage' provider in the OAuthProvider options.`
    );
  }

  const resolved = new KvStorage(kv);
  defaultKvCache.set(key, resolved);
  return resolved;
}
