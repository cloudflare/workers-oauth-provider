/**
 * Storage resolution.
 *
 * Resolves the `storage` option into an {@link OAuthStorage} for a request.
 * Defaults to Workers KV (`env.OAUTH_KV`), behaviour-identical to before.
 */

import { KvStorage } from './kv';
import type { OAuthStorage, StorageProvider } from './types';

export { KvStorage } from './kv';
export type {
  OAuthStorage,
  StorageProvider,
  StorageListKey,
  StorageListOptions,
  StorageListResult,
  StoragePutOptions,
} from './types';

/** Hardcoded default KV binding name. */
const KV_BINDING = 'OAUTH_KV';

/** Per-`env` memoization for the default KV wrapper. */
const defaultKvCache = new WeakMap<object, OAuthStorage>();

/** Per-factory, per-`env` memoization for custom storage providers. */
const providerCache = new WeakMap<StorageProvider, WeakMap<object, OAuthStorage>>();

function envKey(env: any): object {
  if (env && (typeof env === 'object' || typeof env === 'function')) return env;
  throw new TypeError(`OAuth storage resolution requires a Worker env object.`);
}

/**
 * Resolve {@link OAuthStorage} for this request.
 *
 * - `storage` factory → called with `env`, result memoized by factory+env.
 * - No `storage` option → default KV provider over `env.OAUTH_KV`.
 */
export function resolveStorage(storage: StorageProvider | undefined, env: any): OAuthStorage {
  const key = envKey(env);

  if (storage) {
    let byEnv = providerCache.get(storage);
    if (!byEnv) {
      byEnv = new WeakMap<object, OAuthStorage>();
      providerCache.set(storage, byEnv);
    }

    const cached = byEnv.get(key);
    if (cached) return cached;

    const resolved = storage(env);
    byEnv.set(key, resolved);
    return resolved;
  }

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
