/**
 * Storage provider factory.
 *
 * Resolves the configured backend from `OAuthProviderOptions.storage` and the
 * request `env`. The DO namespace binding is hardcoded as
 * `env.OAUTH_DURABLE_OBJECT`; the KV namespace/index is `env.OAUTH_KV`.
 */

import { DurableObjectStorage, OAuthStore } from './durable-object';
import { KvStorage } from './kv';
import type { OAuthStorage, StorageConfig } from './types';

export { OAuthStore } from './durable-object';
export { KvStorage } from './kv';
export { DurableObjectStorage } from './durable-object';
export type {
  OAuthStorage,
  StorageConfig,
  DurableObjectPartition,
  StorageListOptions,
  StorageListResult,
  StoragePutOptions,
} from './types';

/** Hardcoded binding names (see docs/storage-providers.md). */
const KV_BINDING = 'OAUTH_KV';
const DO_BINDING = 'OAUTH_DURABLE_OBJECT';

/**
 * Build an {@link OAuthStorage} for this request from config + env.
 *
 * Defaults to KV (behaviour-identical to today). When `durable_object` is
 * selected, requires `env.OAUTH_DURABLE_OBJECT` (the `OAuthStore` namespace)
 * and `env.OAUTH_KV` (used as the cross-partition index).
 */
export function resolveStorage(config: StorageConfig | undefined, env: any): OAuthStorage {
  const kv = env?.[KV_BINDING] as KVNamespace | undefined;

  if (!config || config.type === 'kv') {
    if (!kv) {
      throw new TypeError(`OAuth storage requires the '${KV_BINDING}' KV namespace binding.`);
    }
    return new KvStorage(kv);
  }

  if (config.type === 'durable_object') {
    const ns = env?.[DO_BINDING];
    if (!ns) {
      throw new TypeError(
        `storage.type 'durable_object' requires the '${DO_BINDING}' Durable Object ` +
          `binding (class ${OAuthStore.name}). Add it to wrangler.jsonc with a ` +
          `new_sqlite_classes migration and re-export { OAuthStore } from your Worker.`
      );
    }
    if (!kv) {
      throw new TypeError(
        `storage.type 'durable_object' also requires the '${KV_BINDING}' KV ` +
          `namespace binding, used as the cross-partition index.`
      );
    }
    return new DurableObjectStorage(kv, ns, config.partition ?? 'user');
  }

  throw new TypeError(`Unknown storage.type: ${(config as { type: string }).type}`);
}
