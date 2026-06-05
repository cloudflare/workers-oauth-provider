/**
 * Storage provider factory.
 *
 * Resolves the configured backend from `OAuthProviderOptions.storage` and the
 * request `env`. The KV namespace/index binding is `env.OAUTH_KV`.
 */

import { HyperdriveStorage } from './hyperdrive';
import { KvStorage } from './kv';
import type { OAuthStorage, StorageConfig } from './types';

export { KvStorage } from './kv';
export { HyperdriveStorage } from './hyperdrive';
export type {
  OAuthStorage,
  StorageConfig,
  SqlClient,
  SqlQueryResult,
  HyperdriveLike,
  StorageListOptions,
  StorageListResult,
  StoragePutOptions,
} from './types';

/** Hardcoded KV binding name. */
const KV_BINDING = 'OAUTH_KV';

/**
 * Build an {@link OAuthStorage} for this request from config + env.
 *
 * Defaults to KV (behaviour-identical to today). When `hyperdrive` is selected,
 * uses the provided Hyperdrive binding (or injected `client`) to talk to
 * Postgres.
 */
export function resolveStorage(config: StorageConfig | undefined, env: any): OAuthStorage {
  if (!config || config.type === 'kv') {
    const kv = env?.[KV_BINDING] as KVNamespace | undefined;
    if (!kv) {
      throw new TypeError(`OAuth storage requires the '${KV_BINDING}' KV namespace binding.`);
    }
    return new KvStorage(kv);
  }

  if (config.type === 'hyperdrive') {
    return new HyperdriveStorage({
      hyperdrive: config.hyperdrive,
      client: config.client,
      tableName: config.tableName,
    });
  }

  throw new TypeError(`Unknown storage.type: ${(config as { type: string }).type}`);
}
