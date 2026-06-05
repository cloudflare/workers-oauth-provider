/**
 * KV storage provider — the default backend.
 *
 * This is a thin pass-through to `env.OAUTH_KV`. It exists so the provider can
 * talk to a single `OAuthStorage` interface; using it must be byte-for-byte
 * equivalent to calling `env.OAUTH_KV` directly.
 */

import type { OAuthStorage, StorageListOptions, StorageListResult, StoragePutOptions } from './types';

export class KvStorage implements OAuthStorage {
  readonly #kv: KVNamespace;

  constructor(kv: KVNamespace) {
    this.#kv = kv;
  }

  get(key: string): Promise<string | null>;
  get(key: string, options: { type: 'json' }): Promise<any | null>;
  get(key: string, options?: { type: 'json' }): Promise<any> {
    return options?.type === 'json' ? this.#kv.get(key, { type: 'json' }) : this.#kv.get(key);
  }

  put(key: string, value: string, options?: StoragePutOptions): Promise<void> {
    return this.#kv.put(key, value, options);
  }

  delete(key: string): Promise<void> {
    return this.#kv.delete(key);
  }

  async list(options: StorageListOptions): Promise<StorageListResult> {
    const result = await this.#kv.list(options);
    return {
      keys: result.keys.map((k) => ({ name: k.name })),
      list_complete: result.list_complete,
      cursor: 'cursor' in result ? (result as { cursor?: string }).cursor : undefined,
    };
  }
}
