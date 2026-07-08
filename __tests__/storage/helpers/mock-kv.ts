export interface MockKvPutOptions {
  readonly expirationTtl?: number;
  readonly expiration?: number;
}

export interface MockKvWrite {
  readonly key: string;
  readonly value: string;
  readonly options?: MockKvPutOptions;
}

interface MockKvEntry {
  readonly value: string;
  readonly expiresAt?: number;
}

/** Deterministic Workers KV test double with TTLs, pagination, and fault injection. */
export class MockKvNamespace {
  readonly writes: MockKvWrite[] = [];
  readonly deletes: string[] = [];
  readonly entries = new Map<string, MockKvEntry>();
  now = 100;
  pageSizeCap = 1000;
  failNextPut: Error | undefined;
  failPutAt: { readonly attempt: number; readonly error: Error } | undefined;
  putAttempts = 0;
  failNextDelete: Error | undefined;

  asNamespace(): KVNamespace {
    return this as unknown as KVNamespace;
  }

  async get(key: string, options?: { readonly type?: string }): Promise<unknown> {
    const entry = this.live(key);
    if (entry === undefined) return null;
    return options?.type === 'json' ? JSON.parse(entry.value) : entry.value;
  }

  async put(key: string, value: string | ArrayBuffer, options?: MockKvPutOptions): Promise<void> {
    this.putAttempts++;
    if (this.failPutAt?.attempt === this.putAttempts) {
      throw this.failPutAt.error;
    }
    if (this.failNextPut !== undefined) {
      const error = this.failNextPut;
      this.failNextPut = undefined;
      throw error;
    }
    if (typeof value !== 'string') throw new TypeError('Mock KV accepts string values only');
    if (options?.expirationTtl !== undefined && options.expirationTtl < 60) {
      throw new Error(`KV PUT failed: 400 Invalid expiration_ttl of ${options.expirationTtl}`);
    }
    if (options?.expiration !== undefined && options.expiration < this.now + 60) {
      throw new Error(`KV PUT failed: 400 Invalid expiration of ${options.expiration}`);
    }
    const expiresAt =
      options?.expiration ?? (options?.expirationTtl === undefined ? undefined : this.now + options.expirationTtl);
    this.entries.set(key, { value, ...(expiresAt === undefined ? {} : { expiresAt }) });
    this.writes.push({ key, value, ...(options === undefined ? {} : { options: { ...options } }) });
  }

  async delete(key: string): Promise<void> {
    if (this.failNextDelete !== undefined) {
      const error = this.failNextDelete;
      this.failNextDelete = undefined;
      throw error;
    }
    this.entries.delete(key);
    this.deletes.push(key);
  }

  async list(options: { readonly prefix?: string; readonly limit?: number; readonly cursor?: string }): Promise<{
    readonly keys: readonly { readonly name: string }[];
    readonly list_complete: boolean;
    readonly cursor?: string;
  }> {
    const prefix = options.prefix ?? '';
    const keys = [...this.entries.keys()]
      .filter((key) => key.startsWith(prefix) && this.live(key) !== undefined)
      .sort();
    const start = options.cursor === undefined ? 0 : Number.parseInt(options.cursor, 10);
    const limit = Math.min(options.limit ?? 1000, this.pageSizeCap);
    const page = keys.slice(start, start + limit);
    const next = start + page.length;
    const complete = next >= keys.length;
    return {
      keys: page.map((name) => ({ name })),
      list_complete: complete,
      ...(complete ? {} : { cursor: String(next) }),
    };
  }

  seed(key: string, value: unknown, expiresAt?: number): void {
    this.entries.set(key, {
      value: typeof value === 'string' ? value : JSON.stringify(value),
      ...(expiresAt === undefined ? {} : { expiresAt }),
    });
  }

  private live(key: string): MockKvEntry | undefined {
    const entry = this.entries.get(key);
    if (entry?.expiresAt !== undefined && entry.expiresAt <= this.now) {
      this.entries.delete(key);
      return undefined;
    }
    return entry;
  }
}
