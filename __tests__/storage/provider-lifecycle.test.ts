import { describe, expect, it } from 'vitest';
import { OAuthProvider, type OAuthHelpers } from '../../src/oauth-provider';
import { workersKvStorage } from '../../src/storage/kv';
import type { OAuthStorageConnection, OAuthStorageOpenContext, OAuthStorageProvider } from '../../src/storage';
import { MockKvNamespace } from './helpers/mock-kv';

interface TestEnv {
  readonly OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER?: OAuthHelpers | null;
}

function countingStorage(delegate: OAuthStorageProvider<TestEnv>): {
  readonly provider: OAuthStorageProvider<TestEnv>;
  readonly counts: { opens: number; closes: number };
} {
  const counts = { opens: 0, closes: 0 };
  return {
    counts,
    provider: {
      ...delegate,
      async open(context: OAuthStorageOpenContext<TestEnv>): Promise<OAuthStorageConnection> {
        counts.opens++;
        const connection = await delegate.open(context);
        return {
          ...connection,
          async close(): Promise<void> {
            counts.closes++;
            await connection.close();
          },
        };
      },
    },
  };
}

function executionContext(): ExecutionContext {
  return {
    props: {},
    exports: {},
    waitUntil() {},
    passThroughOnException() {},
  } as ExecutionContext;
}

function options(storage: OAuthStorageProvider<TestEnv>) {
  return {
    apiRoute: '/api/',
    apiHandler: { fetch: async () => new Response('api') },
    defaultHandler: {
      async fetch(_request: Request, env: TestEnv): Promise<Response> {
        await env.OAUTH_PROVIDER?.listClients();
        return new Response('default');
      },
    },
    authorizeEndpoint: '/authorize',
    tokenEndpoint: '/oauth/token',
    storage,
  };
}

describe('OAuth provider storage lifecycle', () => {
  it('opens and closes one connection for a request and reuses it for bound helpers', async () => {
    const kv = new MockKvNamespace();
    const delegate = workersKvStorage<TestEnv>({ binding: (env) => env.OAUTH_KV, now: () => kv.now });
    const { provider: storage, counts } = countingStorage(delegate);
    const provider = new OAuthProvider(options(storage));
    const env: TestEnv = { OAUTH_KV: kv.asNamespace(), OAUTH_PROVIDER: null };

    const response = await provider.fetch(new Request('https://example.com/'), env, executionContext());

    expect(await response.text()).toBe('default');
    expect(counts).toEqual({ opens: 1, closes: 1 });
    expect(env.OAUTH_PROVIDER).not.toBeNull();
  });

  it('opens and closes a fresh connection around detached helper operations', async () => {
    const kv = new MockKvNamespace();
    const delegate = workersKvStorage<TestEnv>({ binding: (env) => env.OAUTH_KV, now: () => kv.now });
    const { provider: storage, counts } = countingStorage(delegate);
    const provider = new OAuthProvider(options(storage));
    const env: TestEnv = { OAUTH_KV: kv.asNamespace(), OAUTH_PROVIDER: null };

    await provider.fetch(new Request('https://example.com/'), env, executionContext());
    await env.OAUTH_PROVIDER?.listClients();
    await env.OAUTH_PROVIDER?.listClients();

    expect(counts).toEqual({ opens: 3, closes: 3 });
  });

  it('reports KV as compatibility storage and rejects it in strict mode', () => {
    const kv = new MockKvNamespace();
    const storage = workersKvStorage<TestEnv>({ binding: (env) => env.OAUTH_KV, now: () => kv.now });
    const provider = new OAuthProvider(options(storage));

    expect(provider.getStorageCompatibility().overall).toBe('compatibility');
    expect(provider.getStorageCompatibility().features['authorization-code'].status).toBe('compatibility');
    expect(() => new OAuthProvider({ ...options(storage), storageGuarantees: 'strict' })).toThrow(
      /cannot support enabled features/
    );
  });
});
