import { describe, expect, it } from 'vitest';
import { WorkerEntrypoint } from 'cloudflare:workers';
import { OAuthProvider, type OAuthHelpers } from '../../src/oauth-provider';
import { WORKERS_KV_STORAGE_CAPABILITIES, workersKvStorage } from '../../src/storage/kv';
import {
  defineOAuthStorageCapabilities,
  type OAuthStorageConnection,
  type OAuthStorageOpenContext,
  type OAuthStorageProvider,
} from '../../src/storage';
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

function storageWithCloseError(
  delegate: OAuthStorageProvider<TestEnv>,
  closeError: Error
): OAuthStorageProvider<TestEnv> {
  return {
    ...delegate,
    async open(context) {
      const connection = await delegate.open(context);
      return {
        ...connection,
        async close() {
          await connection.close();
          throw closeError;
        },
      };
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

  it('runs authorization, token exchange, and API access without an OAUTH_KV property', async () => {
    interface StoreEnv {
      readonly STORE: KVNamespace;
      OAUTH_PROVIDER?: OAuthHelpers | null;
    }
    const kv = new MockKvNamespace();
    kv.now = Math.floor(Date.now() / 1000);
    const delegate = workersKvStorage<StoreEnv>({ binding: (env) => env.STORE });
    const tokenExchangeRevisions: number[] = [];
    let simulateTokenExchangeRace = false;
    const storage: OAuthStorageProvider<StoreEnv> = {
      ...delegate,
      async open(context) {
        const connection = await delegate.open(context);
        return {
          ...connection,
          close: () => connection.close(),
          accessTokens: {
            ...connection.accessTokens,
            async createForGrant(input) {
              tokenExchangeRevisions.push(input.expectedGrantRevision);
              if (simulateTokenExchangeRace) return { status: 'grant_conflict' };
              return connection.accessTokens.createForGrant(input);
            },
          },
        };
      },
    };
    const callbackKeys: string[] = [];
    const redirectUri = 'https://client.example/callback';
    const provider = new OAuthProvider<StoreEnv>({
      apiRoute: '/api/',
      apiHandler: { fetch: async () => Response.json({ ok: true }) },
      defaultHandler: {
        async fetch(request, env) {
          const url = new URL(request.url);
          if (url.pathname !== '/authorize') return new Response('default');
          const parsed = await env.OAUTH_PROVIDER!.parseAuthRequest(request);
          const completed = await env.OAUTH_PROVIDER!.completeAuthorization({
            request: parsed,
            userId: 'user-1',
            metadata: {},
            scope: parsed.scope,
            props: { userId: 'user-1' },
          });
          return Response.redirect(completed.redirectTo);
        },
      },
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      storage,
      tokenExchangeCallback(options) {
        callbackKeys.push(options.idempotencyKey ?? '');
      },
    });
    const env: StoreEnv = { STORE: kv.asNamespace(), OAUTH_PROVIDER: null };
    await provider.fetch(new Request('https://example.com/'), env, executionContext());
    const client = await env.OAUTH_PROVIDER!.createClient({
      redirectUris: [redirectUri],
      tokenEndpointAuthMethod: 'none',
    });
    const verifier = 'a'.repeat(64);
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const authorize = await provider.fetch(
      new Request(
        `https://example.com/authorize?response_type=code&client_id=${client.clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}&scope=read` +
          `&code_challenge=${challenge}&code_challenge_method=S256`
      ),
      env,
      executionContext()
    );
    const code = new URL(authorize.headers.get('Location')!).searchParams.get('code')!;
    const token = await provider.fetch(
      new Request('https://example.com/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: client.clientId,
          code,
          code_verifier: verifier,
          redirect_uri: redirectUri,
        }),
      }),
      env,
      executionContext()
    );
    expect(token.status).toBe(200);
    const tokens = (await token.json()) as { access_token: string };
    const api = await provider.fetch(
      new Request('https://example.com/api/data', {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      }),
      env,
      executionContext()
    );
    expect(api.status).toBe(200);
    expect(callbackKeys).toHaveLength(1);
    expect(callbackKeys[0]).toMatch(/^[0-9a-f]{64}$/);

    simulateTokenExchangeRace = true;
    await expect(env.OAUTH_PROVIDER!.exchangeToken({ subjectToken: tokens.access_token })).rejects.toThrow(
      /Grant changed during token issuance/
    );
    expect(tokenExchangeRevisions).toEqual([0]);
    expect('OAUTH_KV' in env).toBe(false);
  });

  it('rejects an ExportedHandler helper captured past its request lifetime', async () => {
    const kv = new MockKvNamespace();
    const delegate = workersKvStorage<TestEnv>({ binding: (env) => env.OAUTH_KV, now: () => kv.now });
    const { provider: storage, counts } = countingStorage(delegate);
    let captured: OAuthHelpers | undefined;
    const provider = new OAuthProvider({
      ...options(storage),
      defaultHandler: {
        async fetch(_request, env) {
          captured = env.OAUTH_PROVIDER ?? undefined;
          return new Response('captured');
        },
      },
    });
    await provider.fetch(
      new Request('https://example.com/'),
      { OAUTH_KV: kv.asNamespace(), OAUTH_PROVIDER: null },
      executionContext()
    );

    await expect(captured!.listClients()).rejects.toMatchObject({
      code: 'unavailable',
      operation: 'helpers.operation',
    });
    expect(counts).toEqual({ opens: 1, closes: 1 });
  });

  it('rejects a bound helper used from waitUntil after the response', async () => {
    const kv = new MockKvNamespace();
    const storage = workersKvStorage<TestEnv>({ binding: (env) => env.OAUTH_KV, now: () => kv.now });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let waited: Promise<unknown> | undefined;
    const context = {
      ...executionContext(),
      waitUntil(promise: Promise<unknown>) {
        waited = promise;
      },
    } as ExecutionContext;
    const provider = new OAuthProvider({
      ...options(storage),
      defaultHandler: {
        async fetch(_request, env, ctx) {
          ctx.waitUntil(gate.then(() => env.OAUTH_PROVIDER!.listClients()));
          return new Response('queued');
        },
      },
    });
    await provider.fetch(
      new Request('https://example.com/'),
      { OAUTH_KV: kv.asNamespace(), OAUTH_PROVIDER: null },
      context
    );

    const assertion = expect(waited!).rejects.toMatchObject({ code: 'unavailable' });
    release();
    await assertion;
  });

  it('rejects a WorkerEntrypoint helper captured past its request lifetime', async () => {
    const kv = new MockKvNamespace();
    const delegate = workersKvStorage<TestEnv>({ binding: (env) => env.OAUTH_KV, now: () => kv.now });
    const { provider: storage, counts } = countingStorage(delegate);
    let captured: OAuthHelpers | undefined;
    class CapturingEntrypoint extends WorkerEntrypoint<TestEnv> {
      async fetch(): Promise<Response> {
        captured = this.env.OAUTH_PROVIDER ?? undefined;
        return new Response('captured');
      }
    }
    const provider = new OAuthProvider({ ...options(storage), defaultHandler: CapturingEntrypoint });
    await provider.fetch(
      new Request('https://example.com/'),
      { OAUTH_KV: kv.asNamespace(), OAUTH_PROVIDER: null },
      executionContext()
    );

    await expect(captured!.listClients()).rejects.toMatchObject({ code: 'unavailable' });
    expect(counts).toEqual({ opens: 1, closes: 1 });
  });

  it('preserves the primary handler error when storage close also fails', async () => {
    const kv = new MockKvNamespace();
    const delegate = workersKvStorage<TestEnv>({ binding: (env) => env.OAUTH_KV, now: () => kv.now });
    const closeError = new Error('close failed');
    const primary = new Error('handler failed');
    const storage = storageWithCloseError(delegate, closeError);
    const provider = new OAuthProvider({
      ...options(storage),
      defaultHandler: {
        async fetch() {
          throw primary;
        },
      },
    });

    await expect(
      provider.fetch(
        new Request('https://example.com/'),
        { OAUTH_KV: kv.asNamespace(), OAUTH_PROVIDER: null },
        executionContext()
      )
    ).rejects.toBe(primary);
    expect((primary as Error & { storageCloseError?: unknown }).storageCloseError).toBe(closeError);
  });

  it('surfaces a close failure after a successful request and detached helper call', async () => {
    const kv = new MockKvNamespace();
    const delegate = workersKvStorage<TestEnv>({ binding: (env) => env.OAUTH_KV, now: () => kv.now });
    const closeError = new Error('close failed');
    const storage = storageWithCloseError(delegate, closeError);
    const provider = new OAuthProvider(options(storage));
    const env: TestEnv = { OAUTH_KV: kv.asNamespace(), OAUTH_PROVIDER: null };

    await expect(provider.fetch(new Request('https://example.com/'), env, executionContext())).rejects.toBe(closeError);
    await expect(env.OAUTH_PROVIDER!.listClients()).rejects.toBe(closeError);
  });

  it('rejects unsupported helper capabilities before adapter operation I/O', async () => {
    const kv = new MockKvNamespace();
    const delegate = workersKvStorage<TestEnv>({ binding: (env) => env.OAUTH_KV, now: () => kv.now });
    let operationCalls = 0;
    const storage: OAuthStorageProvider<TestEnv> = {
      ...delegate,
      capabilities: defineOAuthStorageCapabilities({
        ...WORKERS_KV_STORAGE_CAPABILITIES,
        clients: { ...WORKERS_KV_STORAGE_CAPABILITIES.clients, replace: 'unsupported' },
        revocation: { ...WORKERS_KV_STORAGE_CAPABILITIES.revocation, clientCascade: 'unsupported' },
        queries: {
          ...WORKERS_KV_STORAGE_CAPABILITIES.queries,
          listClients: 'unsupported',
          grantsByUser: 'unsupported',
          globalMaintenance: 'unsupported',
        },
      }),
      async open(context) {
        const connection = await delegate.open(context);
        return {
          ...connection,
          close: () => connection.close(),
          clients: {
            ...connection.clients,
            async list(input) {
              operationCalls++;
              return connection.clients.list(input);
            },
            async replace(input) {
              operationCalls++;
              return connection.clients.replace(input);
            },
            async deleteWithGrants(input) {
              operationCalls++;
              return connection.clients.deleteWithGrants(input);
            },
          },
          grants: {
            ...connection.grants,
            async listByUser(input) {
              operationCalls++;
              return connection.grants.listByUser(input);
            },
          },
          maintenance: {
            async purge(input) {
              operationCalls++;
              return connection.maintenance.purge(input);
            },
          },
        };
      },
    };
    const provider = new OAuthProvider({
      ...options(storage),
      defaultHandler: { fetch: async () => new Response('default') },
    });
    const env: TestEnv = { OAUTH_KV: kv.asNamespace(), OAUTH_PROVIDER: null };
    await provider.fetch(new Request('https://example.com/'), env, executionContext());

    await expect(env.OAUTH_PROVIDER!.listClients()).rejects.toMatchObject({ code: 'unsupported_operation' });
    await expect(env.OAUTH_PROVIDER!.updateClient('client-1', {})).rejects.toMatchObject({
      code: 'unsupported_operation',
    });
    await expect(env.OAUTH_PROVIDER!.deleteClient('client-1')).rejects.toMatchObject({
      code: 'unsupported_operation',
    });
    await expect(env.OAUTH_PROVIDER!.listUserGrants('user-1')).rejects.toMatchObject({
      code: 'unsupported_operation',
    });
    await expect(env.OAUTH_PROVIDER!.purgeExpiredData()).rejects.toMatchObject({
      code: 'unsupported_operation',
    });
    expect(operationCalls).toBe(0);
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
