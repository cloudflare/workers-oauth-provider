/**
 * Reproduction test for issue #34:
 * "No provision to restart the authorization flow if the oauth server
 *  to the worker oauth client does not provide refresh tokens"
 *
 * The core problem: When a user re-authorizes (goes through the auth flow again),
 * the old grant persists with stale props. If the MCP client (e.g. Claude) still
 * holds the old refresh token, it will continue to use the old grant with outdated
 * props — even though the user just went through the auth flow with fresh props.
 *
 * This creates an infinite re-auth loop when tokenExchangeCallback throws
 * invalid_grant to force re-auth, because the client retries with old cached tokens.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { OAuthProvider, type OAuthHelpers } from '../src/oauth-provider';
import type { ExecutionContext } from '@cloudflare/workers-types';
import { WorkerEntrypoint } from 'cloudflare:workers';

// --- Test infrastructure (mirrors main test file) ---

class MockKV {
  private storage: Map<string, { value: any; expiration?: number }> = new Map();

  async put(key: string, value: string | ArrayBuffer, options?: { expirationTtl?: number }): Promise<void> {
    let expirationTime: number | undefined;
    if (options?.expirationTtl) {
      expirationTime = Date.now() + options.expirationTtl * 1000;
    }
    this.storage.set(key, { value, expiration: expirationTime });
  }

  async get(key: string, options?: { type: 'text' | 'json' | 'arrayBuffer' | 'stream' }): Promise<any> {
    const item = this.storage.get(key);
    if (!item) return null;
    if (item.expiration && item.expiration < Date.now()) {
      this.storage.delete(key);
      return null;
    }
    if (options?.type === 'json' && typeof item.value === 'string') {
      return JSON.parse(item.value);
    }
    return item.value;
  }

  async delete(key: string): Promise<void> {
    this.storage.delete(key);
  }

  async list(options: { prefix: string; limit?: number; cursor?: string }): Promise<{
    keys: { name: string }[];
    list_complete: boolean;
    cursor?: string;
  }> {
    const { prefix, limit = 1000 } = options;
    const keys: { name: string }[] = [];
    for (const key of this.storage.keys()) {
      if (key.startsWith(prefix)) {
        const item = this.storage.get(key);
        if (item && (!item.expiration || item.expiration >= Date.now())) {
          keys.push({ name: key });
        }
      }
      if (keys.length >= limit) break;
    }
    return { keys, list_complete: true };
  }

  clear() {
    this.storage.clear();
  }
}

class MockExecutionContext implements ExecutionContext {
  props: any = {};
  waitUntil(_promise: Promise<any>): void {}
  passThroughOnException(): void {}
}

class TestApiHandler extends WorkerEntrypoint {
  fetch(_request: Request) {
    return new Response(JSON.stringify({ props: this.ctx.props }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

function createMockRequest(
  url: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  body?: string
): Request {
  const init: RequestInit = { method, headers };
  if (body) init.body = body;
  return new Request(url, init);
}

// --- Helpers for the OAuth dance ---

async function registerClient(
  provider: OAuthProvider,
  env: any,
  ctx: MockExecutionContext
): Promise<{ clientId: string; clientSecret: string }> {
  const response = await provider.fetch(
    createMockRequest(
      'https://example.com/oauth/register',
      'POST',
      { 'Content-Type': 'application/json' },
      JSON.stringify({
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'MCP Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      })
    ),
    env,
    ctx
  );
  const client = await response.json<any>();
  return { clientId: client.client_id, clientSecret: client.client_secret };
}

async function authorizeAndGetCode(
  provider: OAuthProvider,
  env: any,
  ctx: MockExecutionContext,
  clientId: string,
  scope: string = 'read write'
): Promise<string> {
  const authRequest = createMockRequest(
    `https://example.com/authorize?response_type=code&client_id=${clientId}` +
      `&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}` +
      `&scope=${encodeURIComponent(scope)}&state=test-state`
  );
  const response = await provider.fetch(authRequest, env, ctx);
  const location = response.headers.get('Location')!;
  return new URL(location).searchParams.get('code')!;
}

async function exchangeCodeForTokens(
  provider: OAuthProvider,
  env: any,
  ctx: MockExecutionContext,
  code: string,
  clientId: string,
  clientSecret: string
): Promise<{ access_token: string; refresh_token: string }> {
  const response = await provider.fetch(
    createMockRequest(
      'https://example.com/oauth/token',
      'POST',
      {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
      },
      `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}`
    ),
    env,
    ctx
  );
  return response.json<any>();
}

async function refreshTokens(
  provider: OAuthProvider,
  env: any,
  ctx: MockExecutionContext,
  refreshToken: string,
  clientId: string,
  clientSecret: string
): Promise<{ status: number; body: any; error?: string }> {
  try {
    const response = await provider.fetch(
      createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        `grant_type=refresh_token&refresh_token=${refreshToken}`
      ),
      env,
      ctx
    );
    return { status: response.status, body: await response.json<any>() };
  } catch (err: any) {
    // tokenExchangeCallback errors propagate as thrown exceptions
    return { status: 400, body: null, error: err.message };
  }
}

async function callApi(
  provider: OAuthProvider,
  env: any,
  ctx: MockExecutionContext,
  accessToken: string
): Promise<{ status: number; body: any }> {
  const response = await provider.fetch(
    createMockRequest('https://example.com/api/test', 'GET', {
      Authorization: `Bearer ${accessToken}`,
    }),
    env,
    ctx
  );
  return { status: response.status, body: await response.json<any>() };
}

// --- Tests ---

describe('Issue #34: Re-authorization stale props / infinite loop', () => {
  let mockEnv: { OAUTH_KV: MockKV; OAUTH_PROVIDER: OAuthHelpers | null };
  let mockCtx: MockExecutionContext;
  let propsFromAuthorize: Record<string, any>;

  // Handler with revokeExistingGrants disabled (opt-out) to demonstrate the bug
  function createDefaultHandlerNoRevoke(getProps: () => Record<string, any>) {
    return {
      async fetch(request: Request, env: any, _ctx: ExecutionContext) {
        const url = new URL(request.url);
        if (url.pathname === '/authorize') {
          const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
          const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
            request: oauthReqInfo,
            userId: 'user-1',
            metadata: {},
            scope: oauthReqInfo.scope,
            props: getProps(),
            revokeExistingGrants: false, // opt out of default behavior
          });
          return Response.redirect(redirectTo, 302);
        }
        return new Response('OK', { status: 200 });
      },
    };
  }

  // Handler using default behavior (revokeExistingGrants defaults to true)
  function createDefaultHandler(getProps: () => Record<string, any>) {
    return {
      async fetch(request: Request, env: any, _ctx: ExecutionContext) {
        const url = new URL(request.url);
        if (url.pathname === '/authorize') {
          const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
          const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
            request: oauthReqInfo,
            userId: 'user-1',
            metadata: {},
            scope: oauthReqInfo.scope,
            props: getProps(),
          });
          return Response.redirect(redirectTo, 302);
        }
        return new Response('OK', { status: 200 });
      },
    };
  }

  beforeEach(() => {
    vi.resetAllMocks();
    mockEnv = { OAUTH_KV: new MockKV(), OAUTH_PROVIDER: null };
    mockCtx = new MockExecutionContext();
    propsFromAuthorize = { upstreamToken: 'token-v1', version: 1 };
  });

  afterEach(() => {
    mockEnv.OAUTH_KV.clear();
  });

  describe('WITHOUT revokeExistingGrants (opt-out / the bug)', () => {
    it('should demonstrate that re-authorization creates a second grant while old grant persists', async () => {
      const provider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: createDefaultHandlerNoRevoke(() => propsFromAuthorize),
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
      });

      const { clientId, clientSecret } = await registerClient(provider, mockEnv, mockCtx);

      // --- First authorization: props v1 ---
      const code1 = await authorizeAndGetCode(provider, mockEnv, mockCtx, clientId);
      const tokens1 = await exchangeCodeForTokens(provider, mockEnv, mockCtx, code1, clientId, clientSecret);

      // Verify props v1 are served
      const api1 = await callApi(provider, mockEnv, mockCtx, tokens1.access_token);
      expect(api1.status).toBe(200);
      expect(api1.body.props.upstreamToken).toBe('token-v1');

      // --- Simulate upstream token change ---
      propsFromAuthorize = { upstreamToken: 'token-v2', version: 2 };

      // --- Second authorization (re-auth): props v2 ---
      const code2 = await authorizeAndGetCode(provider, mockEnv, mockCtx, clientId);
      const tokens2 = await exchangeCodeForTokens(provider, mockEnv, mockCtx, code2, clientId, clientSecret);

      // New tokens have correct props v2
      const api2 = await callApi(provider, mockEnv, mockCtx, tokens2.access_token);
      expect(api2.status).toBe(200);
      expect(api2.body.props.upstreamToken).toBe('token-v2');

      // BUG: Old tokens STILL WORK with stale props v1!
      const apiOld = await callApi(provider, mockEnv, mockCtx, tokens1.access_token);
      expect(apiOld.status).toBe(200);
      expect(apiOld.body.props.upstreamToken).toBe('token-v1'); // stale!

      // BUG: Old refresh token STILL WORKS - client can keep getting stale v1 tokens
      const refreshOld = await refreshTokens(provider, mockEnv, mockCtx, tokens1.refresh_token, clientId, clientSecret);
      expect(refreshOld.status).toBe(200); // This is the root cause of infinite loops

      // Verify there are now TWO grants for the same user+client
      const grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('user-1');
      expect(grants.items.length).toBe(2);
      expect(grants.items.every((g: any) => g.clientId === clientId)).toBe(true);
    });

    it('should demonstrate the infinite re-auth loop scenario', async () => {
      /**
       * Simulates the exact issue from #34:
       * 1. tokenExchangeCallback throws invalid_grant on refresh to force re-auth
       * 2. Client goes through auth flow again, gets new code + new tokens
       * 3. But client ALSO still has old refresh token cached
       * 4. Client uses old refresh token → gets stale props → invalid_grant → loop
       */
      let refreshAttempts = 0;

      const provider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: createDefaultHandlerNoRevoke(() => propsFromAuthorize),
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        tokenExchangeCallback: async (options) => {
          if (options.grantType === 'refresh_token') {
            refreshAttempts++;
            // Simulate: upstream token in props is expired, force re-auth
            if (options.props.upstreamToken === 'token-v1-expired') {
              throw new Error(
                JSON.stringify({
                  error: 'invalid_grant',
                  error_description: 'upstream token expired',
                })
              );
            }
          }
          return undefined;
        },
      });

      const { clientId, clientSecret } = await registerClient(provider, mockEnv, mockCtx);

      // First auth with a token that will expire
      propsFromAuthorize = { upstreamToken: 'token-v1-expired', version: 1 };
      const code1 = await authorizeAndGetCode(provider, mockEnv, mockCtx, clientId);
      const tokens1 = await exchangeCodeForTokens(provider, mockEnv, mockCtx, code1, clientId, clientSecret);

      // Simulate upstream token expiry - refresh should fail with invalid_grant
      // (tokenExchangeCallback throws, which propagates as an exception)
      const refresh1 = await refreshTokens(provider, mockEnv, mockCtx, tokens1.refresh_token, clientId, clientSecret);
      expect(refresh1.status).toBe(400);
      expect(refresh1.error).toContain('invalid_grant');

      // Client goes through re-auth with fresh props
      propsFromAuthorize = { upstreamToken: 'token-v2-fresh', version: 2 };
      const code2 = await authorizeAndGetCode(provider, mockEnv, mockCtx, clientId);
      const tokens2 = await exchangeCodeForTokens(provider, mockEnv, mockCtx, code2, clientId, clientSecret);

      // New tokens work fine
      const api2 = await callApi(provider, mockEnv, mockCtx, tokens2.access_token);
      expect(api2.status).toBe(200);
      expect(api2.body.props.upstreamToken).toBe('token-v2-fresh');

      // THE BUG: Client still has old refresh token cached. Old grant still exists.
      // If client uses old refresh token, it hits the old grant with stale props.
      // The old grant is a DIFFERENT grant (different grantId) so it has the
      // old (expired) props → tokenExchangeCallback throws → client re-auths → loop
      const grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('user-1');
      expect(grants.items.length).toBe(2); // Two grants exist!
    });
  });

  describe('WITH revokeExistingGrants (the fix from PR #144)', () => {
    it('should revoke old grants on re-authorization so stale tokens are invalidated', async () => {
      const provider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: createDefaultHandler(() => propsFromAuthorize),
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
      });

      const { clientId, clientSecret } = await registerClient(provider, mockEnv, mockCtx);

      // --- First authorization: props v1 ---
      const code1 = await authorizeAndGetCode(provider, mockEnv, mockCtx, clientId);
      const tokens1 = await exchangeCodeForTokens(provider, mockEnv, mockCtx, code1, clientId, clientSecret);

      // Verify first auth works
      const api1 = await callApi(provider, mockEnv, mockCtx, tokens1.access_token);
      expect(api1.status).toBe(200);
      expect(api1.body.props.upstreamToken).toBe('token-v1');

      // --- Simulate upstream token change ---
      propsFromAuthorize = { upstreamToken: 'token-v2', version: 2 };

      // --- Re-authorize with revokeExistingGrants: true ---
      const code2 = await authorizeAndGetCode(provider, mockEnv, mockCtx, clientId);
      const tokens2 = await exchangeCodeForTokens(provider, mockEnv, mockCtx, code2, clientId, clientSecret);

      // New tokens have correct props v2
      const api2 = await callApi(provider, mockEnv, mockCtx, tokens2.access_token);
      expect(api2.status).toBe(200);
      expect(api2.body.props.upstreamToken).toBe('token-v2');

      // FIX: Old access token should now be INVALID (grant was revoked)
      const apiOld = await callApi(provider, mockEnv, mockCtx, tokens1.access_token);
      expect(apiOld.status).toBe(401); // Old token is dead!

      // FIX: Old refresh token should also be INVALID
      const refreshOld = await refreshTokens(provider, mockEnv, mockCtx, tokens1.refresh_token, clientId, clientSecret);
      expect(refreshOld.status).toBe(400); // Old refresh token is dead!

      // FIX: Only ONE grant should exist for this user+client
      const grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('user-1');
      // Note: might be 1 (the new one) since old was revoked before new was created
      // The new grant is created AFTER revocation in completeAuthorization
      expect(grants.items.length).toBe(1);
      expect(grants.items[0].clientId).toBe(clientId);
    });

    it('should break the infinite re-auth loop', async () => {
      let refreshCallCount = 0;

      const provider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: createDefaultHandler(() => propsFromAuthorize),
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        tokenExchangeCallback: async (options) => {
          if (options.grantType === 'refresh_token') {
            refreshCallCount++;
            if (options.props.upstreamToken === 'token-v1-expired') {
              throw new Error(
                JSON.stringify({
                  error: 'invalid_grant',
                  error_description: 'upstream token expired',
                })
              );
            }
          }
          return undefined;
        },
      });

      const { clientId, clientSecret } = await registerClient(provider, mockEnv, mockCtx);

      // First auth with token that will expire
      propsFromAuthorize = { upstreamToken: 'token-v1-expired', version: 1 };
      const code1 = await authorizeAndGetCode(provider, mockEnv, mockCtx, clientId);
      const tokens1 = await exchangeCodeForTokens(provider, mockEnv, mockCtx, code1, clientId, clientSecret);

      // Refresh fails because upstream token is expired (thrown error)
      const refresh1 = await refreshTokens(provider, mockEnv, mockCtx, tokens1.refresh_token, clientId, clientSecret);
      expect(refresh1.status).toBe(400);
      expect(refresh1.error).toContain('invalid_grant');

      // Re-authorize with fresh props + revokeExistingGrants
      propsFromAuthorize = { upstreamToken: 'token-v2-fresh', version: 2 };
      const code2 = await authorizeAndGetCode(provider, mockEnv, mockCtx, clientId);
      const tokens2 = await exchangeCodeForTokens(provider, mockEnv, mockCtx, code2, clientId, clientSecret);

      // FIX: If client tries old refresh token, it FAILS immediately
      // (grant was revoked) instead of hitting tokenExchangeCallback with stale props
      const refreshOld = await refreshTokens(provider, mockEnv, mockCtx, tokens1.refresh_token, clientId, clientSecret);
      expect(refreshOld.status).toBe(400);

      // New refresh token works correctly with fresh props
      const refreshNew = await refreshTokens(provider, mockEnv, mockCtx, tokens2.refresh_token, clientId, clientSecret);
      expect(refreshNew.status).toBe(200);

      // Only one grant should exist
      const grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('user-1');
      expect(grants.items.length).toBe(1);
    });

    it('should not affect grants from other clients', async () => {
      const provider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: createDefaultHandler(() => propsFromAuthorize),
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
      });

      // Register two different clients
      const client1 = await registerClient(provider, mockEnv, mockCtx);

      const response2 = await provider.fetch(
        createMockRequest(
          'https://example.com/oauth/register',
          'POST',
          { 'Content-Type': 'application/json' },
          JSON.stringify({
            redirect_uris: ['https://other-client.example.com/callback'],
            client_name: 'Other MCP Client',
            token_endpoint_auth_method: 'client_secret_basic',
          })
        ),
        mockEnv,
        mockCtx
      );
      const c2 = await response2.json<any>();
      const client2 = { clientId: c2.client_id, clientSecret: c2.client_secret };

      // Authorize both clients
      const code1 = await authorizeAndGetCode(provider, mockEnv, mockCtx, client1.clientId);
      await exchangeCodeForTokens(provider, mockEnv, mockCtx, code1, client1.clientId, client1.clientSecret);

      // For client2, we need to use its redirect_uri
      const authRequest2 = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${client2.clientId}` +
          `&redirect_uri=${encodeURIComponent('https://other-client.example.com/callback')}` +
          `&scope=read%20write&state=test-state`
      );
      const authResponse2 = await provider.fetch(authRequest2, mockEnv, mockCtx);
      const code2 = new URL(authResponse2.headers.get('Location')!).searchParams.get('code')!;

      const tokenResponse2 = await provider.fetch(
        createMockRequest(
          'https://example.com/oauth/token',
          'POST',
          {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${btoa(`${client2.clientId}:${client2.clientSecret}`)}`,
          },
          `grant_type=authorization_code&code=${code2}&redirect_uri=${encodeURIComponent('https://other-client.example.com/callback')}`
        ),
        mockEnv,
        mockCtx
      );
      const tokens2 = await tokenResponse2.json<any>();

      // Should have 2 grants (one per client)
      let grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('user-1');
      expect(grants.items.length).toBe(2);

      // Re-authorize client1 with revokeExistingGrants
      propsFromAuthorize = { upstreamToken: 'token-v2', version: 2 };
      const code1b = await authorizeAndGetCode(provider, mockEnv, mockCtx, client1.clientId);
      await exchangeCodeForTokens(provider, mockEnv, mockCtx, code1b, client1.clientId, client1.clientSecret);

      // Should still have 2 grants: new client1 grant + untouched client2 grant
      grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('user-1');
      expect(grants.items.length).toBe(2);

      // Client2's tokens should still work
      const api2 = await callApi(provider, mockEnv, mockCtx, tokens2.access_token);
      expect(api2.status).toBe(200);
    });
  });
});
