import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { OAuthProvider, type OAuthHelpers } from '../src/oauth-provider';
import type { ExecutionContext } from '@cloudflare/workers-types';
// We're importing WorkerEntrypoint from our mock implementation
// The actual import is mocked in setup.ts
import { WorkerEntrypoint } from 'cloudflare:workers';

/**
 * Mock KV namespace implementation that stores data in memory
 */
class MockKV {
  private storage: Map<string, { value: any; expiration?: number }> = new Map();

  async put(key: string, value: string | ArrayBuffer, options?: { expirationTtl?: number }): Promise<void> {
    let expirationTime: number | undefined = undefined;

    if (options?.expirationTtl) {
      expirationTime = Date.now() + options.expirationTtl * 1000;
    }

    this.storage.set(key, { value, expiration: expirationTime });
  }

  async get(key: string, options?: { type: 'text' | 'json' | 'arrayBuffer' | 'stream' }): Promise<any> {
    const item = this.storage.get(key);

    if (!item) {
      return null;
    }

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
    let keys: { name: string }[] = [];

    for (const key of this.storage.keys()) {
      if (key.startsWith(prefix)) {
        const item = this.storage.get(key);
        if (item && (!item.expiration || item.expiration >= Date.now())) {
          keys.push({ name: key });
        }
      }

      if (keys.length >= limit) {
        break;
      }
    }

    return {
      keys,
      list_complete: true,
    };
  }

  clear() {
    this.storage.clear();
  }
}

/**
 * Mock execution context for Cloudflare Workers
 */
class MockExecutionContext implements ExecutionContext {
  props: any = {};

  waitUntil(promise: Promise<any>): void {
    // In tests, we can just ignore waitUntil
  }

  passThroughOnException(): void {
    // No-op for tests
  }
}

// Simple API handler for testing
class TestApiHandler extends WorkerEntrypoint {
  fetch(request: Request) {
    const url = new URL(request.url);

    if (url.pathname === '/api/test') {
      // Return authenticated user info from ctx.props
      return new Response(
        JSON.stringify({
          success: true,
          user: this.ctx.props,
        }),
        {
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    return new Response('Not found', { status: 404 });
  }
}

// Simple default handler for testing
const testDefaultHandler = {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (url.pathname === '/authorize') {
      // Mock authorize endpoint
      const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      const clientInfo = await env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId);

      // Mock user consent flow - automatically grant consent
      const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
        request: oauthReqInfo,
        userId: 'test-user-123',
        metadata: { testConsent: true },
        scope: oauthReqInfo.scope,
        props: { userId: 'test-user-123', username: 'TestUser' },
      });

      return Response.redirect(redirectTo, 302);
    }

    return new Response('Default handler', { status: 200 });
  },
};

// Helper function to create mock requests
function createMockRequest(
  url: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  body?: string | FormData
): Request {
  const requestInit: RequestInit = {
    method,
    headers,
  };

  if (body) {
    requestInit.body = body;
  }

  return new Request(url, requestInit);
}

// Create a configured mock environment
function createMockEnv() {
  return {
    OAUTH_KV: new MockKV(),
    OAUTH_PROVIDER: null, // Will be populated by the OAuthProvider
  } as {
    OAUTH_KV: MockKV;
    OAUTH_PROVIDER: OAuthHelpers | null;
  };
}

describe('OAuthProvider', () => {
  let oauthProvider: OAuthProvider;
  let mockEnv: ReturnType<typeof createMockEnv>;
  let mockCtx: MockExecutionContext;

  beforeEach(() => {
    // Reset mocks before each test
    vi.resetAllMocks();

    // Create fresh instances for each test
    mockEnv = createMockEnv();
    mockCtx = new MockExecutionContext();

    // Create OAuth provider with test configuration
    oauthProvider = new OAuthProvider({
      apiRoute: ['/api/', 'https://api.example.com/'],
      apiHandler: TestApiHandler,
      defaultHandler: testDefaultHandler,
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      clientRegistrationEndpoint: '/oauth/register',
      scopesSupported: ['read', 'write', 'profile'],
      accessTokenTTL: 3600,
      allowImplicitFlow: true, // Enable implicit flow for tests
      allowTokenExchangeGrant: true, // Enable token exchange for tests
    });
  });

  afterEach(() => {
    // Clean up KV storage after each test
    mockEnv.OAUTH_KV.clear();
  });

  describe('API Route Configuration', () => {
    it('should support multi-handler configuration with apiHandlers', async () => {
      // Create handler classes for different API routes
      class UsersApiHandler extends WorkerEntrypoint {
        fetch(request: Request) {
          return new Response('Users API response', { status: 200 });
        }
      }

      class DocumentsApiHandler extends WorkerEntrypoint {
        fetch(request: Request) {
          return new Response('Documents API response', { status: 200 });
        }
      }

      // Create provider with multi-handler configuration
      const providerWithMultiHandler = new OAuthProvider({
        apiHandlers: {
          '/api/users/': UsersApiHandler,
          '/api/documents/': DocumentsApiHandler,
        },
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register', // Important for registering clients in the test
        scopesSupported: ['read', 'write'],
      });

      // Create a client and get an access token
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await providerWithMultiHandler.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await providerWithMultiHandler.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await providerWithMultiHandler.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      const accessToken = tokens.access_token;

      // Make requests to different API routes
      const usersApiRequest = createMockRequest('https://example.com/api/users/profile', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const documentsApiRequest = createMockRequest('https://example.com/api/documents/list', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      // Request to Users API should be handled by UsersApiHandler
      const usersResponse = await providerWithMultiHandler.fetch(usersApiRequest, mockEnv, mockCtx);
      expect(usersResponse.status).toBe(200);
      expect(await usersResponse.text()).toBe('Users API response');

      // Request to Documents API should be handled by DocumentsApiHandler
      const documentsResponse = await providerWithMultiHandler.fetch(documentsApiRequest, mockEnv, mockCtx);
      expect(documentsResponse.status).toBe(200);
      expect(await documentsResponse.text()).toBe('Documents API response');
    });

    it('should throw an error when both single-handler and multi-handler configs are provided', () => {
      expect(() => {
        new OAuthProvider({
          apiRoute: '/api/',
          apiHandler: {
            fetch: () => Promise.resolve(new Response()),
          },
          apiHandlers: {
            '/api/users/': {
              fetch: () => Promise.resolve(new Response()),
            },
          },
          defaultHandler: testDefaultHandler,
          authorizeEndpoint: '/authorize',
          tokenEndpoint: '/oauth/token',
        });
      }).toThrow('Cannot use both apiRoute/apiHandler and apiHandlers');
    });

    it('should throw an error when neither single-handler nor multi-handler config is provided', () => {
      expect(() => {
        new OAuthProvider({
          // Intentionally omitting apiRoute and apiHandler and apiHandlers
          defaultHandler: testDefaultHandler,
          authorizeEndpoint: '/authorize',
          tokenEndpoint: '/oauth/token',
        });
      }).toThrow('Must provide either apiRoute + apiHandler OR apiHandlers');
    });
  });

  describe('OAuth Metadata Discovery', () => {
    it('should return correct metadata at .well-known/oauth-authorization-server', async () => {
      const request = createMockRequest('https://example.com/.well-known/oauth-authorization-server');
      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(200);

      const metadata = await response.json<any>();
      expect(metadata.issuer).toBe('https://example.com');
      expect(metadata.authorization_endpoint).toBe('https://example.com/authorize');
      expect(metadata.token_endpoint).toBe('https://example.com/oauth/token');
      expect(metadata.registration_endpoint).toBe('https://example.com/oauth/register');
      expect(metadata.scopes_supported).toEqual(['read', 'write', 'profile']);
      expect(metadata.response_types_supported).toContain('code');
      expect(metadata.response_types_supported).toContain('token'); // Implicit flow enabled
      expect(metadata.grant_types_supported).toContain('authorization_code');
      expect(metadata.code_challenge_methods_supported).toContain('S256');
    });

    it('should not include token response type when implicit flow is disabled', async () => {
      // Create a provider with implicit flow disabled
      const providerWithoutImplicit = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        allowImplicitFlow: false, // Explicitly disable
      });

      const request = createMockRequest('https://example.com/.well-known/oauth-authorization-server');
      const response = await providerWithoutImplicit.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(200);

      const metadata = await response.json<any>();
      expect(metadata.response_types_supported).toContain('code');
      expect(metadata.response_types_supported).not.toContain('token');
    });
  });

  describe('Client Registration', () => {
    it('should register a new client', async () => {
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(201);

      const registeredClient = await response.json<any>();
      expect(registeredClient.client_id).toBeDefined();
      expect(registeredClient.client_secret).toBeDefined();
      expect(registeredClient.redirect_uris).toEqual(['https://client.example.com/callback']);
      expect(registeredClient.client_name).toBe('Test Client');

      // Verify the client was saved to KV
      const savedClient = await mockEnv.OAUTH_KV.get(`client:${registeredClient.client_id}`, { type: 'json' });
      expect(savedClient).not.toBeNull();
      expect(savedClient.clientId).toBe(registeredClient.client_id);
      // Secret should be stored as a hash
      expect(savedClient.clientSecret).not.toBe(registeredClient.client_secret);
    });

    it('should register a public client', async () => {
      const clientData = {
        redirect_uris: ['https://spa.example.com/callback'],
        client_name: 'SPA Client',
        token_endpoint_auth_method: 'none',
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(201);

      const registeredClient = await response.json<any>();
      expect(registeredClient.client_id).toBeDefined();
      expect(registeredClient.client_secret).toBeUndefined(); // Public client should not have a secret
      expect(registeredClient.token_endpoint_auth_method).toBe('none');

      // Verify the client was saved to KV
      const savedClient = await mockEnv.OAUTH_KV.get(`client:${registeredClient.client_id}`, { type: 'json' });
      expect(savedClient).not.toBeNull();
      expect(savedClient.clientSecret).toBeUndefined(); // No secret stored
    });
  });

  describe('Authorization Code Flow', () => {
    let clientId: string;
    let clientSecret: string;
    let redirectUri: string;

    // Helper to create a test client before authorization tests
    async function createTestClient() {
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);
      const client = await response.json<any>();

      clientId = client.client_id;
      clientSecret = client.client_secret;
      redirectUri = 'https://client.example.com/callback';
    }

    beforeEach(async () => {
      await createTestClient();
    });

    it('should handle the authorization request and redirect', async () => {
      // Create an authorization request
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      // The default handler will process this request and generate a redirect
      const response = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);

      expect(response.status).toBe(302);

      // Check that we're redirected to the client's redirect_uri with a code
      const location = response.headers.get('Location');
      expect(location).toBeDefined();
      expect(location).toContain(redirectUri);
      expect(location).toContain('code=');
      expect(location).toContain('state=xyz123');

      // Extract the authorization code from the redirect URL
      const url = new URL(location!);
      const code = url.searchParams.get('code');
      expect(code).toBeDefined();

      // Verify a grant was created in KV
      const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      expect(grants.keys.length).toBe(1);
    });

    it('should reject authorization request with invalid redirect URI', async () => {
      // Create an authorization request with an invalid redirect URI
      const invalidRedirectUri = 'https://attacker.example.com/callback';
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(invalidRedirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      // Expect the request to be rejected
      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');

      // Verify no grant was created
      const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      expect(grants.keys.length).toBe(0);
    });

    it('should reject authorization request with invalid client id', async () => {
      // Create an authorization request with an invalid redirect URI
      const invalidClientId = 'attackerClientId';
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${invalidClientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      // Expect the request to be rejected
      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid client');

      // Verify no grant was created
      const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      expect(grants.keys.length).toBe(0);
    });

    it('should reject authorization request with invalid client id and redirect uri', async () => {
      // Create an authorization request with an invalid redirect URI
      const invalidRedirectUri = 'https://attacker.example.com/callback';
      const invalidClientId = 'attackerClientId';
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${invalidClientId}` +
          `&redirect_uri=${encodeURIComponent(invalidRedirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      // Expect the request to be rejected
      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid client');

      // Verify no grant was created
      const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      expect(grants.keys.length).toBe(0);
    });

    it('should reject authorization request with javascript: redirect URI', async () => {
      // Create an authorization request with a javascript: redirect URI
      const javascriptRedirectUri = 'javascript:alert("xss")';
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(javascriptRedirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      // Expect the request to be rejected
      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');

      // Verify no grant was created
      const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      expect(grants.keys.length).toBe(0);
    });

    it('should reject completeAuthorization if redirect_uri is invalid', async () => {
      // This test ensures that completeAuthorization re-validates the redirect_uri.
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read&state=xyz123`
      );

      // Manually trigger the fetch to populate env.OAUTH_PROVIDER
      await oauthProvider.fetch(createMockRequest('https://example.com/'), mockEnv, mockCtx);
      const helpers = mockEnv.OAUTH_PROVIDER!;

      // Parse the request to get a valid AuthRequest object
      const oauthReqInfo = await helpers.parseAuthRequest(authRequest);

      // Manually tamper with the redirect_uri after parsing
      const tamperedRequest = { ...oauthReqInfo, redirectUri: 'https://attacker.com' };

      // Expect completeAuthorization to throw because the redirect_uri is not registered
      await expect(
        helpers.completeAuthorization({
          request: tamperedRequest,
          userId: 'test-user-123',
          metadata: {},
          scope: tamperedRequest.scope,
          props: {},
        })
      ).rejects.toThrow('Invalid redirect URI');
    });
  });

  describe('Implicit Flow', () => {
    let clientId: string;
    let redirectUri: string;

    // Helper to create a test client before authorization tests
    async function createPublicClient() {
      const clientData = {
        redirect_uris: ['https://spa-client.example.com/callback'],
        client_name: 'SPA Test Client',
        token_endpoint_auth_method: 'none', // Public client
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);
      const client = await response.json<any>();

      clientId = client.client_id;
      redirectUri = 'https://spa-client.example.com/callback';
    }

    beforeEach(async () => {
      await createPublicClient();
    });

    it('should handle implicit flow request and redirect with token in fragment', async () => {
      // Create an implicit flow authorization request
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=token&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      // The default handler will process this request and generate a redirect
      const response = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);

      expect(response.status).toBe(302);

      // Check that we're redirected to the client's redirect_uri with token in fragment
      const location = response.headers.get('Location');
      expect(location).toBeDefined();
      expect(location).toContain(redirectUri);

      const url = new URL(location!);

      // Check that there's no code parameter in the query string
      expect(url.searchParams.has('code')).toBe(false);

      // Check that we have a hash/fragment with token parameters
      expect(url.hash).toBeTruthy();

      // Parse the fragment
      const fragment = new URLSearchParams(url.hash.substring(1)); // Remove the # character

      // Verify token parameters
      expect(fragment.get('access_token')).toBeTruthy();
      expect(fragment.get('token_type')).toBe('bearer');
      expect(fragment.get('expires_in')).toBe('3600');
      expect(fragment.get('scope')).toBe('read write');
      expect(fragment.get('state')).toBe('xyz123');

      // Verify a grant was created in KV
      const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      expect(grants.keys.length).toBe(1);

      // Verify access token was stored in KV
      const tokenEntries = await mockEnv.OAUTH_KV.list({ prefix: 'token:' });
      expect(tokenEntries.keys.length).toBe(1);
    });

    it('should reject implicit flow when allowImplicitFlow is disabled', async () => {
      // Create a provider with implicit flow disabled
      const providerWithoutImplicit = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        allowImplicitFlow: false, // Explicitly disable
      });

      // Create an implicit flow authorization request
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=token&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      // Mock parseAuthRequest to test error handling
      vi.spyOn(authRequest, 'formData').mockImplementation(() => {
        throw new Error('The implicit grant flow is not enabled for this provider');
      });

      // Expect an error response
      await expect(providerWithoutImplicit.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(
        'The implicit grant flow is not enabled for this provider'
      );
    });

    it('should use the access token to access API directly', async () => {
      // Create an implicit flow authorization request
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=token&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      // The default handler will process this request and generate a redirect
      const response = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = response.headers.get('Location')!;

      // Parse the fragment to get the access token
      const url = new URL(location);
      const fragment = new URLSearchParams(url.hash.substring(1));
      const accessToken = fragment.get('access_token')!;

      // Now use the access token for an API request
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);

      const apiData = await apiResponse.json<any>();
      expect(apiData.success).toBe(true);
      expect(apiData.user).toEqual({ userId: 'test-user-123', username: 'TestUser' });
    });
  });

  describe('Redirect URI Scheme Validation (Security)', () => {
    let clientId: string;
    let clientSecret: string;
    let redirectUri: string;

    // Helper to create a test client before authorization tests
    async function createTestClient() {
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);
      const client = await response.json<any>();

      clientId = client.client_id;
      clientSecret = client.client_secret;
      redirectUri = 'https://client.example.com/callback';
    }

    beforeEach(async () => {
      await createTestClient();
    });

    describe('should reject dangerous pseudo-schemes (case-sensitive baseline)', () => {
      const dangerousSchemes = [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'vbscript:msgbox(1)',
        'file:///etc/passwd',
        'mailto:attacker@evil.com',
        'blob:https://example.com/uuid',
      ];

      dangerousSchemes.forEach((maliciousUri) => {
        it(`should reject ${maliciousUri.split(':')[0]}: scheme`, async () => {
          const authRequest = createMockRequest(
            `https://example.com/authorize?response_type=code&client_id=${clientId}` +
              `&redirect_uri=${encodeURIComponent(maliciousUri)}` +
              `&scope=read&state=xyz123`
          );

          await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');

          // Verify no grant was created
          const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
          expect(grants.keys.length).toBe(0);
        });
      });
    });

    describe('should block mixed-case scheme bypass attempts', () => {
      const mixedCaseSchemes = [
        'JaVaScRiPt:alert(1)',
        'JAVASCRIPT:alert(1)',
        'JavaScript:alert(1)',
        'DaTa:text/html,<script>alert(1)</script>',
        'DATA:text/html,<script>alert(1)</script>',
        'VbScRiPt:msgbox(1)',
        'VBSCRIPT:msgbox(1)',
        'FiLe:///etc/passwd',
        'FILE:///etc/passwd',
        'MaIlTo:attacker@evil.com',
        'MAILTO:attacker@evil.com',
        'BlOb:https://example.com/uuid',
        'BLOB:https://example.com/uuid',
      ];

      mixedCaseSchemes.forEach((maliciousUri) => {
        it(`should reject ${maliciousUri}`, async () => {
          const authRequest = createMockRequest(
            `https://example.com/authorize?response_type=code&client_id=${clientId}` +
              `&redirect_uri=${encodeURIComponent(maliciousUri)}` +
              `&scope=read&state=xyz123`
          );

          await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');

          // Verify no grant was created
          const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
          expect(grants.keys.length).toBe(0);
        });
      });
    });

    describe('should block leading whitespace/control character bypass attempts', () => {
      const bypassAttempts = [
        { desc: 'leading space', uri: ' javascript:alert(1)' },
        { desc: 'leading tab', uri: '\tjavascript:alert(1)' },
        { desc: 'leading newline', uri: '\njavascript:alert(1)' },
        { desc: 'leading carriage return', uri: '\rjavascript:alert(1)' },
        { desc: 'leading null byte', uri: '\x00javascript:alert(1)' },
        { desc: 'multiple leading spaces', uri: '   javascript:alert(1)' },
        { desc: 'leading vertical tab', uri: '\x0Bjavascript:alert(1)' },
        { desc: 'leading form feed', uri: '\x0Cjavascript:alert(1)' },
        { desc: 'trailing space with javascript', uri: ' javascript:alert(1) ' },
      ];

      bypassAttempts.forEach(({ desc, uri }) => {
        it(`should reject URI with ${desc}`, async () => {
          const authRequest = createMockRequest(
            `https://example.com/authorize?response_type=code&client_id=${clientId}` +
              `&redirect_uri=${encodeURIComponent(uri)}` +
              `&scope=read&state=xyz123`
          );

          await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');

          // Verify no grant was created
          const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
          expect(grants.keys.length).toBe(0);
        });
      });
    });

    describe('should block embedded control character bypass attempts', () => {
      const bypassAttempts = [
        { desc: 'tab in scheme name', uri: 'jav\tascript:alert(1)' },
        { desc: 'newline in scheme name', uri: 'java\nscript:alert(1)' },
        { desc: 'null byte in scheme name', uri: 'java\x00script:alert(1)' },
        { desc: 'carriage return in scheme', uri: 'java\rscript:alert(1)' },
        { desc: 'vertical tab in scheme', uri: 'java\x0Bscript:alert(1)' },
        { desc: 'form feed in scheme', uri: 'java\x0Cscript:alert(1)' },
        { desc: 'multiple control chars', uri: 'ja\x00va\tsc\nript:alert(1)' },
      ];

      bypassAttempts.forEach(({ desc, uri }) => {
        it(`should reject URI with ${desc}`, async () => {
          const authRequest = createMockRequest(
            `https://example.com/authorize?response_type=code&client_id=${clientId}` +
              `&redirect_uri=${encodeURIComponent(uri)}` +
              `&scope=read&state=xyz123`
          );

          await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');

          // Verify no grant was created
          const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
          expect(grants.keys.length).toBe(0);
        });
      });
    });

    describe('should block control characters in legitimate URIs', () => {
      const controlCharVariants = [
        { desc: 'DELETE char (0x7F) in path', uri: 'https://example.com\x7F/callback' },
        { desc: 'null byte in path', uri: 'https://example.com/call\x00back' },
        { desc: 'tab in path', uri: 'https://example.com/call\tback' },
        { desc: 'newline after scheme', uri: 'https:\n//example.com/callback' },
        { desc: 'C1 control (0x80) in host', uri: 'https://exam\x80ple.com/callback' },
        { desc: 'C1 control (0x9F) in path', uri: 'https://example.com/call\x9Fback' },
        { desc: 'boundary C0 (0x1F)', uri: 'https://example.com/call\x1Fback' },
        { desc: 'boundary C1 (0x9F)', uri: 'https://example.com/call\x9Fback' },
        { desc: 'control char in query', uri: 'https://example.com/callback?param=val\x00ue' },
        { desc: 'control char in fragment', uri: 'https://example.com/callback#sec\x00tion' },
      ];

      controlCharVariants.forEach(({ desc, uri }) => {
        it(`should reject URI with ${desc}`, async () => {
          const authRequest = createMockRequest(
            `https://example.com/authorize?response_type=code&client_id=${clientId}` +
              `&redirect_uri=${encodeURIComponent(uri)}` +
              `&scope=read&state=xyz123`
          );

          await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');

          // Verify no grant was created
          const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
          expect(grants.keys.length).toBe(0);
        });
      });
    });

    describe('should block data: URI variations', () => {
      const dataUriVariants = [
        'data:text/html,<script>alert(1)</script>',
        'DaTa:text/html,<script>alert(1)</script>',
        ' data:text/html,<script>alert(1)</script>',
        'da\tta:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
      ];

      dataUriVariants.forEach((uri) => {
        it(`should reject ${uri.substring(0, 30)}...`, async () => {
          const authRequest = createMockRequest(
            `https://example.com/authorize?response_type=code&client_id=${clientId}` +
              `&redirect_uri=${encodeURIComponent(uri)}` +
              `&scope=read&state=xyz123`
          );

          await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');

          // Verify no grant was created
          const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
          expect(grants.keys.length).toBe(0);
        });
      });
    });

    describe('should allow legitimate URIs', () => {
      const legitimateUris = [
        'https://client.example.com/callback',
        'https://client.example.com/callback?param=value',
        'https://client.example.com:8080/callback',
        'http://localhost:3000/callback',
        'http://127.0.0.1:8080/callback',
        'myapp://callback',
        'com.example.app://oauth/callback',
      ];

      legitimateUris.forEach((uri) => {
        it(`should allow ${uri}`, async () => {
          // First, we need to register a client with this URI
          const clientData = {
            redirect_uris: [uri],
            client_name: 'Test Client for ' + uri,
            token_endpoint_auth_method: 'client_secret_basic',
          };

          const registerRequest = createMockRequest(
            'https://example.com/oauth/register',
            'POST',
            { 'Content-Type': 'application/json' },
            JSON.stringify(clientData)
          );

          const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
          const client = await registerResponse.json<any>();

          const authRequest = createMockRequest(
            `https://example.com/authorize?response_type=code&client_id=${client.client_id}` +
              `&redirect_uri=${encodeURIComponent(uri)}` +
              `&scope=read&state=xyz123`
          );

          const response = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);

          // Should get a redirect, not an error
          expect(response.status).toBe(302);
          const location = response.headers.get('Location');
          expect(location).toBeDefined();
          expect(location).toContain('code=');
        });
      });
    });

    describe('should handle edge cases', () => {
      it('should reject empty redirect URI', async () => {
        const authRequest = createMockRequest(
          `https://example.com/authorize?response_type=code&client_id=${clientId}` +
            `&redirect_uri=&scope=read&state=xyz123`
        );

        await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow();
      });

      it('should reject relative URIs', async () => {
        // Relative URIs should be rejected at scheme validation
        const relativeUri = '/callback';

        const clientData = {
          redirect_uris: [relativeUri],
          client_name: 'Test Client with Relative URI',
          token_endpoint_auth_method: 'client_secret_basic',
        };

        const registerRequest = createMockRequest(
          'https://example.com/oauth/register',
          'POST',
          { 'Content-Type': 'application/json' },
          JSON.stringify(clientData)
        );

        // Should be rejected with "Invalid redirect URI" error
        const response = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
        expect(response.status).toBe(400);
        const errorBody = await response.json<any>();
        expect(errorBody.error).toBe('invalid_client_metadata');
        expect(errorBody.error_description).toBe('Invalid redirect URI');
      });
    });
  });

  describe('Authorization Code Flow Exchange', () => {
    let clientId: string;
    let clientSecret: string;
    let redirectUri: string;

    // Helper to create a test client before authorization tests
    async function createTestClient() {
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);
      const client = await response.json<any>();

      clientId = client.client_id;
      clientSecret = client.client_secret;
      redirectUri = 'https://client.example.com/callback';
    }

    beforeEach(async () => {
      await createTestClient();
    });

    it('should exchange auth code for tokens', async () => {
      // First get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const url = new URL(location);
      const code = url.searchParams.get('code')!;

      // Now exchange the code for tokens
      // Use URLSearchParams which is proper for application/x-www-form-urlencoded
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      // Use the URLSearchParams object as the body - correctly encoded for Content-Type: application/x-www-form-urlencoded
      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      expect(tokenResponse.status).toBe(200);

      const tokens = await tokenResponse.json<any>();
      expect(tokens.access_token).toBeDefined();
      expect(tokens.refresh_token).toBeDefined();
      expect(tokens.token_type).toBe('bearer');
      expect(tokens.expires_in).toBe(3600);

      // Verify token was stored in KV
      const tokenEntries = await mockEnv.OAUTH_KV.list({ prefix: 'token:' });
      expect(tokenEntries.keys.length).toBe(1);

      // Verify grant was updated (auth code removed, refresh token added)
      const grantEntries = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      const grantKey = grantEntries.keys[0].name;
      const grant = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });

      expect(grant.authCodeId).toBeUndefined(); // Auth code should be removed
      expect(grant.refreshTokenId).toBeDefined(); // Refresh token should be added
    });

    it('should reject token exchange without redirect_uri when not using PKCE', async () => {
      // First get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const url = new URL(location);
      const code = url.searchParams.get('code')!;

      // Now exchange the code without providing redirect_uri
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      // redirect_uri intentionally omitted
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      // Should fail because redirect_uri is required when not using PKCE
      expect(tokenResponse.status).toBe(400);
      const error = await tokenResponse.json<any>();
      expect(error.error).toBe('invalid_request');
      expect(error.error_description).toBe('redirect_uri is required when not using PKCE');
    });

    it('should reject token exchange with code_verifier when PKCE was not used in authorization', async () => {
      // First get an auth code WITHOUT using PKCE
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const url = new URL(location);
      const code = url.searchParams.get('code')!;

      // Now exchange the code and incorrectly provide a code_verifier
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
      params.append('code_verifier', 'some_random_verifier_that_wasnt_used_in_auth');

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      // Should fail because code_verifier is provided but PKCE wasn't used in authorization
      expect(tokenResponse.status).toBe(400);
      const error = await tokenResponse.json<any>();
      expect(error.error).toBe('invalid_request');
      expect(error.error_description).toBe('code_verifier provided for a flow that did not use PKCE');
    });

    // Helper function for PKCE tests
    function generateRandomString(length: number): string {
      const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      let result = '';
      const values = new Uint8Array(length);
      crypto.getRandomValues(values);
      for (let i = 0; i < length; i++) {
        result += characters.charAt(values[i] % characters.length);
      }
      return result;
    }

    // Helper function for PKCE tests
    function base64UrlEncode(str: string): string {
      return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    it('should accept token exchange without redirect_uri when using PKCE', async () => {
      // Generate PKCE code verifier and challenge
      const codeVerifier = generateRandomString(43); // Recommended length
      const encoder = new TextEncoder();
      const data = encoder.encode(codeVerifier);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const codeChallenge = base64UrlEncode(String.fromCharCode(...hashArray));

      // First get an auth code with PKCE
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123` +
          `&code_challenge=${codeChallenge}&code_challenge_method=S256`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const url = new URL(location);
      const code = url.searchParams.get('code')!;

      // Now exchange the code without providing redirect_uri
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      // redirect_uri intentionally omitted
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
      params.append('code_verifier', codeVerifier);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      // Should succeed because redirect_uri is optional when using PKCE
      expect(tokenResponse.status).toBe(200);

      const tokens = await tokenResponse.json<any>();
      expect(tokens.access_token).toBeDefined();
      expect(tokens.refresh_token).toBeDefined();
      expect(tokens.token_type).toBe('bearer');
      expect(tokens.expires_in).toBe(3600);
    });

    it('should accept the access token for API requests', async () => {
      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();

      // Now use the access token for an API request
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${tokens.access_token}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);

      const apiData = await apiResponse.json<any>();
      expect(apiData.success).toBe(true);
      expect(apiData.user).toEqual({ userId: 'test-user-123', username: 'TestUser' });
    });
  });

  describe('Refresh Token Flow', () => {
    let clientId: string;
    let clientSecret: string;
    let refreshToken: string;

    // Helper to get through authorization and token exchange to get a refresh token
    async function getRefreshToken() {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      clientId = client.client_id;
      clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      refreshToken = tokens.refresh_token;
    }

    beforeEach(async () => {
      await getRefreshToken();
    });

    it('should issue new tokens with refresh token', async () => {
      // Use the refresh token to get a new access token
      const params = new URLSearchParams();
      params.append('grant_type', 'refresh_token');
      params.append('refresh_token', refreshToken);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const refreshResponse = await oauthProvider.fetch(refreshRequest, mockEnv, mockCtx);

      expect(refreshResponse.status).toBe(200);

      const newTokens = await refreshResponse.json<any>();
      expect(newTokens.access_token).toBeDefined();
      expect(newTokens.refresh_token).toBeDefined();
      expect(newTokens.refresh_token).not.toBe(refreshToken); // Should get a new refresh token

      // Verify we now have a new token in storage
      const tokenEntries = await mockEnv.OAUTH_KV.list({ prefix: 'token:' });
      expect(tokenEntries.keys.length).toBe(2); // The old one and the new one

      // Verify the grant was updated
      const grantEntries = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      const grantKey = grantEntries.keys[0].name;
      const grant = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });

      expect(grant.previousRefreshTokenId).toBeDefined(); // Old refresh token should be tracked
      expect(grant.refreshTokenId).toBeDefined(); // New refresh token should be set
    });

    it('should allow using the previous refresh token once', async () => {
      // Use the refresh token to get a new access token (first refresh)
      const params1 = new URLSearchParams();
      params1.append('grant_type', 'refresh_token');
      params1.append('refresh_token', refreshToken);
      params1.append('client_id', clientId);
      params1.append('client_secret', clientSecret);

      const refreshRequest1 = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params1.toString()
      );

      const refreshResponse1 = await oauthProvider.fetch(refreshRequest1, mockEnv, mockCtx);
      const newTokens1 = await refreshResponse1.json<any>();
      const newRefreshToken = newTokens1.refresh_token;

      // Now try to use the original refresh token again (simulating a retry after failure)
      const params2 = new URLSearchParams();
      params2.append('grant_type', 'refresh_token');
      params2.append('refresh_token', refreshToken); // Original token
      params2.append('client_id', clientId);
      params2.append('client_secret', clientSecret);

      const refreshRequest2 = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params2.toString()
      );

      const refreshResponse2 = await oauthProvider.fetch(refreshRequest2, mockEnv, mockCtx);

      // The request should succeed
      expect(refreshResponse2.status).toBe(200);

      const newTokens2 = await refreshResponse2.json<any>();
      expect(newTokens2.access_token).toBeDefined();
      expect(newTokens2.refresh_token).toBeDefined();

      // Now the grant should have the newest refresh token and the token from the first refresh
      // as the previous token
      const grantEntries = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      const grantKey = grantEntries.keys[0].name;
      const grant = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });

      // The previousRefreshTokenId should now be from the first refresh, not the original
      expect(grant.previousRefreshTokenId).toBeDefined();
    });
  });

  describe('Token Exchange Flow', () => {
    let clientId: string;
    let clientSecret: string;
    let accessToken: string;
    let originalClientId: string;
    let originalClientSecret: string;

    // Helper to get an access token for testing
    async function getAccessToken() {
      // Create the original client (the one that got the token)
      const originalClientData = {
        redirect_uris: ['https://original.example.com/callback'],
        client_name: 'Original Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest1 = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(originalClientData)
      );

      const registerResponse1 = await oauthProvider.fetch(registerRequest1, mockEnv, mockCtx);
      const originalClient = await registerResponse1.json<any>();
      originalClientId = originalClient.client_id;
      originalClientSecret = originalClient.client_secret;

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${originalClientId}` +
          `&redirect_uri=${encodeURIComponent('https://original.example.com/callback')}` +
          `&scope=read%20write%20admin&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', 'https://original.example.com/callback');
      params.append('client_id', originalClientId);
      params.append('client_secret', originalClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      accessToken = tokens.access_token;
    }

    // Helper to create a different client (the one making the exchange request)
    async function createExchangeClient() {
      const clientData = {
        redirect_uris: ['https://exchange.example.com/callback'],
        client_name: 'Exchange Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      clientId = client.client_id;
      clientSecret = client.client_secret;
    }

    beforeEach(async () => {
      await getAccessToken();
      await createExchangeClient();
    });

    it('should exchange an access token for a new one via HTTP endpoint', async () => {
      const params = new URLSearchParams();
      params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params.append('subject_token', accessToken);
      params.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params.append('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params.toString()
      );

      const exchangeResponse = await oauthProvider.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(exchangeResponse.status).toBe(200);

      const newTokens = await exchangeResponse.json<any>();
      expect(newTokens.access_token).toBeDefined();
      expect(newTokens.access_token).not.toBe(accessToken); // Should be a new token
      expect(newTokens.token_type).toBe('bearer');
      expect(newTokens.issued_token_type).toBe('urn:ietf:params:oauth:token-type:access_token');
      expect(newTokens.expires_in).toBeDefined();
      expect(newTokens.scope).toBe('read write admin'); // Should preserve original scopes

      // Verify new token works
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${newTokens.access_token}`,
      });
      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);
      expect(apiResponse.status).toBe(200);

      // Verify original token still works
      const originalApiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });
      const originalApiResponse = await oauthProvider.fetch(originalApiRequest, mockEnv, mockCtx);
      expect(originalApiResponse.status).toBe(200);
    });

    it('should exchange token with narrowed scopes', async () => {
      const params = new URLSearchParams();
      params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params.append('subject_token', accessToken);
      params.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params.append('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params.append('scope', 'read write'); // Narrow from 'read write admin'

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params.toString()
      );

      const exchangeResponse = await oauthProvider.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(exchangeResponse.status).toBe(200);

      const newTokens = await exchangeResponse.json<any>();
      expect(newTokens.scope).toBe('read write'); // Should have narrowed scopes
    });

    it('should silently remove invalid scopes from token exchange', async () => {
      const params = new URLSearchParams();
      params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params.append('subject_token', accessToken);
      params.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params.append('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params.append('scope', 'read write admin delete'); // 'delete' not in original, should be silently removed

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params.toString()
      );

      const exchangeResponse = await oauthProvider.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(exchangeResponse.status).toBe(200);

      const newTokens = await exchangeResponse.json<any>();
      // Should return only valid scopes, invalid 'delete' scope should be silently removed
      expect(newTokens.scope).toBe('read write admin');
    });

    it('should exchange token with different audience/resource', async () => {
      // First, get a token with a resource
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${originalClientId}` +
          `&redirect_uri=${encodeURIComponent('https://original.example.com/callback')}` +
          `&scope=read%20write&resource=${encodeURIComponent('https://api1.example.com')}` +
          `&resource=${encodeURIComponent('https://api2.example.com')}&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      const params1 = new URLSearchParams();
      params1.append('grant_type', 'authorization_code');
      params1.append('code', code);
      params1.append('redirect_uri', 'https://original.example.com/callback');
      params1.append('client_id', originalClientId);
      params1.append('client_secret', originalClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params1.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      const tokenWithResource = tokens.access_token;

      // Now exchange with a narrowed resource
      const params2 = new URLSearchParams();
      params2.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params2.append('subject_token', tokenWithResource);
      params2.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params2.append('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params2.append('resource', 'https://api1.example.com'); // Narrow to one resource

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params2.toString()
      );

      const exchangeResponse = await oauthProvider.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(exchangeResponse.status).toBe(200);

      const newTokens = await exchangeResponse.json<any>();
      expect(newTokens.resource).toBe('https://api1.example.com');
    });

    it('should reject token exchange with invalid resource', async () => {
      // Get a token with a resource
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${originalClientId}` +
          `&redirect_uri=${encodeURIComponent('https://original.example.com/callback')}` +
          `&scope=read%20write&resource=${encodeURIComponent('https://api1.example.com')}&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      const params1 = new URLSearchParams();
      params1.append('grant_type', 'authorization_code');
      params1.append('code', code);
      params1.append('redirect_uri', 'https://original.example.com/callback');
      params1.append('client_id', originalClientId);
      params1.append('client_secret', originalClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params1.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      const tokenWithResource = tokens.access_token;

      // Try to exchange with a resource not in the original grant
      const params2 = new URLSearchParams();
      params2.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params2.append('subject_token', tokenWithResource);
      params2.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params2.append('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params2.append('resource', 'https://api2.example.com'); // Not in original grant

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params2.toString()
      );

      const exchangeResponse = await oauthProvider.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(exchangeResponse.status).toBe(400);

      const error = await exchangeResponse.json<any>();
      expect(error.error).toBe('invalid_target');
    });

    it('should exchange token with shorter TTL', async () => {
      const params = new URLSearchParams();
      params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params.append('subject_token', accessToken);
      params.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params.append('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params.append('expires_in', '1800'); // 30 minutes instead of default 1 hour

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params.toString()
      );

      const exchangeResponse = await oauthProvider.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(exchangeResponse.status).toBe(200);

      const newTokens = await exchangeResponse.json<any>();
      expect(newTokens.expires_in).toBe(1800);
    });

    it('should reject token exchange with invalid subject token', async () => {
      const params = new URLSearchParams();
      params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params.append('subject_token', 'invalid:token:here');
      params.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params.append('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params.toString()
      );

      const exchangeResponse = await oauthProvider.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(exchangeResponse.status).toBe(400);

      const error = await exchangeResponse.json<any>();
      expect(error.error).toBe('invalid_grant');
    });

    it('should reject token exchange without subject_token', async () => {
      const params = new URLSearchParams();
      params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params.append('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params.toString()
      );

      const exchangeResponse = await oauthProvider.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(exchangeResponse.status).toBe(400);

      const error = await exchangeResponse.json<any>();
      expect(error.error).toBe('invalid_request');
    });

    it('should reject token exchange with unsupported subject_token_type', async () => {
      const params = new URLSearchParams();
      params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params.append('subject_token', accessToken);
      params.append('subject_token_type', 'urn:ietf:params:oauth:token-type:refresh_token');
      params.append('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params.toString()
      );

      const exchangeResponse = await oauthProvider.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(exchangeResponse.status).toBe(400);

      const error = await exchangeResponse.json<any>();
      expect(error.error).toBe('invalid_request');
    });

    it('should reject token exchange with unsupported requested_token_type', async () => {
      const params = new URLSearchParams();
      params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params.append('subject_token', accessToken);
      params.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params.append('requested_token_type', 'urn:ietf:params:oauth:token-type:refresh_token');

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params.toString()
      );

      const exchangeResponse = await oauthProvider.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(exchangeResponse.status).toBe(400);

      const error = await exchangeResponse.json<any>();
      expect(error.error).toBe('invalid_request');
    });

    it('should exchange token via OAuthHelpers.exchangeToken', async () => {
      const helpers = mockEnv.OAUTH_PROVIDER as OAuthHelpers;

      const newToken = await helpers.exchangeToken({
        subjectToken: accessToken,
      });

      expect(newToken.access_token).toBeDefined();
      expect(newToken.access_token).not.toBe(accessToken);
      expect(newToken.token_type).toBe('bearer');
      expect(newToken.expires_in).toBeDefined();
    });

    it('should exchange token via OAuthHelpers with narrowed scopes', async () => {
      const helpers = mockEnv.OAUTH_PROVIDER as OAuthHelpers;

      const newToken = await helpers.exchangeToken({
        subjectToken: accessToken,
        scope: ['read', 'write'],
      });

      expect(newToken.scope).toBe('read write');
    });

    it('should exchange token via OAuthHelpers with different audience', async () => {
      // Get a token with resource first
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${originalClientId}` +
          `&redirect_uri=${encodeURIComponent('https://original.example.com/callback')}` +
          `&scope=read%20write&resource=${encodeURIComponent('https://api1.example.com')}` +
          `&resource=${encodeURIComponent('https://api2.example.com')}&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', 'https://original.example.com/callback');
      params.append('client_id', originalClientId);
      params.append('client_secret', originalClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      const tokenWithResource = tokens.access_token;

      const helpers = mockEnv.OAUTH_PROVIDER as OAuthHelpers;

      const newToken = await helpers.exchangeToken({
        subjectToken: tokenWithResource,
        aud: 'https://api1.example.com',
      });

      expect(newToken.resource).toBe('https://api1.example.com');
    });

    it('should exchange token via OAuthHelpers with custom TTL', async () => {
      const helpers = mockEnv.OAUTH_PROVIDER as OAuthHelpers;

      const newToken = await helpers.exchangeToken({
        subjectToken: accessToken,
        expiresIn: 1800,
      });

      expect(newToken.expires_in).toBe(1800);
    });

    it('should reject OAuthHelpers.exchangeToken with invalid token', async () => {
      const helpers = mockEnv.OAUTH_PROVIDER as OAuthHelpers;

      await expect(
        helpers.exchangeToken({
          subjectToken: 'invalid:token:here',
        })
      ).rejects.toThrow();
    });

    it('should silently remove invalid scopes from OAuthHelpers.exchangeToken', async () => {
      const helpers = mockEnv.OAUTH_PROVIDER as OAuthHelpers;

      const tokenResponse = await helpers.exchangeToken({
        subjectToken: accessToken,
        scope: ['read', 'write', 'admin', 'delete'], // 'delete' not in original, should be silently removed
      });

      // Should return only valid scopes, invalid 'delete' scope should be silently removed
      expect(tokenResponse.scope).toBe('read write admin');
    });

    it('should call tokenExchangeCallback during token exchange', async () => {
      let callbackInvoked = false;
      let callbackOptions: any = null;

      const providerWithCallback = new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        allowTokenExchangeGrant: true,
        tokenExchangeCallback: async (options) => {
          callbackInvoked = true;
          callbackOptions = options;
          return {
            accessTokenProps: { ...options.props, exchanged: true },
          };
        },
      });

      // Get a token with this provider
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${originalClientId}` +
          `&redirect_uri=${encodeURIComponent('https://original.example.com/callback')}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await providerWithCallback.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      const params1 = new URLSearchParams();
      params1.append('grant_type', 'authorization_code');
      params1.append('code', code);
      params1.append('redirect_uri', 'https://original.example.com/callback');
      params1.append('client_id', originalClientId);
      params1.append('client_secret', originalClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params1.toString()
      );

      const tokenResponse = await providerWithCallback.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      const tokenToExchange = tokens.access_token;

      // Reset callback tracking before token exchange
      callbackInvoked = false;
      callbackOptions = null;

      // Now exchange it
      const params2 = new URLSearchParams();
      params2.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
      params2.append('subject_token', tokenToExchange);
      params2.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
      params2.append('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token');

      const exchangeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        params2.toString()
      );

      await providerWithCallback.fetch(exchangeRequest, mockEnv, mockCtx);

      expect(callbackInvoked).toBe(true);
      expect(callbackOptions).toBeDefined();
      expect(callbackOptions.grantType).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
      expect(callbackOptions.scope).toEqual(['read', 'write']); // Grant scopes
      expect(callbackOptions.requestedScope).toEqual(['read', 'write']); // Requested scopes (no downscoping in this test)
    });
  });

  describe('Refresh Token TTL', () => {
    let clientId: string;
    let clientSecret: string;
    let redirectUri: string;

    beforeEach(async () => {
      // Create a client for testing
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      clientId = client.client_id;
      clientSecret = client.client_secret;
      redirectUri = 'https://client.example.com/callback';
    });

    it('should not issue refresh token when TTL is 0', async () => {
      // Create provider with refreshTokenTTL = 0 (no refresh tokens)
      const providerNoRefresh = new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        accessTokenTTL: 3600,
        refreshTokenTTL: 0, // No refresh tokens
      });

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await providerNoRefresh.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await providerNoRefresh.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();

      // Should have access token but no refresh token
      expect(tokens.access_token).toBeDefined();
      expect(tokens.expires_in).toBe(3600);
      expect(tokens.refresh_token).toBeUndefined();
    });

    it('should allow callback to enable refresh tokens when globally disabled', async () => {
      // Create provider with globally disabled refresh tokens, but callback can enable them
      const providerWithCallback = new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        accessTokenTTL: 3600,
        refreshTokenTTL: 0, // Globally disabled
        tokenExchangeCallback: async (options) => {
          if (options.grantType === 'authorization_code') {
            // Enable refresh tokens for this specific case
            return {
              newProps: { ...options.props, specialUser: true },
              refreshTokenTTL: 7200, // Enable with 2 hour TTL
            };
          }
          return {};
        },
      });

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await providerWithCallback.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await providerWithCallback.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();

      // Should have both access token AND refresh token (callback enabled it)
      expect(tokens.access_token).toBeDefined();
      expect(tokens.expires_in).toBe(3600);
      expect(tokens.refresh_token).toBeDefined(); // Callback override worked!

      // Verify the grant has the correct TTL
      const grantEntries = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      const grantKey = grantEntries.keys[0].name;
      const grant = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });
      expect(grant.expiresAt).toBeDefined();
      const now = Math.floor(Date.now() / 1000);
      expect(grant.expiresAt).toBeGreaterThan(now);
      expect(grant.expiresAt).toBeLessThanOrEqual(now + 7200);

      // Verify props were updated
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${tokens.access_token}`,
      });
      const apiResponse = await providerWithCallback.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json<any>();
      expect(apiData.user.specialUser).toBe(true);
    });

    it('should set refresh token expiration when global TTL is configured', async () => {
      // Create provider with refresh token TTL
      const providerWithTTL = new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        accessTokenTTL: 3600,
        refreshTokenTTL: 7200, // 2 hours
      });

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await providerWithTTL.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await providerWithTTL.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();

      // Check that the grant has the refresh token expiration set
      const grantEntries = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      const grantKey = grantEntries.keys[0].name;
      const grant = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });

      expect(grant.expiresAt).toBeDefined();
      const now = Math.floor(Date.now() / 1000);
      expect(grant.expiresAt).toBeGreaterThan(now);
      expect(grant.expiresAt).toBeLessThanOrEqual(now + 7200);
    });

    it('should reject expired refresh tokens', async () => {
      // Create provider with very short refresh token TTL
      const providerWithShortTTL = new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        accessTokenTTL: 3600,
        refreshTokenTTL: 1, // 1 second - very short for testing
      });

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await providerWithShortTTL.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await providerWithShortTTL.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      const refreshToken = tokens.refresh_token;

      // Wait for the token to expire
      await new Promise((resolve) => setTimeout(resolve, 1500));

      // Try to use the expired refresh token
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', refreshToken);
      refreshParams.append('client_id', clientId);
      refreshParams.append('client_secret', clientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await providerWithShortTTL.fetch(refreshRequest, mockEnv, mockCtx);

      expect(refreshResponse.status).toBe(400);
      const error = await refreshResponse.json<any>();
      expect(error.error).toBe('invalid_grant');
      expect(error.error_description).toBe('Refresh token has expired');
    });

    it('should allow overriding refresh token TTL via callback', async () => {
      // Create provider with callback that sets custom TTL
      const providerWithCallback = new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        accessTokenTTL: 3600,
        refreshTokenTTL: 86400, // Default: 24 hours
        tokenExchangeCallback: async (options) => {
          if (options.grantType === 'authorization_code') {
            // Set shorter TTL for authorization code exchange
            return { refreshTokenTTL: 3600 }; // 1 hour
          }
          return {};
        },
      });

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await providerWithCallback.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await providerWithCallback.fetch(tokenRequest, mockEnv, mockCtx);
      await tokenResponse.json<any>();

      // Check that the grant has the custom TTL
      const grantEntries = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      const grantKey = grantEntries.keys[0].name;
      const grant = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });

      expect(grant.expiresAt).toBeDefined();
      const now = Math.floor(Date.now() / 1000);
      // Should be approximately 1 hour, not 24 hours
      expect(grant.expiresAt).toBeLessThanOrEqual(now + 3600);
      expect(grant.expiresAt).toBeGreaterThan(now + 3500); // Allow some margin
    });

    it('should preserve refresh token expiration during token rotation', async () => {
      // Create provider with refresh token TTL
      const providerWithTTL = new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        accessTokenTTL: 3600,
        refreshTokenTTL: 7200, // 2 hours
      });

      // Get initial tokens
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await providerWithTTL.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await providerWithTTL.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();

      // Get the original expiration time
      const grantEntries1 = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      const grantKey = grantEntries1.keys[0].name;
      const grant1 = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });
      const originalExpiration = grant1.expiresAt;

      // Do a refresh without specifying new TTL
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', tokens.refresh_token);
      refreshParams.append('client_id', clientId);
      refreshParams.append('client_secret', clientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await providerWithTTL.fetch(refreshRequest, mockEnv, mockCtx);
      expect(refreshResponse.status).toBe(200);

      // Check that expiration is preserved
      const grant2 = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });
      expect(grant2.expiresAt).toBe(originalExpiration);
    });

    it('should reject callback attempts to change TTL during refresh', async () => {
      // Create provider with callback that tries to change TTL during refresh
      const providerWithBadCallback = new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        accessTokenTTL: 3600,
        refreshTokenTTL: 7200,
        tokenExchangeCallback: async (options) => {
          if (options.grantType === 'refresh_token') {
            // This should cause an error
            return { refreshTokenTTL: 3600 };
          }
          return {};
        },
      });

      // Get initial tokens through the full flow
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await providerWithBadCallback.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      const tokenParams = new URLSearchParams();
      tokenParams.append('grant_type', 'authorization_code');
      tokenParams.append('code', code);
      tokenParams.append('redirect_uri', redirectUri);
      tokenParams.append('client_id', clientId);
      tokenParams.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        tokenParams.toString()
      );

      const tokenResponse = await providerWithBadCallback.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      expect(tokens.refresh_token).toBeDefined();

      // Try to refresh - this should return an error
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', tokens.refresh_token);
      refreshParams.append('client_id', clientId);
      refreshParams.append('client_secret', clientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await providerWithBadCallback.fetch(refreshRequest, mockEnv, mockCtx);
      expect(refreshResponse.status).toBe(400);

      const error = await refreshResponse.json<any>();
      expect(error.error).toBe('invalid_request');
      expect(error.error_description).toBe('refreshTokenTTL cannot be changed during refresh token exchange');
    });
  });

  describe('Token Validation and API Access', () => {
    let accessToken: string;

    // Helper to get through authorization and token exchange to get an access token
    async function getAccessToken() {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      accessToken = tokens.access_token;
    }

    beforeEach(async () => {
      await getAccessToken();
    });

    it('should reject API requests without a token', async () => {
      const apiRequest = createMockRequest('https://example.com/api/test');

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);

      const error = await apiResponse.json<any>();
      expect(error.error).toBe('invalid_token');
    });

    it('should reject API requests with an invalid token', async () => {
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer invalid-token',
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);

      const error = await apiResponse.json<any>();
      expect(error.error).toBe('invalid_token');
    });

    it('should accept valid token and pass props to API handler', async () => {
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);

      const data = await apiResponse.json<any>();
      expect(data.success).toBe(true);
      expect(data.user).toEqual({ userId: 'test-user-123', username: 'TestUser' });
    });
  });

  describe('Audience Validation (RFC 7519 Section 4.1.3)', () => {
    // Helper to get access token with resource parameter (RFC 8707)
    async function getAccessTokenWithResource(resource?: string | string[]) {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens with resource parameter (RFC 8707)
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
      if (resource !== undefined) {
        // RFC 8707: multiple resources are sent as separate parameters
        if (Array.isArray(resource)) {
          resource.forEach((r) => params.append('resource', r));
        } else {
          params.append('resource', resource);
        }
      }

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<{ access_token: string }>();
      return tokens.access_token;
    }

    it('should accept token with matching audience (string)', async () => {
      const accessToken = await getAccessTokenWithResource('https://example.com');

      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);
      const data = await apiResponse.json<any>();
      expect(data.success).toBe(true);
      expect(data.user).toEqual({ userId: 'test-user-123', username: 'TestUser' });
    });

    it('should accept token with matching audience in array', async () => {
      const accessToken = await getAccessTokenWithResource(['https://example.com', 'https://other.example.com']);

      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);
      const data = await apiResponse.json<{ success: boolean }>();
      expect(data.success).toBe(true);
    });

    it('should accept token with multiple resources at all specified resource servers (E2E)', async () => {
      // Request token for two resource servers
      const accessToken = await getAccessTokenWithResource(['https://api1.example.com', 'https://api2.example.com']);

      // Should work at first resource server
      const api1Request = createMockRequest('https://api1.example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });
      const api1Response = await oauthProvider.fetch(api1Request, mockEnv, mockCtx);
      expect(api1Response.status).toBe(200);
      const api1Data = await api1Response.json<{ success: boolean }>();
      expect(api1Data.success).toBe(true);

      // Should also work at second resource server
      const api2Request = createMockRequest('https://api2.example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });
      const api2Response = await oauthProvider.fetch(api2Request, mockEnv, mockCtx);
      expect(api2Response.status).toBe(200);
      const api2Data = await api2Response.json<{ success: boolean }>();
      expect(api2Data.success).toBe(true);

      // Should fail at third resource server not in audience
      const api3Request = createMockRequest('https://api3.example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });
      const api3Response = await oauthProvider.fetch(api3Request, mockEnv, mockCtx);
      expect(api3Response.status).toBe(401);
      const api3Error = await api3Response.json<{ error: string }>();
      expect(api3Error.error).toBe('invalid_token');
    });

    it('should accept token without audience claim (backward compatibility)', async () => {
      const accessToken = await getAccessTokenWithResource(undefined);

      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);
      const data = await apiResponse.json<{ success: boolean }>();
      expect(data.success).toBe(true);
    });

    it('should reject token with wrong audience (HTTP 401)', async () => {
      const accessToken = await getAccessTokenWithResource('https://wrong-server.com');

      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);

      const wwwAuth = apiResponse.headers.get('WWW-Authenticate');
      expect(wwwAuth).toContain('Bearer');
      expect(wwwAuth).toContain('error="invalid_token"');
      expect(wwwAuth).toContain('Invalid audience');

      const error = await apiResponse.json<{ error: string; error_description: string }>();
      expect(error.error).toBe('invalid_token');
      expect(error.error_description).toContain('audience');
    });

    it('should reject token when resource server not in audience array', async () => {
      const accessToken = await getAccessTokenWithResource(['https://other1.com', 'https://other2.com']);

      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);

      const error = await apiResponse.json<{ error: string; error_description: string }>();
      expect(error.error).toBe('invalid_token');
    });

    it('should reject token with audience mismatch on different host', async () => {
      const accessToken = await getAccessTokenWithResource('https://api.example.com');

      const apiRequest = createMockRequest('https://api2.example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);
      const error = await apiResponse.json<{ error: string; error_description: string }>();
      expect(error.error).toBe('invalid_token');
    });

    it('should reject token with audience mismatch on different protocol', async () => {
      const accessToken = await getAccessTokenWithResource('http://example.com');

      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);
      const error = await apiResponse.json<{ error: string; error_description: string }>();
      expect(error.error).toBe('invalid_token');
    });

    it('should reject token with different port', async () => {
      // Token issued for port 8080
      const accessToken = await getAccessTokenWithResource('https://example.com:8080');

      // Request to default port (443)
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);
      const error = await apiResponse.json<any>();
      expect(error.error).toBe('invalid_token');
    });

    it('should reject token when ports do not match', async () => {
      // Token issued for default port
      const accessToken = await getAccessTokenWithResource('https://example.com');

      // Request to explicit port 8443
      const apiRequest = createMockRequest('https://example.com:8443/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);
      const error = await apiResponse.json<any>();
      expect(error.error).toBe('invalid_token');
    });

    it('should accept token with IPv6 resource URI', async () => {
      const accessToken = await getAccessTokenWithResource('https://[2001:db8::1]:8080');

      const apiRequest = createMockRequest('https://[2001:db8::1]:8080/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);
      const data = await apiResponse.json<any>();
      expect(data.success).toBe(true);
    });

    it('should reject token request with resource containing fragment (RFC 8707)', async () => {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Try to exchange with resource containing fragment
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
      params.append('resource', 'https://example.com/api#fragment');

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      expect(tokenResponse.status).toBe(400);
      const error = await tokenResponse.json<any>();
      expect(error.error).toBe('invalid_target');
      expect(error.error_description).toContain('fragment');
    });

    it('should reject token request with javascript: resource scheme', async () => {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Try to exchange with javascript: resource
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
      params.append('resource', 'javascript:alert(1)');

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      expect(tokenResponse.status).toBe(400);
      const error = await tokenResponse.json<any>();
      expect(error.error).toBe('invalid_target');
    });

    it('should reject token request with relative URI resource', async () => {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Try to exchange with relative URI resource
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
      params.append('resource', '/api/resource');

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      expect(tokenResponse.status).toBe(400);
      const error = await tokenResponse.json<any>();
      expect(error.error).toBe('invalid_target');
    });

    it('should use resource from authorization request when not provided in token request', async () => {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code WITH resource parameter
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&resource=${encodeURIComponent('https://api.example.com')}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange WITHOUT resource parameter in token request
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
      // No resource parameter here!

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      expect(tokenResponse.status).toBe(200);
      const tokens = await tokenResponse.json<any>();
      const accessToken = tokens.access_token;

      // Use token at the resource server specified in authorization request
      const apiRequest = createMockRequest('https://api.example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);
      expect(apiResponse.status).toBe(200);
      const data = await apiResponse.json<any>();
      expect(data.success).toBe(true);
    });

    it('should validate audience for external tokens with matching audience', async () => {
      const externalProvider = new OAuthProvider({
        apiRoute: ['/api/', 'https://example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write', 'profile'],
        resolveExternalToken: async ({ token }) => {
          if (token === 'external-token-with-audience') {
            return {
              props: { userId: 'external-user', source: 'external' },
              audience: 'https://example.com',
            };
          }
          return null;
        },
      });

      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer external-token-with-audience',
      });

      const apiResponse = await externalProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);
      const data = await apiResponse.json<any>();
      expect(data.success).toBe(true);
    });

    it('should reject external tokens with wrong audience', async () => {
      const externalProvider = new OAuthProvider({
        apiRoute: ['/api/', 'https://example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write', 'profile'],
        resolveExternalToken: async ({ token }) => {
          if (token === 'external-token-wrong-audience') {
            return {
              props: { userId: 'external-user', source: 'external' },
              audience: 'https://wrong-server.com',
            };
          }
          return null;
        },
      });

      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer external-token-wrong-audience',
      });

      const apiResponse = await externalProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);
      const error = await apiResponse.json<any>();
      expect(error.error).toBe('invalid_token');
      expect(error.error_description).toContain('audience');
    });
  });

  describe('Resource Parameter Downscoping (RFC 8707)', () => {
    it('should reject upscoping attempt (requesting resource not in authorization)', async () => {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code with resource=https://api1.example.com
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123&resource=https://api1.example.com`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Try to exchange with resource=https://api2.example.com (not in authorization!)
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
      params.append('resource', 'https://api2.example.com'); // Different resource - upscoping!

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      expect(tokenResponse.status).toBe(400);
      const error = await tokenResponse.json<any>();
      expect(error.error).toBe('invalid_target');
      expect(error.error_description).toContain('not included in the authorization request');
    });

    it('should allow downscoping (requesting subset of authorized resources)', async () => {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code with TWO resources
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123` +
          `&resource=https://api1.example.com&resource=https://api2.example.com`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange with only ONE resource (downscoping - subset of original)
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
      params.append('resource', 'https://api1.example.com'); // Subset - downscoping allowed!

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      expect(tokenResponse.status).toBe(200);
      const tokens = await tokenResponse.json<any>();
      expect(tokens.access_token).toBeDefined();
      expect(tokens.resource).toBe('https://api1.example.com');
    });
  });

  describe('CORS Support', () => {
    it('should handle CORS preflight for API requests', async () => {
      const preflightRequest = createMockRequest('https://example.com/api/test', 'OPTIONS', {
        Origin: 'https://client.example.com',
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'Authorization',
      });

      const preflightResponse = await oauthProvider.fetch(preflightRequest, mockEnv, mockCtx);

      expect(preflightResponse.status).toBe(204);
      expect(preflightResponse.headers.get('Access-Control-Allow-Origin')).toBe('https://client.example.com');
      expect(preflightResponse.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(preflightResponse.headers.get('Access-Control-Allow-Headers')).toContain('Authorization');
    });

    it('should add CORS headers to OAuth metadata discovery endpoint', async () => {
      const request = createMockRequest('https://example.com/.well-known/oauth-authorization-server', 'GET', {
        Origin: 'https://client.example.com',
      });

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(200);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://client.example.com');
      expect(response.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Headers')).toBe('Authorization, *');
      expect(response.headers.get('Access-Control-Max-Age')).toBe('86400');
    });

    it('should handle OPTIONS preflight for metadata discovery endpoint', async () => {
      const preflightRequest = createMockRequest(
        'https://example.com/.well-known/oauth-authorization-server',
        'OPTIONS',
        {
          Origin: 'https://spa.example.com',
          'Access-Control-Request-Method': 'GET',
        }
      );

      const response = await oauthProvider.fetch(preflightRequest, mockEnv, mockCtx);

      expect(response.status).toBe(204);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://spa.example.com');
      expect(response.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Headers')).toBe('Authorization, *');
      expect(response.headers.get('Access-Control-Max-Age')).toBe('86400');
      expect(response.headers.get('Content-Length')).toBe('0');
    });

    it('should add CORS headers to token endpoint responses', async () => {
      // First create a client and get auth code
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'CORS Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Now test token exchange with CORS
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Origin: 'https://webapp.example.com',
        },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      expect(tokenResponse.status).toBe(200);
      expect(tokenResponse.headers.get('Access-Control-Allow-Origin')).toBe('https://webapp.example.com');
      expect(tokenResponse.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(tokenResponse.headers.get('Access-Control-Allow-Headers')).toBe('Authorization, *');
      expect(tokenResponse.headers.get('Access-Control-Max-Age')).toBe('86400');
    });

    it('should handle OPTIONS preflight for token endpoint', async () => {
      const preflightRequest = createMockRequest('https://example.com/oauth/token', 'OPTIONS', {
        Origin: 'https://mobile.example.com',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type',
      });

      const response = await oauthProvider.fetch(preflightRequest, mockEnv, mockCtx);

      expect(response.status).toBe(204);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://mobile.example.com');
      expect(response.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Headers')).toBe('Authorization, *');
      expect(response.headers.get('Access-Control-Max-Age')).toBe('86400');
    });

    it('should add CORS headers to client registration endpoint', async () => {
      const clientData = {
        redirect_uris: ['https://newapp.example.com/callback'],
        client_name: 'New CORS Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        {
          'Content-Type': 'application/json',
          Origin: 'https://admin.example.com',
        },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(201);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://admin.example.com');
      expect(response.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Headers')).toBe('Authorization, *');
    });

    it('should handle OPTIONS preflight for client registration endpoint', async () => {
      const preflightRequest = createMockRequest('https://example.com/oauth/register', 'OPTIONS', {
        Origin: 'https://dashboard.example.com',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type, Authorization',
      });

      const response = await oauthProvider.fetch(preflightRequest, mockEnv, mockCtx);

      expect(response.status).toBe(204);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://dashboard.example.com');
      expect(response.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Headers')).toBe('Authorization, *');
    });

    it('should not add CORS headers when no Origin header is present', async () => {
      const request = createMockRequest('https://example.com/.well-known/oauth-authorization-server');
      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(200);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
      expect(response.headers.get('Access-Control-Allow-Methods')).toBeNull();
      expect(response.headers.get('Access-Control-Allow-Headers')).toBeNull();
    });

    it('should add CORS headers to API error responses', async () => {
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Origin: 'https://client.example.com',
        // No Authorization header - should get 401 error with CORS headers
      });

      const response = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(response.status).toBe(401);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://client.example.com');
      expect(response.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Headers')).toBe('Authorization, *');

      const error = await response.json<any>();
      expect(error.error).toBe('invalid_token');
    });

    it('should add CORS headers to token endpoint error responses', async () => {
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', 'invalid-code');
      params.append('client_id', 'invalid-client');

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Origin: 'https://evil.example.com',
        },
        params.toString()
      );

      const response = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      expect(response.status).toBe(401); // Should be an error
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://evil.example.com');
      expect(response.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Headers')).toBe('Authorization, *');
    });

    it('should not add CORS headers to default handler responses', async () => {
      const defaultRequest = createMockRequest('https://example.com/some-other-route', 'GET', {
        Origin: 'https://client.example.com',
      });

      const response = await oauthProvider.fetch(defaultRequest, mockEnv, mockCtx);

      expect(response.status).toBe(200);
      // CORS headers should NOT be added to default handler responses
      expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
      expect(response.headers.get('Access-Control-Allow-Methods')).toBeNull();
      expect(response.headers.get('Access-Control-Allow-Headers')).toBeNull();
    });
  });

  describe('Token Exchange Callback', () => {
    // Test with provider that has token exchange callback
    let oauthProviderWithCallback: OAuthProvider;
    let callbackInvocations: any[] = [];
    let mockEnv: ReturnType<typeof createMockEnv>;
    let mockCtx: MockExecutionContext;

    // Helper function to create a test OAuth provider with a token exchange callback
    function createProviderWithCallback() {
      callbackInvocations = [];

      const tokenExchangeCallback = async (options: any) => {
        // Record that the callback was called and with what arguments
        callbackInvocations.push({ ...options });

        // Return different props based on the grant type
        if (options.grantType === 'authorization_code') {
          return {
            accessTokenProps: {
              ...options.props,
              tokenSpecific: true,
              tokenUpdatedAt: 'auth_code_flow',
            },
            newProps: {
              ...options.props,
              grantUpdated: true,
            },
          };
        } else if (options.grantType === 'refresh_token') {
          return {
            accessTokenProps: {
              ...options.props,
              tokenSpecific: true,
              tokenUpdatedAt: 'refresh_token_flow',
            },
            newProps: {
              ...options.props,
              grantUpdated: true,
              refreshCount: (options.props.refreshCount || 0) + 1,
            },
          };
        }
      };

      return new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write', 'profile'],
        accessTokenTTL: 3600,
        allowImplicitFlow: true,
        tokenExchangeCallback,
      });
    }

    let clientId: string;
    let clientSecret: string;
    let redirectUri: string;

    // Helper to create a test client
    async function createTestClient() {
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProviderWithCallback.fetch(request, mockEnv, mockCtx);
      const client = await response.json<any>();

      clientId = client.client_id;
      clientSecret = client.client_secret;
      redirectUri = 'https://client.example.com/callback';
    }

    beforeEach(async () => {
      // Reset mocks before each test
      vi.resetAllMocks();

      // Create fresh instances for each test
      mockEnv = createMockEnv();
      mockCtx = new MockExecutionContext();

      // Create OAuth provider with test configuration and callback
      oauthProviderWithCallback = createProviderWithCallback();

      // Create a test client
      await createTestClient();
    });

    afterEach(() => {
      // Clean up KV storage after each test
      mockEnv.OAUTH_KV.clear();
    });

    it('should call the callback during authorization code flow', async () => {
      // First get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProviderWithCallback.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Reset callback invocations tracking before token exchange
      callbackInvocations = [];

      // Exchange code for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProviderWithCallback.fetch(tokenRequest, mockEnv, mockCtx);

      // Check that the token exchange was successful
      expect(tokenResponse.status).toBe(200);
      const tokens = await tokenResponse.json<any>();
      expect(tokens.access_token).toBeDefined();

      // Check that the callback was called once
      expect(callbackInvocations.length).toBe(1);

      // Check that callback was called with correct arguments
      const callbackArgs = callbackInvocations[0];
      expect(callbackArgs.grantType).toBe('authorization_code');
      expect(callbackArgs.clientId).toBe(clientId);
      expect(callbackArgs.props).toEqual({ userId: 'test-user-123', username: 'TestUser' });

      // Use the token to access API
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${tokens.access_token}`,
      });

      const apiResponse = await oauthProviderWithCallback.fetch(apiRequest, mockEnv, mockCtx);
      expect(apiResponse.status).toBe(200);

      // Check that the API received the token-specific props from the callback
      const apiData = await apiResponse.json<any>();
      expect(apiData.user).toEqual({
        userId: 'test-user-123',
        username: 'TestUser',
        tokenSpecific: true,
        tokenUpdatedAt: 'auth_code_flow',
      });
    });

    it('should call the callback during refresh token flow', async () => {
      // First get an auth code and exchange it for tokens
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProviderWithCallback.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange code for tokens
      const codeParams = new URLSearchParams();
      codeParams.append('grant_type', 'authorization_code');
      codeParams.append('code', code);
      codeParams.append('redirect_uri', redirectUri);
      codeParams.append('client_id', clientId);
      codeParams.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        codeParams.toString()
      );

      const tokenResponse = await oauthProviderWithCallback.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();

      // Reset the callback invocations tracking before refresh
      callbackInvocations = [];

      // Now use the refresh token
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', tokens.refresh_token);
      refreshParams.append('client_id', clientId);
      refreshParams.append('client_secret', clientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await oauthProviderWithCallback.fetch(refreshRequest, mockEnv, mockCtx);

      // Check that the refresh was successful
      expect(refreshResponse.status).toBe(200);
      const newTokens = await refreshResponse.json<any>();
      expect(newTokens.access_token).toBeDefined();

      // Check that the callback was called once
      expect(callbackInvocations.length).toBe(1);

      // Check that callback was called with correct arguments
      const callbackArgs = callbackInvocations[0];
      expect(callbackArgs.grantType).toBe('refresh_token');
      expect(callbackArgs.clientId).toBe(clientId);

      // The props are from the updated grant during auth code flow
      expect(callbackArgs.props).toEqual({
        userId: 'test-user-123',
        username: 'TestUser',
        grantUpdated: true,
      });

      // Use the new token to access API
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${newTokens.access_token}`,
      });

      const apiResponse = await oauthProviderWithCallback.fetch(apiRequest, mockEnv, mockCtx);
      expect(apiResponse.status).toBe(200);

      // Check that the API received the token-specific props from the refresh callback
      const apiData = await apiResponse.json<any>();
      expect(apiData.user).toEqual({
        userId: 'test-user-123',
        username: 'TestUser',
        grantUpdated: true,
        tokenSpecific: true,
        tokenUpdatedAt: 'refresh_token_flow',
      });

      // Do a second refresh to verify that grant props are properly updated
      const refresh2Params = new URLSearchParams();
      refresh2Params.append('grant_type', 'refresh_token');
      refresh2Params.append('refresh_token', newTokens.refresh_token);
      refresh2Params.append('client_id', clientId);
      refresh2Params.append('client_secret', clientSecret);

      // Reset the callback invocations before second refresh
      callbackInvocations = [];

      const refresh2Request = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refresh2Params.toString()
      );

      const refresh2Response = await oauthProviderWithCallback.fetch(refresh2Request, mockEnv, mockCtx);
      const newerTokens = await refresh2Response.json();

      // Check that the refresh count was incremented in the grant props
      expect(callbackInvocations.length).toBe(1);
      expect(callbackInvocations[0].props.refreshCount).toBe(1);
    });

    it('should update token props during refresh when explicitly provided', async () => {
      // Create a provider with a callback that returns both accessTokenProps and newProps
      // but with different values for each
      const differentPropsCallback = async (options: any) => {
        if (options.grantType === 'refresh_token') {
          return {
            accessTokenProps: {
              ...options.props,
              refreshed: true,
              tokenOnly: true,
            },
            newProps: {
              ...options.props,
              grantUpdated: true,
            },
          };
        }
        return undefined;
      };

      const refreshPropsProvider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        tokenExchangeCallback: differentPropsCallback,
      });

      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Refresh Props Test',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await refreshPropsProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const testClientId = client.client_id;
      const testClientSecret = client.client_secret;
      const testRedirectUri = 'https://client.example.com/callback';

      // Get an auth code and exchange it for tokens
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${testClientId}` +
          `&redirect_uri=${encodeURIComponent(testRedirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await refreshPropsProvider.fetch(authRequest, mockEnv, mockCtx);
      const code = new URL(authResponse.headers.get('Location')!).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', testRedirectUri);
      params.append('client_id', testClientId);
      params.append('client_secret', testClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await refreshPropsProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();

      // Now do a refresh token exchange
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', tokens.refresh_token);
      refreshParams.append('client_id', testClientId);
      refreshParams.append('client_secret', testClientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await refreshPropsProvider.fetch(refreshRequest, mockEnv, mockCtx);
      const newTokens = await refreshResponse.json<any>();

      // Use the new token to access API
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${newTokens.access_token}`,
      });

      const apiResponse = await refreshPropsProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json<any>();

      // The access token should contain the token-specific props from the refresh callback
      expect(apiData.user).toHaveProperty('refreshed', true);
      expect(apiData.user).toHaveProperty('tokenOnly', true);
      expect(apiData.user).not.toHaveProperty('grantUpdated');
    });

    it('should handle callback that returns only accessTokenProps or only newProps', async () => {
      // Create a provider with a callback that returns only accessTokenProps for auth code
      // and only newProps for refresh token
      // Note: With the enhanced implementation, when only newProps is returned
      // without accessTokenProps, the token props will inherit from newProps
      const propsCallback = async (options: any) => {
        if (options.grantType === 'authorization_code') {
          return {
            accessTokenProps: { ...options.props, tokenOnly: true },
          };
        } else if (options.grantType === 'refresh_token') {
          return {
            newProps: { ...options.props, grantOnly: true },
          };
        }
      };

      const specialProvider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        tokenExchangeCallback: propsCallback,
      });

      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Token Props Only Test',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await specialProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const testClientId = client.client_id;
      const testClientSecret = client.client_secret;
      const testRedirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${testClientId}` +
          `&redirect_uri=${encodeURIComponent(testRedirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await specialProvider.fetch(authRequest, mockEnv, mockCtx);
      const code = new URL(authResponse.headers.get('Location')!).searchParams.get('code')!;

      // Exchange code for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', testRedirectUri);
      params.append('client_id', testClientId);
      params.append('client_secret', testClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await specialProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();

      // Verify the token has the tokenOnly property when used for API access
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${tokens.access_token}`,
      });

      const apiResponse = await specialProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json<any>();
      expect(apiData.user.tokenOnly).toBe(true);

      // Now do a refresh token exchange
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', tokens.refresh_token);
      refreshParams.append('client_id', testClientId);
      refreshParams.append('client_secret', testClientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await specialProvider.fetch(refreshRequest, mockEnv, mockCtx);
      const newTokens = await refreshResponse.json<any>();

      // Use the new token to access API
      const api2Request = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${newTokens.access_token}`,
      });

      const api2Response = await specialProvider.fetch(api2Request, mockEnv, mockCtx);
      const api2Data = await api2Response.json<any>();

      // With the enhanced implementation, the token props now inherit from grant props
      // when only newProps is returned but accessTokenProps is not specified
      expect(api2Data.user).toEqual({
        userId: 'test-user-123',
        username: 'TestUser',
        grantOnly: true, // This is now included in the token props
      });
    });

    it('should allow customizing access token TTL via callback', async () => {
      // Create a provider with a callback that customizes TTL
      const customTtlCallback = async (options: any) => {
        if (options.grantType === 'refresh_token') {
          // Return custom TTL for the access token
          return {
            accessTokenProps: { ...options.props, customTtl: true },
            accessTokenTTL: 7200, // 2 hours instead of default
          };
        }
        return undefined;
      };

      const customTtlProvider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        accessTokenTTL: 3600, // Default 1 hour
        tokenExchangeCallback: customTtlCallback,
      });

      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Custom TTL Test',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await customTtlProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const testClientId = client.client_id;
      const testClientSecret = client.client_secret;
      const testRedirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${testClientId}` +
          `&redirect_uri=${encodeURIComponent(testRedirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await customTtlProvider.fetch(authRequest, mockEnv, mockCtx);
      const code = new URL(authResponse.headers.get('Location')!).searchParams.get('code')!;

      // Exchange code for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', testRedirectUri);
      params.append('client_id', testClientId);
      params.append('client_secret', testClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await customTtlProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();

      // Now do a refresh
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', tokens.refresh_token);
      refreshParams.append('client_id', testClientId);
      refreshParams.append('client_secret', testClientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await customTtlProvider.fetch(refreshRequest, mockEnv, mockCtx);
      const newTokens = await refreshResponse.json<any>();

      // Verify that the TTL is from the callback, not the default
      expect(newTokens.expires_in).toBe(7200);

      // Verify the token contains our custom property
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${newTokens.access_token}`,
      });

      const apiResponse = await customTtlProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json<any>();
      expect(apiData.user.customTtl).toBe(true);
    });

    it('should handle callback that returns undefined (keeping original props)', async () => {
      // Create a provider with a callback that returns undefined
      const noopCallback = async (options: any) => {
        // Don't return anything, which should keep the original props
        return undefined;
      };

      const noopProvider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        tokenExchangeCallback: noopCallback,
      });

      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Noop Callback Test',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await noopProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const testClientId = client.client_id;
      const testClientSecret = client.client_secret;
      const testRedirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${testClientId}` +
          `&redirect_uri=${encodeURIComponent(testRedirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await noopProvider.fetch(authRequest, mockEnv, mockCtx);
      const code = new URL(authResponse.headers.get('Location')!).searchParams.get('code')!;

      // Exchange code for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', testRedirectUri);
      params.append('client_id', testClientId);
      params.append('client_secret', testClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await noopProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();

      // Verify the token has the original props when used for API access
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${tokens.access_token}`,
      });

      const apiResponse = await noopProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json<any>();

      // The props should be the original ones (no change)
      expect(apiData.user).toEqual({ userId: 'test-user-123', username: 'TestUser' });
    });

    it('should correctly handle the previous refresh token when callback updates grant props', async () => {
      // This test verifies fixes for two bugs:
      // 1. previousRefreshTokenWrappedKey not being re-wrapped when grant props change
      // 2. accessTokenProps not inheriting from newProps when only newProps is returned
      let callCount = 0;
      const propUpdatingCallback = async (options: any) => {
        callCount++;
        if (options.grantType === 'refresh_token') {
          const updatedProps = {
            ...options.props,
            updatedCount: (options.props.updatedCount || 0) + 1,
          };

          // Only return newProps to test that accessTokenProps will inherit from it
          return {
            // Return new props to trigger the re-encryption with a new key
            newProps: updatedProps,
            // Intentionally not setting accessTokenProps to verify inheritance works
          };
        }
        return undefined;
      };

      const testProvider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        tokenExchangeCallback: propUpdatingCallback,
      });

      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Key-Rewrapping Test',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await testProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const testClientId = client.client_id;
      const testClientSecret = client.client_secret;
      const testRedirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${testClientId}` +
          `&redirect_uri=${encodeURIComponent(testRedirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await testProvider.fetch(authRequest, mockEnv, mockCtx);
      const code = new URL(authResponse.headers.get('Location')!).searchParams.get('code')!;

      // Exchange code for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', testRedirectUri);
      params.append('client_id', testClientId);
      params.append('client_secret', testClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await testProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      const refreshToken = tokens.refresh_token;

      // Reset the callback invocations before refresh
      callCount = 0;

      // First refresh - this will update the grant props and re-encrypt them with a new key
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', refreshToken);
      refreshParams.append('client_id', testClientId);
      refreshParams.append('client_secret', testClientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await testProvider.fetch(refreshRequest, mockEnv, mockCtx);
      expect(refreshResponse.status).toBe(200);

      // The callback should have been called once for the refresh
      expect(callCount).toBe(1);

      // Get the new tokens from the first refresh
      const newTokens = await refreshResponse.json<any>();

      // Get the refresh token's corresponding token data to verify it has the updated props
      const apiRequest1 = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${newTokens.access_token}`,
      });

      const apiResponse1 = await testProvider.fetch(apiRequest1, mockEnv, mockCtx);
      const apiData1 = await apiResponse1.json<any>();

      // Print the actual API response to debug
      console.log('First API response:', JSON.stringify(apiData1));

      // Verify that the token has the updated props (updatedCount should be 1)
      expect(apiData1.user.updatedCount).toBe(1);

      // Reset callCount before the second refresh
      callCount = 0;

      // Now try to use the SAME refresh token again (which should work once due to token rotation)
      // With the bug, this would fail because previousRefreshTokenWrappedKey wasn't re-wrapped with the new key
      const secondRefreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString() // Using same params with the same refresh token
      );

      const secondRefreshResponse = await testProvider.fetch(secondRefreshRequest, mockEnv, mockCtx);

      // With the bug, this would fail with an error.
      // When fixed, it should succeed because the previous refresh token is still valid once.
      expect(secondRefreshResponse.status).toBe(200);

      const secondTokens = await secondRefreshResponse.json<any>();
      expect(secondTokens.access_token).toBeDefined();

      // The callback should have been called again
      expect(callCount).toBe(1);

      // Use the token to access API and verify it has the updated props
      const apiRequest2 = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${secondTokens.access_token}`,
      });

      const apiResponse2 = await testProvider.fetch(apiRequest2, mockEnv, mockCtx);
      const apiData2 = await apiResponse2.json<any>();

      // The updatedCount should be 2 now (incremented again during the second refresh)
      expect(apiData2.user.updatedCount).toBe(2);
    });
  });

  describe('Error Handling with onError Callback', () => {
    it('should use the default onError callback that logs a warning', async () => {
      // Spy on console.warn to check default behavior
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      // Create a request that will trigger an error
      const invalidTokenRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer invalid-token',
      });

      const response = await oauthProvider.fetch(invalidTokenRequest, mockEnv, mockCtx);

      // Verify the error response
      expect(response.status).toBe(401);
      const error = await response.json<any>();
      expect(error.error).toBe('invalid_token');

      // Verify the default onError callback was triggered and logged a warning
      expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('OAuth error response: 401 invalid_token'));

      // Restore the spy
      consoleWarnSpy.mockRestore();
    });

    it('should allow custom onError callback to modify the error response', async () => {
      // Create a provider with custom onError callback
      const customErrorProvider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        onError: ({ code, description, status }) => {
          // Return a completely different response
          return new Response(
            JSON.stringify({
              custom_error: true,
              original_code: code,
              custom_message: `Custom error handler: ${description}`,
            }),
            {
              status,
              headers: {
                'Content-Type': 'application/json',
                'X-Custom-Error': 'true',
              },
            }
          );
        },
      });

      // Create a request that will trigger an error
      const invalidTokenRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer invalid-token',
      });

      const response = await customErrorProvider.fetch(invalidTokenRequest, mockEnv, mockCtx);

      // Verify the custom error response
      expect(response.status).toBe(401); // Status should be preserved
      expect(response.headers.get('X-Custom-Error')).toBe('true');

      const error = await response.json<any>();
      expect(error.custom_error).toBe(true);
      expect(error.original_code).toBe('invalid_token');
      expect(error.custom_message).toContain('Custom error handler');
    });

    it('should use standard error response when onError returns void', async () => {
      // Create a provider with a callback that performs a side effect but doesn't return a response
      let callbackInvoked = false;
      const sideEffectProvider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        onError: () => {
          callbackInvoked = true;
          // No return - should use standard error response
        },
      });

      // Create a request that will trigger an error
      const invalidRequest = createMockRequest('https://example.com/oauth/token', 'POST', {
        'Content-Type': 'application/x-www-form-urlencoded',
      });

      const response = await sideEffectProvider.fetch(invalidRequest, mockEnv, mockCtx);

      // Verify the standard error response
      expect(response.status).toBe(401);
      const error = await response.json<any>();
      expect(error.error).toBe('invalid_client');

      // Verify callback was invoked
      expect(callbackInvoked).toBe(true);
    });
  });

  describe('OAuthHelpers', () => {
    it('should allow listing and revoking grants', async () => {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);

      // Create a grant by going through auth flow
      const clientId = (await mockEnv.OAUTH_KV.list({ prefix: 'client:' })).keys[0].name.substring(7);
      const redirectUri = 'https://client.example.com/callback';

      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      await oauthProvider.fetch(authRequest, mockEnv, mockCtx);

      // Ensure OAUTH_PROVIDER was injected
      expect(mockEnv.OAUTH_PROVIDER).not.toBeNull();

      // List grants for the user
      const grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('test-user-123');

      expect(grants.items.length).toBe(1);
      expect(grants.items[0].clientId).toBe(clientId);
      expect(grants.items[0].userId).toBe('test-user-123');
      expect(grants.items[0].metadata).toEqual({ testConsent: true });

      // Revoke the grant
      await mockEnv.OAUTH_PROVIDER!.revokeGrant(grants.items[0].id, 'test-user-123');

      // Verify grant was deleted
      const grantsAfterRevoke = await mockEnv.OAUTH_PROVIDER!.listUserGrants('test-user-123');
      expect(grantsAfterRevoke.items.length).toBe(0);
    });

    it('should allow listing, updating, and deleting clients', async () => {
      // First make a simple request to initialize the OAUTH_PROVIDER in the environment
      const initRequest = createMockRequest('https://example.com/');
      await oauthProvider.fetch(initRequest, mockEnv, mockCtx);

      // Now OAUTH_PROVIDER should be initialized
      expect(mockEnv.OAUTH_PROVIDER).not.toBeNull();

      // Create a client
      const client = await mockEnv.OAUTH_PROVIDER!.createClient({
        redirectUris: ['https://client.example.com/callback'],
        clientName: 'Test Client',
        tokenEndpointAuthMethod: 'client_secret_basic',
      });

      expect(client.clientId).toBeDefined();
      expect(client.clientSecret).toBeDefined();

      // List clients
      const clients = await mockEnv.OAUTH_PROVIDER!.listClients();
      expect(clients.items.length).toBe(1);
      expect(clients.items[0].clientId).toBe(client.clientId);

      // Update client
      const updatedClient = await mockEnv.OAUTH_PROVIDER!.updateClient(client.clientId, {
        clientName: 'Updated Client Name',
      });

      expect(updatedClient).not.toBeNull();
      expect(updatedClient!.clientName).toBe('Updated Client Name');

      // Delete client
      await mockEnv.OAUTH_PROVIDER!.deleteClient(client.clientId);

      // Verify client was deleted
      const clientsAfterDelete = await mockEnv.OAUTH_PROVIDER!.listClients();
      expect(clientsAfterDelete.items.length).toBe(0);
    });
  });

  describe('External Token Resolution', () => {
    it('should reject unknown tokens when no resolveExternalToken callback is provided', async () => {
      // Create a provider without external token resolution
      const providerWithoutExternalValidation = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        // Intentionally no resolveExternalToken callback
      });

      // Try to access API with an unknown token format
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer external-token-from-another-service',
      });

      const apiResponse = await providerWithoutExternalValidation.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);
      const error = await apiResponse.json<any>();
      expect(error.error).toBe('invalid_token');
      expect(error.error_description).toBe('Invalid access token');
    });

    it('should successfully resolve external tokens and set props correctly', async () => {
      // Mock external token validation calls
      const externalTokenCalls: any[] = [];

      // Create a provider with external token resolution
      const providerWithExternalValidation = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        resolveExternalToken: async (input) => {
          // Record the call for verification
          externalTokenCalls.push({
            token: input.token,
            requestUrl: input.request.url,
            hasEnv: !!input.env,
          });

          // Simulate successful external token validation
          if (input.token === 'external-valid-token') {
            return {
              props: {
                userId: 'external-user-456',
                username: 'ExternalUser',
                source: 'external-oauth-server',
                permissions: ['read', 'write'],
              },
            };
          }

          // Return null for invalid tokens
          return null;
        },
      });

      // Try to access API with a valid external token
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer external-valid-token',
      });

      const apiResponse = await providerWithExternalValidation.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);
      const responseData = await apiResponse.json<any>();
      expect(responseData.success).toBe(true);
      expect(responseData.user).toEqual({
        userId: 'external-user-456',
        username: 'ExternalUser',
        source: 'external-oauth-server',
        permissions: ['read', 'write'],
      });

      // Verify the external token callback was called correctly
      expect(externalTokenCalls.length).toBe(1);
      expect(externalTokenCalls[0].token).toBe('external-valid-token');
      expect(externalTokenCalls[0].requestUrl).toBe('https://example.com/api/test');
      expect(externalTokenCalls[0].hasEnv).toBe(true);
    });

    it('should reject external tokens when callback returns null', async () => {
      // Mock external token validation calls
      const externalTokenCalls: any[] = [];

      // Create a provider with external token resolution that fails
      const providerWithFailingValidation = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        resolveExternalToken: async (input) => {
          externalTokenCalls.push({ token: input.token });

          // Simulate failed validation by returning null
          return null;
        },
      });

      // Try to access API with an invalid external token
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer invalid-external-token',
      });

      const apiResponse = await providerWithFailingValidation.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);
      const error = await apiResponse.json<any>();
      expect(error.error).toBe('invalid_token');
      expect(error.error_description).toBe('Invalid access token');

      // Verify the external token callback was called
      expect(externalTokenCalls.length).toBe(1);
      expect(externalTokenCalls[0].token).toBe('invalid-external-token');
    });

    it('should prioritize internal tokens over external validation', async () => {
      // Mock external token validation to track if it's called
      const externalTokenCalls: any[] = [];

      // Create a provider with external token resolution
      const providerWithExternalValidation = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        resolveExternalToken: async (input) => {
          externalTokenCalls.push({ token: input.token });
          return {
            props: { source: 'external', shouldNeverSeeThis: true },
          };
        },
      });

      // First, create a valid internal token through normal OAuth flow
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Internal Token Test',
        token_endpoint_auth_method: 'client_secret_basic',
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await providerWithExternalValidation.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json<any>();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=read%20write&state=xyz123`
      );

      const authResponse = await providerWithExternalValidation.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await providerWithExternalValidation.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json<any>();
      const internalAccessToken = tokens.access_token;

      // Now use the internal token - should NOT call external validation
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${internalAccessToken}`,
      });

      const apiResponse = await providerWithExternalValidation.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);
      const responseData = await apiResponse.json<any>();
      expect(responseData.user).toEqual({
        userId: 'test-user-123',
        username: 'TestUser',
      });

      // Verify external validation was NOT called for internal token
      expect(externalTokenCalls.length).toBe(0);
    });

    it('should handle external tokens that use the same format as internal tokens', async () => {
      // Mock external token validation
      const externalTokenCalls: any[] = [];

      const providerWithExternalValidation = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        resolveExternalToken: async (input) => {
          externalTokenCalls.push({ token: input.token });

          // Even if token looks like internal format, treat it as external
          if (input.token === 'user123:grant456:secret789') {
            return {
              props: {
                userId: 'external-user-from-mimicked-token',
                source: 'external-service',
              },
            };
          }

          return null;
        },
      });

      // Use a token that mimics internal format but doesn't exist in KV
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer user123:grant456:secret789',
      });

      const apiResponse = await providerWithExternalValidation.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);
      const responseData = await apiResponse.json<any>();
      expect(responseData.user).toEqual({
        userId: 'external-user-from-mimicked-token',
        source: 'external-service',
      });

      // Verify external validation was called
      expect(externalTokenCalls.length).toBe(1);
      expect(externalTokenCalls[0].token).toBe('user123:grant456:secret789');
    });

    it('should call external validation for non-internal token formats', async () => {
      const externalTokenCalls: any[] = [];

      const providerWithExternalValidation = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        resolveExternalToken: async (input) => {
          externalTokenCalls.push({ token: input.token });

          // Handle JWT-like tokens
          if (input.token.startsWith('eyJ')) {
            return {
              props: {
                userId: 'jwt-user',
                tokenType: 'jwt',
                issuer: 'external-auth-server',
              },
            };
          }

          // Handle simple bearer tokens
          if (input.token === 'simple-bearer-token') {
            return {
              props: {
                userId: 'bearer-user',
                tokenType: 'bearer',
              },
            };
          }

          return null;
        },
      });

      // Test JWT-like token
      const jwtRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mock.token',
      });

      const jwtResponse = await providerWithExternalValidation.fetch(jwtRequest, mockEnv, mockCtx);
      expect(jwtResponse.status).toBe(200);
      const jwtData = await jwtResponse.json<any>();
      expect(jwtData.user.tokenType).toBe('jwt');
      expect(jwtData.user.issuer).toBe('external-auth-server');

      // Test simple bearer token
      const bearerRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer simple-bearer-token',
      });

      const bearerResponse = await providerWithExternalValidation.fetch(bearerRequest, mockEnv, mockCtx);
      expect(bearerResponse.status).toBe(200);
      const bearerData = await bearerResponse.json<any>();
      expect(bearerData.user.tokenType).toBe('bearer');

      // Verify both external validations were called
      expect(externalTokenCalls.length).toBe(2);
      expect(externalTokenCalls[0].token).toBe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mock.token');
      expect(externalTokenCalls[1].token).toBe('simple-bearer-token');
    });

    it('should handle async external token validation properly', async () => {
      const externalTokenCalls: any[] = [];

      const providerWithAsyncValidation = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        resolveExternalToken: async (input) => {
          externalTokenCalls.push({ token: input.token, startTime: Date.now() });

          // Simulate async work (e.g., calling external API)
          await new Promise((resolve) => setTimeout(resolve, 15));

          if (input.token === 'async-valid-token') {
            return {
              props: {
                userId: 'async-user',
                validatedAt: new Date().toISOString(),
                asyncValidation: true,
              },
            };
          }

          return null;
        },
      });

      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer async-valid-token',
      });

      const startTime = Date.now();
      const apiResponse = await providerWithAsyncValidation.fetch(apiRequest, mockEnv, mockCtx);
      const endTime = Date.now();

      expect(apiResponse.status).toBe(200);
      const responseData = await apiResponse.json<any>();
      expect(responseData.user.asyncValidation).toBe(true);
      expect(responseData.user.validatedAt).toBeDefined();

      // Verify async call was made
      expect(externalTokenCalls.length).toBe(1);
      expect(endTime - startTime).toBeGreaterThanOrEqual(10); // Should take at least 10ms due to setTimeout
    });
  });

  describe('Token Revocation', () => {
    let clientId: string;
    let clientSecret: string;
    let redirectUri: string;

    beforeEach(async () => {
      redirectUri = 'https://client.example.com/callback';

      // Create a test client
      const clientResponse = await oauthProvider.fetch(
        createMockRequest(
          'https://example.com/oauth/register',
          'POST',
          {
            'Content-Type': 'application/json',
          },
          JSON.stringify({
            redirect_uris: [redirectUri],
            client_name: 'Test Client for Revocation',
            token_endpoint_auth_method: 'client_secret_basic',
          })
        ),
        mockEnv,
        mockCtx
      );

      expect(clientResponse.status).toBe(201);
      const client = await clientResponse.json<any>();
      clientId = client.client_id;
      clientSecret = client.client_secret;
    });

    it('should connect revokeGrant to token endpoint ', async () => {
      // Step 1: Get tokens through normal OAuth flow
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=read&state=test-state`
      );
      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const code = new URL(authResponse.headers.get('Location')!).searchParams.get('code');

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(redirectUri)}`
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      expect(tokenResponse.status).toBe(200);
      const tokens = await tokenResponse.json<any>();

      // Step 2:this should successfully revoke the token
      const revokeRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        `token=${tokens.access_token}`
      );

      const revokeResponse = await oauthProvider.fetch(revokeRequest, mockEnv, mockCtx);
      // Verify response doesn't contain unsupported_grant_type error
      const revokeResponseText = await revokeResponse.text();
      expect(revokeResponseText).not.toContain('unsupported_grant_type');

      // Step 3: Verify the access token is actually revoked
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${tokens.access_token}`,
      });
      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);
      expect(apiResponse.status).toBe(401); // Access token should no longer work

      // Step 4: Verify refresh token still works
      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        `grant_type=refresh_token&refresh_token=${tokens.refresh_token}`
      );

      const refreshResponse = await oauthProvider.fetch(refreshRequest, mockEnv, mockCtx);
      expect(refreshResponse.status).toBe(200); // Refresh token should still work
      const newTokens = await refreshResponse.json<any>();
      expect(newTokens.access_token).toBeDefined();
      expect(newTokens.refresh_token).toBeDefined();
    });
  });
});
