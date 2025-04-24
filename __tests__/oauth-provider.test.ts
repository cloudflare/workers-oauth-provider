import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { OAuthProvider, ClientInfo, AuthRequest, CompleteAuthorizationOptions } from '../src/oauth-provider';
import { ExecutionContext } from '@cloudflare/workers-types';
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
      const client = await registerResponse.json();
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
      const tokens = await tokenResponse.json();
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
            fetch: () => Promise.resolve(new Response())
          },
          apiHandlers: {
            '/api/users/': {
              fetch: () => Promise.resolve(new Response())
            }
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

      const metadata = await response.json();
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

      const metadata = await response.json();
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

      const registeredClient = await response.json();
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

      const registeredClient = await response.json();
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
      const client = await response.json();

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

    // Add more tests for auth code flow...
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
      const client = await response.json();

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

      const apiData = await apiResponse.json();
      expect(apiData.success).toBe(true);
      expect(apiData.user).toEqual({ userId: 'test-user-123', username: 'TestUser' });
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
      const client = await response.json();

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

      const tokens = await tokenResponse.json();
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
      const error = await tokenResponse.json();
      expect(error.error).toBe('invalid_request');
      expect(error.error_description).toBe('redirect_uri is required when not using PKCE');
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

      const tokens = await tokenResponse.json();
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
      const tokens = await tokenResponse.json();

      // Now use the access token for an API request
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${tokens.access_token}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);

      const apiData = await apiResponse.json();
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
      const client = await registerResponse.json();
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
      const tokens = await tokenResponse.json();
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

      const newTokens = await refreshResponse.json();
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
      const newTokens1 = await refreshResponse1.json();
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

      const newTokens2 = await refreshResponse2.json();
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
      const client = await registerResponse.json();
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
      const tokens = await tokenResponse.json();
      accessToken = tokens.access_token;
    }

    beforeEach(async () => {
      await getAccessToken();
    });

    it('should reject API requests without a token', async () => {
      const apiRequest = createMockRequest('https://example.com/api/test');

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);

      const error = await apiResponse.json();
      expect(error.error).toBe('invalid_token');
    });

    it('should reject API requests with an invalid token', async () => {
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: 'Bearer invalid-token',
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);

      const error = await apiResponse.json();
      expect(error.error).toBe('invalid_token');
    });

    it('should accept valid token and pass props to API handler', async () => {
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${accessToken}`,
      });

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);

      const data = await apiResponse.json();
      expect(data.success).toBe(true);
      expect(data.user).toEqual({ userId: 'test-user-123', username: 'TestUser' });
    });

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
      const client = await response.json();

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
      const tokens = await tokenResponse.json();
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
      const apiData = await apiResponse.json();
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
      const tokens = await tokenResponse.json();

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
      const newTokens = await refreshResponse.json();
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
      const apiData = await apiResponse.json();
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
      const client = await registerResponse.json();
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
      const tokens = await tokenResponse.json();

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
      const newTokens = await refreshResponse.json();

      // Use the new token to access API
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${newTokens.access_token}`,
      });

      const apiResponse = await refreshPropsProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json();

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
      const client = await registerResponse.json();
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
      const tokens = await tokenResponse.json();

      // Verify the token has the tokenOnly property when used for API access
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${tokens.access_token}`,
      });

      const apiResponse = await specialProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json();
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
      const newTokens = await refreshResponse.json();

      // Use the new token to access API
      const api2Request = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${newTokens.access_token}`,
      });

      const api2Response = await specialProvider.fetch(api2Request, mockEnv, mockCtx);
      const api2Data = await api2Response.json();

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
      const client = await registerResponse.json();
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
      const tokens = await tokenResponse.json();

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
      const newTokens = await refreshResponse.json();

      // Verify that the TTL is from the callback, not the default
      expect(newTokens.expires_in).toBe(7200);

      // Verify the token contains our custom property
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${newTokens.access_token}`,
      });

      const apiResponse = await customTtlProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json();
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
      const client = await registerResponse.json();
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
      const tokens = await tokenResponse.json();

      // Verify the token has the original props when used for API access
      const apiRequest = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${tokens.access_token}`,
      });

      const apiResponse = await noopProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json();

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
      const client = await registerResponse.json();
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
      const tokens = await tokenResponse.json();
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
      const newTokens = await refreshResponse.json();

      // Get the refresh token's corresponding token data to verify it has the updated props
      const apiRequest1 = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${newTokens.access_token}`,
      });

      const apiResponse1 = await testProvider.fetch(apiRequest1, mockEnv, mockCtx);
      const apiData1 = await apiResponse1.json();

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

      const secondTokens = await secondRefreshResponse.json();
      expect(secondTokens.access_token).toBeDefined();

      // The callback should have been called again
      expect(callCount).toBe(1);

      // Use the token to access API and verify it has the updated props
      const apiRequest2 = createMockRequest('https://example.com/api/test', 'GET', {
        Authorization: `Bearer ${secondTokens.access_token}`,
      });

      const apiResponse2 = await testProvider.fetch(apiRequest2, mockEnv, mockCtx);
      const apiData2 = await apiResponse2.json();

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
      const error = await response.json();
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

      const error = await response.json();
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
      const error = await response.json();
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
      const grants = await mockEnv.OAUTH_PROVIDER.listUserGrants('test-user-123');

      expect(grants.items.length).toBe(1);
      expect(grants.items[0].clientId).toBe(clientId);
      expect(grants.items[0].userId).toBe('test-user-123');
      expect(grants.items[0].metadata).toEqual({ testConsent: true });

      // Revoke the grant
      await mockEnv.OAUTH_PROVIDER.revokeGrant(grants.items[0].id, 'test-user-123');

      // Verify grant was deleted
      const grantsAfterRevoke = await mockEnv.OAUTH_PROVIDER.listUserGrants('test-user-123');
      expect(grantsAfterRevoke.items.length).toBe(0);
    });

    it('should allow listing, updating, and deleting clients', async () => {
      // First make a simple request to initialize the OAUTH_PROVIDER in the environment
      const initRequest = createMockRequest('https://example.com/');
      await oauthProvider.fetch(initRequest, mockEnv, mockCtx);

      // Now OAUTH_PROVIDER should be initialized
      expect(mockEnv.OAUTH_PROVIDER).not.toBeNull();

      // Create a client
      const client = await mockEnv.OAUTH_PROVIDER.createClient({
        redirectUris: ['https://client.example.com/callback'],
        clientName: 'Test Client',
        tokenEndpointAuthMethod: 'client_secret_basic',
      });

      expect(client.clientId).toBeDefined();
      expect(client.clientSecret).toBeDefined();

      // List clients
      const clients = await mockEnv.OAUTH_PROVIDER.listClients();
      expect(clients.items.length).toBe(1);
      expect(clients.items[0].clientId).toBe(client.clientId);

      // Update client
      const updatedClient = await mockEnv.OAUTH_PROVIDER.updateClient(client.clientId, {
        clientName: 'Updated Client Name',
      });

      expect(updatedClient).not.toBeNull();
      expect(updatedClient!.clientName).toBe('Updated Client Name');

      // Delete client
      await mockEnv.OAUTH_PROVIDER.deleteClient(client.clientId);

      // Verify client was deleted
      const clientsAfterDelete = await mockEnv.OAUTH_PROVIDER.listClients();
      expect(clientsAfterDelete.items.length).toBe(0);
    });
  });
});
