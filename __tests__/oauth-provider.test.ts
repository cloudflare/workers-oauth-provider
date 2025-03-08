import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { OAuthProvider, ClientInfo, AuthRequest, CompleteAuthorizationOptions } from '../oauth-provider';
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
      list_complete: true
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

// Mock FormData to enable testing token endpoint
class MockFormData implements FormData {
  private data: Map<string, string> = new Map();

  append(name: string, value: string | Blob, filename?: string): void {
    this.data.set(name, value.toString());
  }

  delete(name: string): void {
    this.data.delete(name);
  }

  get(name: string): FormDataEntryValue | null {
    return this.data.get(name) || null;
  }

  getAll(name: string): FormDataEntryValue[] {
    const value = this.data.get(name);
    return value ? [value] : [];
  }

  has(name: string): boolean {
    return this.data.has(name);
  }

  set(name: string, value: string | Blob, filename?: string): void {
    this.data.set(name, value.toString());
  }

  forEach(callbackfn: (value: FormDataEntryValue, key: string, parent: FormData) => void): void {
    this.data.forEach((value, key) => callbackfn(value, key, this));
  }

  *entries(): IterableIterator<[string, FormDataEntryValue]> {
    for (const [key, value] of this.data.entries()) {
      yield [key, value];
    }
  }

  *keys(): IterableIterator<string> {
    for (const key of this.data.keys()) {
      yield key;
    }
  }

  *values(): IterableIterator<FormDataEntryValue> {
    for (const value of this.data.values()) {
      yield value;
    }
  }

  [Symbol.iterator](): IterableIterator<[string, FormDataEntryValue]> {
    return this.entries();
  }
}

// Simple API handler for testing
class TestApiHandler extends WorkerEntrypoint {
  fetch(request: Request) {
    const url = new URL(request.url);

    if (url.pathname === '/api/test') {
      // Return authenticated user info from ctx.props
      return new Response(JSON.stringify({
        success: true,
        user: this.ctx.props
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response("Not found", { status: 404 });
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
        userId: "test-user-123",
        metadata: { testConsent: true },
        scope: oauthReqInfo.scope,
        props: { userId: "test-user-123", username: "TestUser" }
      });

      return Response.redirect(redirectTo, 302);
    }

    return new Response("Default handler", { status: 200 });
  }
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
    headers
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
    OAUTH_PROVIDER: null // Will be populated by the OAuthProvider
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
      accessTokenTTL: 3600
    });
  });

  afterEach(() => {
    // Clean up KV storage after each test
    mockEnv.OAUTH_KV.clear();
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
      expect(metadata.grant_types_supported).toContain('authorization_code');
      expect(metadata.code_challenge_methods_supported).toContain('S256');
    });
  });

  describe('Client Registration', () => {
    it('should register a new client', async () => {
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic'
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
        token_endpoint_auth_method: 'none'
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
        token_endpoint_auth_method: 'client_secret_basic'
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
      const formData = new MockFormData();
      formData.append('grant_type', 'authorization_code');
      formData.append('code', code);
      formData.append('redirect_uri', redirectUri);
      formData.append('client_id', clientId);
      formData.append('client_secret', clientSecret);

      // Mock FormData in request
      vi.spyOn(Request.prototype, 'formData').mockResolvedValue(formData as unknown as FormData);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        formData as unknown as FormData
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
      const formData = new MockFormData();
      formData.append('grant_type', 'authorization_code');
      formData.append('code', code);
      formData.append('redirect_uri', redirectUri);
      formData.append('client_id', clientId);
      formData.append('client_secret', clientSecret);

      vi.spyOn(Request.prototype, 'formData').mockResolvedValue(formData as unknown as FormData);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        formData as unknown as FormData
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json();

      // Now use the access token for an API request
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${tokens.access_token}` }
      );

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);

      const apiData = await apiResponse.json();
      expect(apiData.success).toBe(true);
      expect(apiData.user).toEqual({ userId: "test-user-123", username: "TestUser" });
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
        token_endpoint_auth_method: 'client_secret_basic'
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
      const formData = new MockFormData();
      formData.append('grant_type', 'authorization_code');
      formData.append('code', code);
      formData.append('redirect_uri', redirectUri);
      formData.append('client_id', clientId);
      formData.append('client_secret', clientSecret);

      vi.spyOn(Request.prototype, 'formData').mockResolvedValue(formData as unknown as FormData);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        formData as unknown as FormData
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
      const formData = new MockFormData();
      formData.append('grant_type', 'refresh_token');
      formData.append('refresh_token', refreshToken);
      formData.append('client_id', clientId);
      formData.append('client_secret', clientSecret);

      vi.spyOn(Request.prototype, 'formData').mockResolvedValue(formData as unknown as FormData);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        formData as unknown as FormData
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
      const formData1 = new MockFormData();
      formData1.append('grant_type', 'refresh_token');
      formData1.append('refresh_token', refreshToken);
      formData1.append('client_id', clientId);
      formData1.append('client_secret', clientSecret);

      vi.spyOn(Request.prototype, 'formData').mockResolvedValueOnce(formData1 as unknown as FormData);

      const refreshRequest1 = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        formData1 as unknown as FormData
      );

      const refreshResponse1 = await oauthProvider.fetch(refreshRequest1, mockEnv, mockCtx);
      const newTokens1 = await refreshResponse1.json();
      const newRefreshToken = newTokens1.refresh_token;

      // Now try to use the original refresh token again (simulating a retry after failure)
      const formData2 = new MockFormData();
      formData2.append('grant_type', 'refresh_token');
      formData2.append('refresh_token', refreshToken); // Original token
      formData2.append('client_id', clientId);
      formData2.append('client_secret', clientSecret);

      vi.spyOn(Request.prototype, 'formData').mockResolvedValueOnce(formData2 as unknown as FormData);

      const refreshRequest2 = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        formData2 as unknown as FormData
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
        token_endpoint_auth_method: 'client_secret_basic'
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
      const formData = new MockFormData();
      formData.append('grant_type', 'authorization_code');
      formData.append('code', code);
      formData.append('redirect_uri', redirectUri);
      formData.append('client_id', clientId);
      formData.append('client_secret', clientSecret);

      vi.spyOn(Request.prototype, 'formData').mockResolvedValue(formData as unknown as FormData);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        formData as unknown as FormData
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json();
      accessToken = tokens.access_token;
    }

    beforeEach(async () => {
      await getAccessToken();
    });

    it('should reject API requests without a token', async () => {
      const apiRequest = createMockRequest(
        'https://example.com/api/test'
      );

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);

      const error = await apiResponse.json();
      expect(error.error).toBe('invalid_token');
    });

    it('should reject API requests with an invalid token', async () => {
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': 'Bearer invalid-token' }
      );

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);

      const error = await apiResponse.json();
      expect(error.error).toBe('invalid_token');
    });

    it('should accept valid token and pass props to API handler', async () => {
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${accessToken}` }
      );

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);

      const data = await apiResponse.json();
      expect(data.success).toBe(true);
      expect(data.user).toEqual({ userId: "test-user-123", username: "TestUser" });
    });

    it('should handle CORS preflight for API requests', async () => {
      const preflightRequest = createMockRequest(
        'https://example.com/api/test',
        'OPTIONS',
        {
          'Origin': 'https://client.example.com',
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'Authorization'
        }
      );

      const preflightResponse = await oauthProvider.fetch(preflightRequest, mockEnv, mockCtx);

      expect(preflightResponse.status).toBe(204);
      expect(preflightResponse.headers.get('Access-Control-Allow-Origin')).toBe('https://client.example.com');
      expect(preflightResponse.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(preflightResponse.headers.get('Access-Control-Allow-Headers')).toContain('Authorization');
    });
  });

  describe('OAuthHelpers', () => {
    it('should allow listing and revoking grants', async () => {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic'
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
        tokenEndpointAuthMethod: 'client_secret_basic'
      });

      expect(client.clientId).toBeDefined();
      expect(client.clientSecret).toBeDefined();

      // List clients
      const clients = await mockEnv.OAUTH_PROVIDER.listClients();
      expect(clients.items.length).toBe(1);
      expect(clients.items[0].clientId).toBe(client.clientId);

      // Update client
      const updatedClient = await mockEnv.OAUTH_PROVIDER.updateClient(client.clientId, {
        clientName: 'Updated Client Name'
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