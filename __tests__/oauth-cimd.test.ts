import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { CimdFetchError, OAuthProvider } from '../src/oauth-provider';
import {
  MockExecutionContext,
  TestApiHandler,
  createMockEnv,
  createMockRequest,
  testDefaultHandler,
  type TestEnv,
} from './test-helpers';

let oauthProvider: OAuthProvider<TestEnv>;
let mockEnv: TestEnv;
let mockCtx: MockExecutionContext;

beforeEach(() => {
  vi.resetAllMocks();
  mockEnv = createMockEnv();
  mockCtx = new MockExecutionContext();
});

describe('Client ID Metadata Document (CIMD)', () => {
  let originalFetch: typeof globalThis.fetch;
  let originalCloudflare: Cloudflare | undefined;
  let originalCaches: PropertyDescriptor | undefined;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    originalCloudflare = (globalThis as { Cloudflare?: Cloudflare }).Cloudflare;
    originalCaches = Object.getOwnPropertyDescriptor(globalThis, 'caches');
    // Mock the Cloudflare global with the required compatibility flag for SSRF protection
    (globalThis as any).Cloudflare = {
      compatibilityFlags: {
        global_fetch_strictly_public: true,
      },
    };
    // Enable CIMD for the CIMD test suite
    oauthProvider = new OAuthProvider({
      apiRoute: ['/api/', 'https://api.example.com/'],
      apiHandler: TestApiHandler,
      defaultHandler: testDefaultHandler,
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      clientRegistrationEndpoint: '/oauth/register',
      scopesSupported: ['read', 'write', 'profile'],
      accessTokenTTL: 3600,
      allowImplicitFlow: true,
      allowTokenExchangeGrant: true,
      clientIdMetadataDocumentEnabled: true,
    });
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    (globalThis as any).Cloudflare = originalCloudflare;
    if (originalCaches) {
      Object.defineProperty(globalThis, 'caches', originalCaches);
    } else {
      delete (globalThis as { caches?: CacheStorage }).caches;
    }
    warnSpy.mockRestore();
  });

  function createMockFetchResponse(
    body: object | string,
    options: { status?: number; headers?: Record<string, string> } = {}
  ): Response {
    const { status = 200, headers = {} } = options;
    const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
    return new Response(bodyStr, {
      status,
      headers: { 'Content-Type': 'application/json', ...headers },
    });
  }

  // Map-backed stand-in for the Workers Cache API. Node has no `caches`
  // global, so this collaborator lets caching behavior be observed through
  // OAuth flow outcomes and origin fetch counts rather than call records.
  function installMockCimdCache(initial?: Response) {
    const entries = new Map<string, Response>();
    const key = (request: RequestInfo | URL) => (request instanceof Request ? request.url : String(request));
    if (initial) {
      entries.set('https://client.example.com/oauth/metadata.json', initial.clone());
    }
    const cache = {
      match: async (request: RequestInfo | URL) => entries.get(key(request))?.clone(),
      put: async (request: RequestInfo | URL, response: Response) => {
        entries.set(key(request), response.clone());
      },
      delete: async (request: RequestInfo | URL) => entries.delete(key(request)),
    } as unknown as Cache;
    Object.defineProperty(globalThis, 'caches', {
      configurable: true,
      value: { open: async () => cache },
    });
  }

  describe('Valid CIMD Flow', () => {
    it('should accept valid CIMD URL as client_id', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const validMetadata = {
        client_id: cimdUrl,
        client_name: 'CIMD Test Client',
        redirect_uris: ['https://client.example.com/callback'],
        token_endpoint_auth_method: 'none',
      };

      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(validMetadata)));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);

      expect(authResponse.status).toBe(302);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        cimdUrl,
        expect.objectContaining({
          headers: expect.objectContaining({ Accept: 'application/json' }),
        })
      );
    });

    it('should advertise CIMD support in metadata', async () => {
      const metadataRequest = createMockRequest('https://example.com/.well-known/oauth-authorization-server', 'GET');

      const metadataResponse = await oauthProvider.fetch(metadataRequest, mockEnv, mockCtx);
      const metadata = await metadataResponse.json<any>();

      expect(metadata.client_id_metadata_document_supported).toBe(true);
    });

    it('should accept a CIMD document with localized metadata variants', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const validMetadata = {
        client_id: cimdUrl,
        client_name: 'CIMD Test Client',
        'client_name#ja': 'テストクライアント',
        'tos_uri#fr': 'https://client.example.com/fr/terms',
        redirect_uris: ['https://client.example.com/callback'],
        token_endpoint_auth_method: 'none',
      };

      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(validMetadata)));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      expect(authResponse.status).toBe(302);
    });

    it('should reject a CIMD document whose localized URI variant uses an unsafe scheme', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const maliciousMetadata = {
        client_id: cimdUrl,
        client_name: 'CIMD Test Client',
        'tos_uri#fr': 'javascript:alert(1)',
        redirect_uris: ['https://client.example.com/callback'],
        token_endpoint_auth_method: 'none',
      };

      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(maliciousMetadata)));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });
  });

  describe('Response Size Limit (DoS Prevention)', () => {
    it('should treat oversized Content-Length response as invalid client', async () => {
      const cimdUrl = 'https://malicious.example.com/oauth/metadata.json';
      const validMetadata = {
        client_id: cimdUrl,
        redirect_uris: ['https://malicious.example.com/callback'],
      };

      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockFetchResponse(validMetadata, {
          headers: { 'Content-Length': '10000' },
        })
      );

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://malicious.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should treat streaming response exceeding 5KB as invalid client', async () => {
      const cimdUrl = 'https://malicious.example.com/oauth/metadata.json';
      const largeBody = JSON.stringify({
        client_id: cimdUrl,
        redirect_uris: ['https://malicious.example.com/callback'],
        padding: 'x'.repeat(6000),
      });

      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(largeBody, {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://malicious.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });
  });

  describe('HTTP Caching (Cloudflare)', () => {
    const cimdUrl = 'https://client.example.com/oauth/metadata.json';
    const validMetadata = {
      client_id: cimdUrl,
      client_name: 'Cached Client',
      redirect_uris: ['https://client.example.com/callback'],
      token_endpoint_auth_method: 'none',
    };
    const validOriginResponse = () =>
      createMockFetchResponse(validMetadata, { headers: { 'Cache-Control': 'public, max-age=300' } });
    const cimdAuthRequest = () =>
      createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

    it('serves repeat OAuth flows from the validated document cache', async () => {
      installMockCimdCache();
      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(validOriginResponse()));

      expect((await oauthProvider.fetch(cimdAuthRequest(), mockEnv, mockCtx)).status).toBe(302);
      expect((await oauthProvider.fetch(cimdAuthRequest(), mockEnv, mockCtx)).status).toBe(302);
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    });

    it.each([
      ['an error response', () => new Response('Not Found', { status: 404 })],
      [
        'an invalid metadata document',
        () =>
          createMockFetchResponse(
            {
              client_id: 'https://different.example.com/metadata.json',
              client_name: 'Mismatched client',
              redirect_uris: ['https://client.example.com/callback'],
            },
            { headers: { 'Cache-Control': 'public, max-age=300' } }
          ),
      ],
    ])('does not cache %s', async (_label, badOriginResponse) => {
      installMockCimdCache();
      globalThis.fetch = vi
        .fn()
        .mockImplementationOnce(() => Promise.resolve(badOriginResponse()))
        .mockImplementation(() => Promise.resolve(validOriginResponse()));

      await expect(oauthProvider.fetch(cimdAuthRequest(), mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
      // The client recovers on the next request, which only happens when the
      // bad response was never stored.
      expect((await oauthProvider.fetch(cimdAuthRequest(), mockEnv, mockCtx)).status).toBe(302);
      expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    });

    it('recovers in one request when a cached document no longer validates', async () => {
      installMockCimdCache(
        createMockFetchResponse(
          {
            client_id: 'https://attacker.example.com/client.json',
            client_name: 'Poisoned client',
            redirect_uris: ['https://attacker.example.com/callback'],
          },
          { headers: { 'Cache-Control': 'public, max-age=300' } }
        )
      );
      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(validOriginResponse()));

      expect((await oauthProvider.fetch(cimdAuthRequest(), mockEnv, mockCtx)).status).toBe(302);
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('Symmetric Auth Method Rejection', () => {
    it('should treat client_secret_post auth method as invalid client', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockFetchResponse({
          client_id: cimdUrl,
          redirect_uris: ['https://client.example.com/callback'],
          token_endpoint_auth_method: 'client_secret_post',
        })
      );

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should treat client_secret_basic auth method as invalid client', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockFetchResponse({
          client_id: cimdUrl,
          redirect_uris: ['https://client.example.com/callback'],
          token_endpoint_auth_method: 'client_secret_basic',
        })
      );

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should treat client_secret_jwt auth method as invalid client', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockFetchResponse({
          client_id: cimdUrl,
          redirect_uris: ['https://client.example.com/callback'],
          token_endpoint_auth_method: 'client_secret_jwt',
        })
      );

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should accept none auth method', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const validMetadata = {
        client_id: cimdUrl,
        client_name: 'Public CIMD Client',
        redirect_uris: ['https://client.example.com/callback'],
        token_endpoint_auth_method: 'none',
      };

      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(validMetadata)));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);

      // Should succeed with redirect
      expect(authResponse.status).toBe(302);
    });

    it('should negotiate none from the live ChatGPT metadata shape', async () => {
      // Frozen from the live document and independently verified on 2026-08-07.
      const cimdUrl = 'https://chatgpt.com/oauth/IbUR3zxyNQ16/client.json';
      const validMetadata = {
        client_id: cimdUrl,
        client_uri: 'https://chatgpt.com/',
        client_name: 'ChatGPT',
        logo_uri: 'https://persistent.oaistatic.com/sonic/misc/openai-logo.png',
        redirect_uris: ['https://chatgpt.com/connector/oauth/IbUR3zxyNQ16'],
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
        token_endpoint_auth_signing_alg: 'RS256',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        jwks_uri: 'https://chatgpt.com/oauth/jwks.json',
      };

      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(validMetadata)));
      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}` +
          `&redirect_uri=${encodeURIComponent(validMetadata.redirect_uris[0])}` +
          `&response_type=code&state=test-state` +
          `&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      const response = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const client = await mockEnv.OAUTH_PROVIDER!.lookupClient(cimdUrl);

      expect(response.status).toBe(302);
      expect(client).toMatchObject({
        tokenEndpointAuthMethod: 'none',
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
      });
    });

    it('should reject private_key_jwt until token-endpoint assertion validation is implemented', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const validMetadata = {
        client_id: cimdUrl,
        client_name: 'Private Key CIMD Client',
        redirect_uris: ['https://client.example.com/callback'],
        token_endpoint_auth_method: 'private_key_jwt',
        jwks_uri: 'https://client.example.com/.well-known/jwks.json',
      };

      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(validMetadata)));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });
  });

  describe('Metadata Validation', () => {
    it('should treat mismatched client_id as invalid client', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const invalidMetadata = {
        client_id: 'https://different.example.com/metadata.json',
        redirect_uris: ['https://client.example.com/callback'],
      };

      globalThis.fetch = vi.fn().mockResolvedValue(createMockFetchResponse(invalidMetadata));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it.each([
      ['missing', undefined],
      ['empty', '   '],
    ])('should treat %s client_name as invalid client', async (_label, clientName) => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const invalidMetadata = {
        client_id: cimdUrl,
        ...(clientName === undefined ? {} : { client_name: clientName }),
        redirect_uris: ['https://client.example.com/callback'],
        token_endpoint_auth_method: 'none',
      };

      globalThis.fetch = vi.fn().mockResolvedValue(createMockFetchResponse(invalidMetadata));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it.each([
      ['client_secret', 'must-not-be-accepted'],
      ['client_secret_expires_at', 0],
    ])('should reject %s in a CIMD document', async (field, value) => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockImplementation(() =>
        Promise.resolve(
          createMockFetchResponse({
            client_id: cimdUrl,
            client_name: 'Client with embedded secret metadata',
            redirect_uris: ['https://client.example.com/callback'],
            token_endpoint_auth_method: 'none',
            [field]: value,
          })
        )
      );

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should reject inconsistent token authentication signing choices', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockFetchResponse({
          client_id: cimdUrl,
          client_name: 'Client with inconsistent signing choices',
          redirect_uris: ['https://client.example.com/callback'],
          token_endpoint_auth_method: 'none',
          token_endpoint_auth_signing_alg: 'RS256',
          token_endpoint_auth_signing_alg_values_supported: ['ES256'],
        })
      );
      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should reject private key material in an inline CIMD JWKS', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockImplementation(() =>
        Promise.resolve(
          createMockFetchResponse({
            client_id: cimdUrl,
            client_name: 'Client with a private JWK',
            redirect_uris: ['https://client.example.com/callback'],
            token_endpoint_auth_method: 'none',
            jwks: { keys: [{ kty: 'RSA', n: 'public-modulus', e: 'AQAB', d: 'private-exponent' }] },
          })
        )
      );

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should reject unsafe redirect URIs before exposing CIMD metadata', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const metadata = {
        client_id: cimdUrl,
        client_name: 'Client with an unsafe redirect',
        redirect_uris: ['https://client.example.com/callback', 'javascript:alert(1)'],
        token_endpoint_auth_method: 'none',
      };
      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(metadata)));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent(metadata.redirect_uris[0])}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should treat missing redirect_uris as invalid client', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const invalidMetadata = {
        client_id: cimdUrl,
        client_name: 'Missing Redirects Client',
      };

      globalThis.fetch = vi.fn().mockResolvedValue(createMockFetchResponse(invalidMetadata));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should treat empty redirect_uris as invalid client', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const invalidMetadata = {
        client_id: cimdUrl,
        client_name: 'Empty Redirects Client',
        redirect_uris: [],
      };

      globalThis.fetch = vi.fn().mockResolvedValue(createMockFetchResponse(invalidMetadata));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should negotiate supported capabilities from Claude.ai-style CIMD metadata', async () => {
      const cimdUrl = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
      const metadata = {
        client_id: cimdUrl,
        client_name: 'Claude',
        client_uri: 'https://claude.ai',
        redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
        response_types: ['code'],
      };
      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(metadata)));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://claude.ai/api/mcp/auth_callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);

      expect(authResponse.status).toBe(302);
    });

    it('should reject CIMD metadata with inconsistent effective grant and response types', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockFetchResponse({
          client_id: cimdUrl,
          client_name: 'Invalid Capabilities Client',
          redirect_uris: ['https://client.example.com/callback'],
          token_endpoint_auth_method: 'none',
          grant_types: ['authorization_code', 'urn:example:unsupported-grant'],
          response_types: ['id_token'],
        })
      );

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it.each([
      ['invalid JSON', 'not valid json {{{'],
      ['a non-object JSON value', '[]'],
      ['invalid UTF-8', new Uint8Array([0xff])],
    ])('should treat %s as invalid client metadata', async (_label, body) => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(body, {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });
  });

  describe('URL Detection', () => {
    it('should NOT treat HTTP URLs as CIMD', async () => {
      const httpUrl = 'http://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn();

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(httpUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid client');
      expect(globalThis.fetch).not.toHaveBeenCalled();
    });

    it('should NOT treat HTTPS URLs without path as CIMD', async () => {
      const urlWithoutPath = 'https://client.example.com';
      globalThis.fetch = vi.fn();

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(urlWithoutPath)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid client');
      expect(globalThis.fetch).not.toHaveBeenCalled();
    });

    it('should treat HTTPS URLs with a root path as CIMD client identifiers', async () => {
      // CIMD draft §3 only requires a path component; a root path is
      // NOT RECOMMENDED for clients but valid for the server to resolve.
      const urlWithRootPath = 'https://client.example.com/';
      globalThis.fetch = vi.fn().mockImplementation(() =>
        Promise.resolve(
          createMockFetchResponse({
            client_id: urlWithRootPath,
            client_name: 'Root Path Client',
            redirect_uris: ['https://client.example.com/callback'],
            token_endpoint_auth_method: 'none',
          })
        )
      );

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(urlWithRootPath)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      expect((await oauthProvider.fetch(authRequest, mockEnv, mockCtx)).status).toBe(302);
      expect(globalThis.fetch).toHaveBeenCalledWith(urlWithRootPath, expect.anything());
    });

    it.each([
      ['userinfo', 'https://user:password@client.example.com/oauth/metadata.json'],
      ['a fragment', 'https://client.example.com/oauth/metadata.json#fragment'],
      ['a dot path segment', 'https://client.example.com/oauth/../metadata.json'],
    ])('should reject CIMD URLs containing %s without fetching them', async (_label, clientId) => {
      const fetchSpy = vi.fn();
      globalThis.fetch = fetchSpy;
      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('should not mistake a slash in a query for a document path', async () => {
      const clientId = 'https://client.example.com?return=/oauth/metadata.json';
      const fetchSpy = vi.fn();
      globalThis.fetch = fetchSpy;
      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid client');
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('should treat regular client_id strings as KV lookup', async () => {
      const regularClientId = 'my-client-id';
      globalThis.fetch = vi.fn();

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(regularClientId)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid client');
      expect(globalThis.fetch).not.toHaveBeenCalled();
    });
  });

  describe('Request Timeout', () => {
    it('should treat fetch abort as invalid client', async () => {
      const cimdUrl = 'https://abort.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockRejectedValue(new DOMException('Aborted', 'AbortError'));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://abort.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should keep the fetch timeout active while reading the response body', async () => {
      vi.useFakeTimers();
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      let bodyController: ReadableStreamDefaultController<Uint8Array> | undefined;
      let fetchSignal: AbortSignal | undefined;
      globalThis.fetch = vi.fn().mockImplementation((_url, init) => {
        fetchSignal = init?.signal as AbortSignal;
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            bodyController = controller;
            fetchSignal?.addEventListener('abort', () => controller.error(new DOMException('Aborted', 'AbortError')));
          },
        });
        return Promise.resolve(new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } }));
      });

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );
      const responsePromise = oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const rejection = expect(responsePromise).rejects.toThrow(CimdFetchError);

      try {
        await vi.advanceTimersByTimeAsync(10_001);
        expect(fetchSignal?.aborted).toBe(true);
        await rejection;
      } finally {
        if (!fetchSignal?.aborted) bodyController?.close();
        await responsePromise.catch(() => undefined);
        vi.useRealTimers();
      }
    });
  });

  describe('HTTP Error Handling', () => {
    it('should treat 404 responses as invalid client', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockResolvedValue(new Response('Not Found', { status: 404 }));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should treat 500 responses as invalid client', async () => {
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockResolvedValue(new Response('Internal Server Error', { status: 500 }));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });

    it('should treat network errors as invalid client', async () => {
      const cimdUrl = 'https://unreachable.example.com/oauth/metadata.json';
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://unreachable.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
    });
  });

  describe('SSRF Protection', () => {
    it('should reject CIMD fetch when global_fetch_strictly_public is not enabled', async () => {
      // Remove the compatibility flag to simulate it not being enabled
      (globalThis as any).Cloudflare = {
        compatibilityFlags: {
          global_fetch_strictly_public: false,
        },
      };

      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const validMetadata = {
        client_id: cimdUrl,
        client_name: 'CIMD Test Client',
        redirect_uris: ['https://client.example.com/callback'],
        token_endpoint_auth_method: 'none',
      };

      // Fetch should not even be called
      const fetchSpy = vi.fn().mockResolvedValue(
        new Response(JSON.stringify(validMetadata), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );
      globalThis.fetch = fetchSpy;

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(
        "global_fetch_strictly_public' compatibility flag is not set"
      );
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('should reject CIMD fetch when Cloudflare global is undefined', async () => {
      // Remove the Cloudflare global entirely
      delete (globalThis as any).Cloudflare;

      const cimdUrl = 'https://client.example.com/oauth/metadata.json';

      const fetchSpy = vi.fn();
      globalThis.fetch = fetchSpy;

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(
        "global_fetch_strictly_public' compatibility flag is not set"
      );
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('should reject CIMD fetch when compatibilityFlags is undefined', async () => {
      // Cloudflare exists but without compatibilityFlags
      (globalThis as any).Cloudflare = {};

      const cimdUrl = 'https://client.example.com/oauth/metadata.json';

      const fetchSpy = vi.fn();
      globalThis.fetch = fetchSpy;

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(
        "global_fetch_strictly_public' compatibility flag is not set"
      );
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('should report client_id_metadata_document_supported as true when option and flag are enabled', async () => {
      // Both clientIdMetadataDocumentEnabled and compat flag are enabled in beforeEach
      const metadataRequest = createMockRequest('https://example.com/.well-known/oauth-authorization-server', 'GET');
      const response = await oauthProvider.fetch(metadataRequest, mockEnv, mockCtx);
      const metadata = (await response.json()) as { client_id_metadata_document_supported: boolean };

      expect(metadata.client_id_metadata_document_supported).toBe(true);
    });

    it('should report client_id_metadata_document_supported as false when compat flag is not enabled', async () => {
      (globalThis as any).Cloudflare = {
        compatibilityFlags: {
          global_fetch_strictly_public: false,
        },
      };

      const metadataRequest = createMockRequest('https://example.com/.well-known/oauth-authorization-server', 'GET');
      const response = await oauthProvider.fetch(metadataRequest, mockEnv, mockCtx);
      const metadata = (await response.json()) as { client_id_metadata_document_supported: boolean };

      expect(metadata.client_id_metadata_document_supported).toBe(false);
    });

    it('should report client_id_metadata_document_supported as false when Cloudflare global is undefined', async () => {
      delete (globalThis as any).Cloudflare;

      const metadataRequest = createMockRequest('https://example.com/.well-known/oauth-authorization-server', 'GET');
      const response = await oauthProvider.fetch(metadataRequest, mockEnv, mockCtx);
      const metadata = (await response.json()) as { client_id_metadata_document_supported: boolean };

      expect(metadata.client_id_metadata_document_supported).toBe(false);
    });
  });

  describe('Explicit Opt-In', () => {
    it('should fall through to KV lookup for URL client_id when CIMD is not enabled', async () => {
      // Create provider WITHOUT clientIdMetadataDocumentEnabled
      const providerWithoutCimd = new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write', 'profile'],
        accessTokenTTL: 3600,
        allowImplicitFlow: true,
        allowTokenExchangeGrant: true,
      });

      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const fetchSpy = vi.fn();
      globalThis.fetch = fetchSpy;

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      // Should NOT call fetch — falls through to KV lookup (which returns null → "Invalid client")
      await expect(providerWithoutCimd.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid client');
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('should report client_id_metadata_document_supported as false when option is not set', async () => {
      const providerWithoutCimd = new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write', 'profile'],
        accessTokenTTL: 3600,
        allowImplicitFlow: true,
        allowTokenExchangeGrant: true,
      });

      const metadataRequest = createMockRequest('https://example.com/.well-known/oauth-authorization-server', 'GET');
      const response = await providerWithoutCimd.fetch(metadataRequest, mockEnv, mockCtx);
      const metadata = (await response.json()) as { client_id_metadata_document_supported: boolean };

      expect(metadata.client_id_metadata_document_supported).toBe(false);
    });

    it('should fetch CIMD when option is enabled and compat flag is set', async () => {
      // oauthProvider already has clientIdMetadataDocumentEnabled: true from beforeEach
      // and Cloudflare global_fetch_strictly_public: true
      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const validMetadata = {
        client_id: cimdUrl,
        client_name: 'CIMD Opt-In Client',
        redirect_uris: ['https://client.example.com/callback'],
        token_endpoint_auth_method: 'none',
      };

      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(validMetadata)));

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      expect(authResponse.status).toBe(302);
      expect(globalThis.fetch).toHaveBeenCalledWith(cimdUrl, expect.anything());
    });

    it('should throw when option is enabled but compat flag is missing', async () => {
      // oauthProvider has clientIdMetadataDocumentEnabled: true from beforeEach
      // but remove the compat flag
      delete (globalThis as any).Cloudflare;

      const cimdUrl = 'https://client.example.com/oauth/metadata.json';
      const fetchSpy = vi.fn();
      globalThis.fetch = fetchSpy;

      const authRequest = createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(
        "CIMD is enabled but 'global_fetch_strictly_public' compatibility flag is not set."
      );
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });

  describe('CIMD Error Logging', () => {
    const cimdUrl = 'https://client.example.com/oauth/metadata.json';

    function makeAuthRequest(url: string = cimdUrl) {
      return createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(url)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=S256`,
        'GET'
      );
    }

    it('should log warning with client URL and error message on HTTP failure', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(new Response('Not Found', { status: 404 }));

      await expect(oauthProvider.fetch(makeAuthRequest(), mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining(cimdUrl), expect.stringContaining('HTTP 404'));
    });

    it('should log warning on timeout', async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new DOMException('Aborted', 'AbortError'));

      await expect(oauthProvider.fetch(makeAuthRequest(), mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining(cimdUrl), expect.anything());
    });

    it('should log warning on size limit exceeded', async () => {
      globalThis.fetch = vi
        .fn()
        .mockResolvedValue(
          createMockFetchResponse(
            { client_id: cimdUrl, redirect_uris: ['https://client.example.com/callback'] },
            { headers: { 'Content-Length': '10000' } }
          )
        );

      await expect(oauthProvider.fetch(makeAuthRequest(), mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
      expect(warnSpy).toHaveBeenCalledWith(expect.anything(), expect.stringContaining('size limit'));
    });

    it('should log warning on metadata validation failure', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockFetchResponse({
          client_id: 'https://different.example.com/metadata.json',
          redirect_uris: ['https://client.example.com/callback'],
        })
      );

      await expect(oauthProvider.fetch(makeAuthRequest(), mockEnv, mockCtx)).rejects.toThrow(CimdFetchError);
      expect(warnSpy).toHaveBeenCalledWith(expect.anything(), expect.stringContaining('does not match'));
    });

    it('should expose stable and diagnostic fields on the thrown error', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(new Response('Blocked', { status: 403 }));

      const error = await oauthProvider.fetch(makeAuthRequest(), mockEnv, mockCtx).then(
        () => {
          throw new Error('expected rejection');
        },
        (cause) => cause
      );
      expect(error).toBeInstanceOf(CimdFetchError);
      expect(error.metadataUrl).toBe(cimdUrl);
      expect(error.reason).toBe('metadata_resolution_failed');
      expect(error.detail).toContain('HTTP 403');
    });
  });

  describe('Token Endpoint CIMD Failure', () => {
    const cimdUrl = 'https://client.example.com/oauth/metadata.json';

    function makeTokenRequest() {
      return createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        `grant_type=authorization_code&code=test-code&client_id=${encodeURIComponent(cimdUrl)}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}`
      );
    }

    it('should return invalid_client OAuth error when CIMD fetch fails at token endpoint', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(new Response('Not Found', { status: 404 }));

      const response = await oauthProvider.fetch(makeTokenRequest(), mockEnv, mockCtx);
      expect(response.status).toBe(401);
      expect(response.headers.get('WWW-Authenticate')).toBeNull();
      const body = await response.json<any>();
      expect(body.error).toBe('invalid_client');
    });

    it('should retain the Basic challenge when CIMD resolution fails', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(new Response('Blocked', { status: 403 }));

      const response = await oauthProvider.fetch(
        createMockRequest(
          'https://example.com/oauth/token',
          'POST',
          {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${btoa(`${encodeURIComponent(cimdUrl)}:`)}`,
          },
          'grant_type=authorization_code&code=test-code'
        ),
        mockEnv,
        mockCtx
      );

      expect(response.status).toBe(401);
      expect(response.headers.get('WWW-Authenticate')).toBe('Basic realm="OAuth"');
      expect(await response.json<any>()).toEqual({
        error: 'invalid_client',
        error_description: 'Client not found',
      });
    });

    it('should report the fetch failure through onError while keeping the wire response generic', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(new Response('Blocked', { status: 403 }));

      const onError = vi.fn();
      const provider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        clientIdMetadataDocumentEnabled: true,
        onError,
      });

      const tokenRequest = makeTokenRequest();
      const response = await provider.fetch(tokenRequest, mockEnv, mockCtx);

      // The wire response is indistinguishable from an unknown client.
      expect(response.status).toBe(401);
      expect(await response.json<any>()).toEqual({
        error: 'invalid_client',
        error_description: 'Client not found',
      });

      // The hook receives the real reason and the originating request, so
      // deployers can log it and attach it to request-scoped telemetry.
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'invalid_client',
          status: 401,
          internal: {
            category: 'client-id-metadata-document',
            reason: 'metadata_resolution_failed',
            detail: {
              metadataUrl: cimdUrl,
              message: expect.stringContaining('HTTP 403'),
            },
          },
          request: tokenRequest,
        })
      );
    });
  });

  describe('Grant Revocation Scoping', () => {
    // A CIMD client_id is the metadata document URL, shared by every installation of
    // the client. Two loopback redirect URIs stand in for two installations (devices).
    const cimdUrl = 'https://client.example.com/oauth/metadata.json';
    const installA = 'http://127.0.0.1:49152/callback';
    const installB = 'http://127.0.0.1:49153/callback';
    const cimdMetadata = {
      client_id: cimdUrl,
      client_name: 'Multi-Install CIMD Client',
      redirect_uris: [installA, installB],
      token_endpoint_auth_method: 'none',
    };
    const codeVerifier = 'grant-scoping-code-verifier-that-is-at-least-43-characters';
    let codeChallenge: string;

    beforeEach(async () => {
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
      codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    });

    async function authorizeAndGetCode(clientId: string, redirectUri: string): Promise<string> {
      const authResponse = await oauthProvider.fetch(
        createMockRequest(
          `https://example.com/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&state=test-state&code_challenge=${codeChallenge}&code_challenge_method=S256`,
          'GET'
        ),
        mockEnv,
        mockCtx
      );
      expect(authResponse.status).toBe(302);
      return new URL(authResponse.headers.get('Location')!).searchParams.get('code')!;
    }

    async function exchangeCodeForTokens(clientId: string, code: string, redirectUri: string): Promise<any> {
      const tokenResponse = await oauthProvider.fetch(
        createMockRequest(
          'https://example.com/oauth/token',
          'POST',
          { 'Content-Type': 'application/x-www-form-urlencoded' },
          `grant_type=authorization_code&code=${encodeURIComponent(code)}&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&code_verifier=${codeVerifier}`
        ),
        mockEnv,
        mockCtx
      );
      expect(tokenResponse.status).toBe(200);
      return tokenResponse.json<any>();
    }

    async function callApi(accessToken: string): Promise<number> {
      const apiResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/api/test', 'GET', { Authorization: `Bearer ${accessToken}` }),
        mockEnv,
        mockCtx
      );
      return apiResponse.status;
    }

    it('should keep grants from other installations of the same CIMD client', async () => {
      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(cimdMetadata)));

      const codeA = await authorizeAndGetCode(cimdUrl, installA);
      const tokensA = await exchangeCodeForTokens(cimdUrl, codeA, installA);

      const codeB = await authorizeAndGetCode(cimdUrl, installB);
      const tokensB = await exchangeCodeForTokens(cimdUrl, codeB, installB);

      // Installation A's grant survives installation B's authorization.
      expect(await callApi(tokensA.access_token)).toBe(200);
      expect(await callApi(tokensB.access_token)).toBe(200);

      const grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('test-user-123');
      expect(grants.items.length).toBe(2);
      expect(grants.items.map((grant) => grant.redirectUri).sort()).toEqual([installA, installB]);
    });

    it('should revoke the previous grant when the same installation re-authorizes', async () => {
      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(cimdMetadata)));

      const codeA = await authorizeAndGetCode(cimdUrl, installA);
      const tokensA = await exchangeCodeForTokens(cimdUrl, codeA, installA);
      expect(await callApi(tokensA.access_token)).toBe(200);

      // Same installation authorizes again with the same redirect URI.
      const codeB = await authorizeAndGetCode(cimdUrl, installA);
      const tokensB = await exchangeCodeForTokens(cimdUrl, codeB, installA);

      expect(await callApi(tokensA.access_token)).toBe(401);
      expect(await callApi(tokensB.access_token)).toBe(200);

      const grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('test-user-123');
      expect(grants.items.length).toBe(1);
    });

    it('should leave grants recorded before redirectUri existed untouched', async () => {
      // A grant persisted by a release that predates the redirectUri field.
      await mockEnv.OAUTH_KV.put(
        'grant:test-user-123:legacygrant1',
        JSON.stringify({
          id: 'legacygrant1',
          clientId: cimdUrl,
          userId: 'test-user-123',
          scope: ['read'],
          metadata: {},
          encryptedProps: 'legacy-ciphertext',
          createdAt: 1700000000,
        })
      );
      globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createMockFetchResponse(cimdMetadata)));

      const code = await authorizeAndGetCode(cimdUrl, installA);
      expect(code).toBeTruthy();

      const grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('test-user-123');
      expect(grants.items.length).toBe(2);
      expect(grants.items.some((grant) => grant.id === 'legacygrant1')).toBe(true);
    });

    it('should still revoke by client alone for non-CIMD clients with a different redirect URI', async () => {
      const registerResponse = await oauthProvider.fetch(
        createMockRequest(
          'https://example.com/oauth/register',
          'POST',
          { 'Content-Type': 'application/json' },
          JSON.stringify({
            redirect_uris: [
              'https://dcr-client.example.com/callback-one',
              'https://dcr-client.example.com/callback-two',
            ],
            client_name: 'DCR Test Client',
            token_endpoint_auth_method: 'none',
          })
        ),
        mockEnv,
        mockCtx
      );
      const { client_id: dcrClientId } = await registerResponse.json<any>();

      const codeOne = await authorizeAndGetCode(dcrClientId, 'https://dcr-client.example.com/callback-one');
      const tokensOne = await exchangeCodeForTokens(
        dcrClientId,
        codeOne,
        'https://dcr-client.example.com/callback-one'
      );
      expect(await callApi(tokensOne.access_token)).toBe(200);

      // A DCR client_id is unique to one installation, so a re-authorization from a
      // different redirect URI still revokes the existing grant.
      const codeTwo = await authorizeAndGetCode(dcrClientId, 'https://dcr-client.example.com/callback-two');
      expect(codeTwo).toBeTruthy();

      expect(await callApi(tokensOne.access_token)).toBe(401);
      const grants = await mockEnv.OAUTH_PROVIDER!.listUserGrants('test-user-123');
      expect(grants.items.length).toBe(1);
    });
  });
});
