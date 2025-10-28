import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OAuthClient, OAuthError } from '../src/oauth-client';
import type { AuthRequest } from '../src/oauth-provider';

/**
 * Mock KV namespace implementation that stores data in memory
 */
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
    const keys: { name: string }[] = [];

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
 * Helper function to create mock requests
 */
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

describe('OAuthClient', () => {
  let mockKV: MockKV;
  let client: OAuthClient;

  beforeEach(() => {
    mockKV = new MockKV();
    client = new OAuthClient({
      kv: mockKV as unknown as KVNamespace,
      cookieSecret: 'test-secret-key-for-signing-cookies',
    });
  });

  describe('OAuthClient instantiation', () => {
    it('creates client with required options', () => {
      const testClient = new OAuthClient({
        kv: mockKV as unknown as KVNamespace,
        cookieSecret: 'test-secret',
      });
      expect(testClient).toBeInstanceOf(OAuthClient);
    });

    it('uses default cookie names with mcp namespace', () => {
      const testClient = new OAuthClient({
        kv: mockKV as unknown as KVNamespace,
        cookieSecret: 'test-secret',
      });
      const csrf = testClient.generateCSRFProtection();

      expect(csrf.setCookie).toContain('__Host-CSRF_TOKEN-mcp=');
    });

    it('accepts custom clientName for namespacing', () => {
      const testClient = new OAuthClient({
        kv: mockKV as unknown as KVNamespace,
        cookieSecret: 'test-secret',
        clientName: 'github',
      });
      const csrf = testClient.generateCSRFProtection();

      expect(csrf.setCookie).toContain('__Host-CSRF_TOKEN-github=');
    });

    it('validates clientName format', () => {
      expect(() => {
        new OAuthClient({
          kv: mockKV as unknown as KVNamespace,
          cookieSecret: 'test-secret',
          clientName: 'invalid name!',
        });
      }).toThrow('clientName must contain only alphanumeric characters, hyphens, or underscores');
    });
  });

  describe('sanitizeText()', () => {
    it('escapes HTML special characters', () => {
      const input = '<script>alert("xss")</script>';
      const result = OAuthClient.sanitizeText(input);
      expect(result).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
    });

    it('escapes ampersands', () => {
      const result = OAuthClient.sanitizeText('foo & bar');
      expect(result).toBe('foo &amp; bar');
    });

    it('escapes single quotes', () => {
      const result = OAuthClient.sanitizeText("it's a test");
      expect(result).toBe('it&#039;s a test');
    });

    it('handles all special characters together', () => {
      const input = '& < > " \'';
      const result = OAuthClient.sanitizeText(input);
      expect(result).toBe('&amp; &lt; &gt; &quot; &#039;');
    });

    it('preserves safe content', () => {
      const input = 'Hello World 123';
      const result = OAuthClient.sanitizeText(input);
      expect(result).toBe('Hello World 123');
    });

    it('handles empty string', () => {
      const result = OAuthClient.sanitizeText('');
      expect(result).toBe('');
    });
  });

  describe('sanitizeUrl()', () => {
    it('allows valid HTTPS URLs', () => {
      const result = OAuthClient.sanitizeUrl('https://example.com/callback');
      expect(result).toBe('https://example.com/callback');
    });

    it('allows valid HTTP URLs', () => {
      const result = OAuthClient.sanitizeUrl('http://localhost:3000/callback');
      expect(result).toBe('http://localhost:3000/callback');
    });

    it('blocks javascript: scheme', () => {
      const result = OAuthClient.sanitizeUrl('javascript:alert(1)');
      expect(result).toBe('');
    });

    it('blocks data: scheme', () => {
      const result = OAuthClient.sanitizeUrl('data:text/html,<script>alert(1)</script>');
      expect(result).toBe('');
    });

    it('blocks vbscript: scheme', () => {
      const result = OAuthClient.sanitizeUrl('vbscript:msgbox(1)');
      expect(result).toBe('');
    });

    it('blocks file: scheme', () => {
      const result = OAuthClient.sanitizeUrl('file:///etc/passwd');
      expect(result).toBe('');
    });

    it('blocks about: scheme', () => {
      const result = OAuthClient.sanitizeUrl('about:blank');
      expect(result).toBe('');
    });

    it('blocks blob: scheme', () => {
      const result = OAuthClient.sanitizeUrl('blob:https://example.com/uuid');
      expect(result).toBe('');
    });

    it('blocks mailto: scheme', () => {
      const result = OAuthClient.sanitizeUrl('mailto:attacker@evil.com');
      expect(result).toBe('');
    });

    it('blocks mixed-case javascript: bypass', () => {
      const result = OAuthClient.sanitizeUrl('JaVaScRiPt:alert(1)');
      expect(result).toBe('');
    });

    it('blocks mixed-case DATA: bypass', () => {
      const result = OAuthClient.sanitizeUrl('DaTa:text/html,<script>');
      expect(result).toBe('');
    });

    it('rejects URLs with leading whitespace', () => {
      const result = OAuthClient.sanitizeUrl(' javascript:alert(1)');
      expect(result).toBe('');
    });

    it('rejects URLs with null byte', () => {
      const result = OAuthClient.sanitizeUrl('https://example.com\x00/callback');
      expect(result).toBe('');
    });

    it('rejects URLs with tab character', () => {
      const result = OAuthClient.sanitizeUrl('https://example.com\t/callback');
      expect(result).toBe('');
    });

    it('rejects URLs with newline', () => {
      const result = OAuthClient.sanitizeUrl('https://example.com\n/callback');
      expect(result).toBe('');
    });

    it('rejects URLs with DELETE char (0x7F)', () => {
      const result = OAuthClient.sanitizeUrl('https://example.com\x7F/callback');
      expect(result).toBe('');
    });

    it('rejects URLs with C1 control chars', () => {
      const result = OAuthClient.sanitizeUrl('https://example.com\x80/callback');
      expect(result).toBe('');
    });

    it('rejects relative URLs without scheme', () => {
      const result = OAuthClient.sanitizeUrl('/callback');
      expect(result).toBe('');
    });

    it('rejects empty URLs', () => {
      const result = OAuthClient.sanitizeUrl('');
      expect(result).toBe('');
    });

    it('returns unescaped valid URLs', () => {
      const result = OAuthClient.sanitizeUrl('https://example.com/path?query="value"');
      expect(result).toBe('https://example.com/path?query="value"');
    });

    it('can be combined with sanitizeText for HTML context', () => {
      const url = 'https://example.com/path?query="value"';
      const validated = OAuthClient.sanitizeUrl(url);
      const htmlSafe = OAuthClient.sanitizeText(validated);
      expect(htmlSafe).toBe('https://example.com/path?query=&quot;value&quot;');
    });
  });

  describe('generateCSRFProtection()', () => {
    it('generates random token', () => {
      const result = client.generateCSRFProtection();

      expect(result.token).toBeDefined();
      expect(typeof result.token).toBe('string');
      expect(result.token.length).toBeGreaterThan(0);
    });

    it('returns valid Set-Cookie header', () => {
      const result = client.generateCSRFProtection();

      expect(result.setCookie).toBeDefined();
      expect(result.setCookie).toContain('HttpOnly');
      expect(result.setCookie).toContain('Secure');
      expect(result.setCookie).toContain('Path=/authorize');
      expect(result.setCookie).toContain('SameSite=Lax');
      expect(result.setCookie).toContain('Max-Age=600');
    });

    it('uses correct cookie name with namespace', () => {
      const result = client.generateCSRFProtection();

      expect(result.setCookie).toContain('__Host-CSRF_TOKEN-mcp=');
      expect(result.setCookie).toContain(result.token);
    });

    it('token is different each time', () => {
      const result1 = client.generateCSRFProtection();
      const result2 = client.generateCSRFProtection();

      expect(result1.token).not.toBe(result2.token);
    });
  });

  describe('validateCSRFToken()', () => {
    it('validates matching token and cookie', async () => {
      const { token, setCookie } = client.generateCSRFProtection();
      const cookieValue = setCookie.split(';')[0].split('=')[1];

      const formData = new FormData();
      formData.append('csrf_token', token);

      const request = createMockRequest(
        'https://example.com/authorize',
        'POST',
        {
          Cookie: `__Host-CSRF_TOKEN-mcp=${cookieValue}`,
        },
        formData
      );

      const result = await client.validateCSRFToken(request);
      expect(result.clearCookie).toBeDefined();
    });

    it('throws OAuthError on missing form token', async () => {
      const formData = new FormData();

      const request = createMockRequest(
        'https://example.com/authorize',
        'POST',
        {
          Cookie: '__Host-CSRF_TOKEN-mcp=some-token',
        },
        formData
      );

      try {
        await client.validateCSRFToken(request);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect((error as OAuthError).description).toContain('Missing CSRF token in form data');
      }
    });

    it('throws OAuthError on missing cookie', async () => {
      const formData = new FormData();
      formData.append('csrf_token', 'some-token');

      const request = createMockRequest('https://example.com/authorize', 'POST', {}, formData);

      try {
        await client.validateCSRFToken(request);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect((error as OAuthError).description).toContain('Missing CSRF token cookie');
      }
    });

    it('throws OAuthError on mismatched tokens', async () => {
      const formData = new FormData();
      formData.append('csrf_token', 'token-from-form');

      const request = createMockRequest(
        'https://example.com/authorize',
        'POST',
        {
          Cookie: '__Host-CSRF_TOKEN-mcp=different-token',
        },
        formData
      );

      try {
        await client.validateCSRFToken(request);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect((error as OAuthError).description).toContain('CSRF token mismatch');
      }
    });

    it('error has correct code and status', async () => {
      const formData = new FormData();

      const request = createMockRequest('https://example.com/authorize', 'POST', {}, formData);

      try {
        await client.validateCSRFToken(request);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect((error as OAuthError).code).toBe('invalid_request');
        expect((error as OAuthError).statusCode).toBe(400);
      }
    });
  });

  describe('createOAuthState()', () => {
    it('generates random state token', async () => {
      const oauthReqInfo = {
        clientId: 'test-client',
        redirectUri: 'https://example.com/callback',
      } as AuthRequest;

      const result = await client.createOAuthState(oauthReqInfo);

      expect(result.stateToken).toBeDefined();
      expect(typeof result.stateToken).toBe('string');
      expect(result.stateToken.length).toBeGreaterThan(0);
    });

    it('stores data in KV with correct key format', async () => {
      const oauthReqInfo = {
        clientId: 'test-client',
        redirectUri: 'https://example.com/callback',
        scope: ['read', 'write'],
        responseType: 'code',
        state: 'xyz123',
      } as AuthRequest;

      const result = await client.createOAuthState(oauthReqInfo);

      const storedData = await mockKV.get(`oauth:mcp:state:${result.stateToken}`);
      expect(storedData).toBeDefined();

      const parsedData = JSON.parse(storedData);
      expect(parsedData).toEqual(oauthReqInfo);
    });

    it('sets correct TTL (600 seconds)', async () => {
      const oauthReqInfo = {
        clientId: 'test-client',
        redirectUri: 'https://example.com/callback',
        scope: ['read', 'write'],
        responseType: 'code',
        state: 'xyz123',
      } as AuthRequest;

      vi.spyOn(mockKV, 'put');

      await client.createOAuthState(oauthReqInfo);

      expect(mockKV.put).toHaveBeenCalledWith(expect.stringContaining('oauth:mcp:state:'), expect.any(String), {
        expirationTtl: 600,
      });
    });

    it('returns valid Set-Cookie header', async () => {
      const oauthReqInfo = {
        clientId: 'test-client',
        redirectUri: 'https://example.com/callback',
        scope: ['read', 'write'],
        responseType: 'code',
        state: 'xyz123',
      } as AuthRequest;

      const result = await client.createOAuthState(oauthReqInfo);

      expect(result.setCookie).toBeDefined();
      expect(result.setCookie).toContain('__Host-CONSENTED_STATE-mcp=');
      expect(result.setCookie).toContain(result.stateToken);
      expect(result.setCookie).toContain('HttpOnly');
      expect(result.setCookie).toContain('Secure');
      expect(result.setCookie).toContain('Path=/callback');
      expect(result.setCookie).toContain('SameSite=Lax');
      expect(result.setCookie).toContain('Max-Age=600');
    });

    it('state token is different each time', async () => {
      const oauthReqInfo = {
        clientId: 'test-client',
        redirectUri: 'https://example.com/callback',
        scope: ['read', 'write'],
        responseType: 'code',
        state: 'xyz123',
      } as AuthRequest;

      const result1 = await client.createOAuthState(oauthReqInfo);
      const result2 = await client.createOAuthState(oauthReqInfo);

      expect(result1.stateToken).not.toBe(result2.stateToken);
    });
  });

  describe('validateOAuthState()', () => {
    it('validates matching query param, cookie, and KV', async () => {
      const oauthReqInfo = {
        clientId: 'test-client',
        redirectUri: 'https://example.com/callback',
        scope: ['read', 'write'],
        responseType: 'code',
        state: 'xyz123',
      } as AuthRequest;

      const { stateToken } = await client.createOAuthState(oauthReqInfo);

      const request = createMockRequest(`https://example.com/callback?state=${stateToken}&code=auth-code-123`, 'GET', {
        Cookie: `__Host-CONSENTED_STATE-mcp=${stateToken}`,
      });

      const result = await client.validateOAuthState(request);

      expect(result.oauthReqInfo).toEqual(oauthReqInfo);
    });

    it('returns stored oauthReqInfo', async () => {
      const oauthReqInfo = {
        clientId: 'test-client',
        redirectUri: 'https://example.com/callback',
        scope: ['read', 'write', 'profile'],
        responseType: 'code',
        state: 'xyz123',
      } as AuthRequest;

      const { stateToken } = await client.createOAuthState(oauthReqInfo);

      const request = createMockRequest(`https://example.com/callback?state=${stateToken}`, 'GET', {
        Cookie: `__Host-CONSENTED_STATE-mcp=${stateToken}`,
      });

      const result = await client.validateOAuthState(request);

      expect(result.oauthReqInfo).toEqual(oauthReqInfo);
    });

    it('deletes KV entry (single-use)', async () => {
      const oauthReqInfo = {
        clientId: 'test-client',
        redirectUri: 'https://example.com/callback',
        scope: ['read', 'write', 'profile'],
        responseType: 'code',
        state: 'xyz123',
      } as AuthRequest;

      const { stateToken } = await client.createOAuthState(oauthReqInfo);

      const request = createMockRequest(`https://example.com/callback?state=${stateToken}`, 'GET', {
        Cookie: `__Host-CONSENTED_STATE-mcp=${stateToken}`,
      });

      await client.validateOAuthState(request);

      const storedData = await mockKV.get(`oauth:mcp:state:${stateToken}`);
      expect(storedData).toBeNull();
    });

    it('returns clear cookie header', async () => {
      const oauthReqInfo = {
        clientId: 'test-client',
        redirectUri: 'https://example.com/callback',
        scope: ['read', 'write', 'profile'],
        responseType: 'code',
        state: 'xyz123',
      } as AuthRequest;

      const { stateToken } = await client.createOAuthState(oauthReqInfo);

      const request = createMockRequest(`https://example.com/callback?state=${stateToken}`, 'GET', {
        Cookie: `__Host-CONSENTED_STATE-mcp=${stateToken}`,
      });

      const result = await client.validateOAuthState(request);

      expect(result.clearCookie).toBeDefined();
      expect(result.clearCookie).toContain('__Host-CONSENTED_STATE-mcp=');
      expect(result.clearCookie).toContain('Max-Age=0');
    });

    it('throws on missing query param', async () => {
      const request = createMockRequest('https://example.com/callback', 'GET', {
        Cookie: '__Host-CONSENTED_STATE-mcp=some-token',
      });

      await expect(client.validateOAuthState(request)).rejects.toThrow(OAuthError);
      await expect(client.validateOAuthState(request)).rejects.toThrow('Missing state parameter');
    });

    it('throws on missing cookie', async () => {
      const request = createMockRequest('https://example.com/callback?state=some-token', 'GET');

      await expect(client.validateOAuthState(request)).rejects.toThrow(OAuthError);
      await expect(client.validateOAuthState(request)).rejects.toThrow('Missing consent state cookie');
    });

    it('throws on mismatched state', async () => {
      const request = createMockRequest('https://example.com/callback?state=query-token', 'GET', {
        Cookie: '__Host-CONSENTED_STATE-mcp=cookie-token',
      });

      await expect(client.validateOAuthState(request)).rejects.toThrow(OAuthError);
      await expect(client.validateOAuthState(request)).rejects.toThrow('State mismatch');
    });

    it('throws on missing/expired KV entry', async () => {
      const request = createMockRequest('https://example.com/callback?state=nonexistent-token', 'GET', {
        Cookie: '__Host-CONSENTED_STATE-mcp=nonexistent-token',
      });

      await expect(client.validateOAuthState(request)).rejects.toThrow(OAuthError);
      await expect(client.validateOAuthState(request)).rejects.toThrow('Invalid or expired state');
    });

    it('throws on invalid JSON in KV', async () => {
      const stateToken = 'test-state-token';

      // Store invalid JSON in KV
      await mockKV.put(`oauth:mcp:state:${stateToken}`, 'invalid-json-data', {
        expirationTtl: 600,
      });

      const request = createMockRequest(`https://example.com/callback?state=${stateToken}`, 'GET', {
        Cookie: `__Host-CONSENTED_STATE-mcp=${stateToken}`,
      });

      await expect(client.validateOAuthState(request)).rejects.toThrow(OAuthError);
      await expect(client.validateOAuthState(request)).rejects.toThrow('Invalid state data');

      try {
        await client.validateOAuthState(request);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect((error as OAuthError).code).toBe('server_error');
        expect((error as OAuthError).statusCode).toBe(500);
      }
    });
  });

  describe('isClientApproved()', () => {
    it('returns false with no cookie', async () => {
      const request = createMockRequest('https://example.com/authorize', 'GET');

      const result = await client.isClientApproved(request, 'client-123');

      expect(result).toBe(false);
    });

    it('returns false with invalid cookie', async () => {
      const request = createMockRequest('https://example.com/authorize', 'GET', {
        Cookie: '__Host-MCP_APPROVED_CLIENTS-mcp=invalid-format',
      });

      const result = await client.isClientApproved(request, 'client-123');

      expect(result).toBe(false);
    });

    it('returns true when client is in approved list', async () => {
      const clientId = 'client-123';

      // First, approve the client
      const setCookie = await client.addApprovedClient(
        createMockRequest('https://example.com/authorize', 'GET'),
        clientId
      );

      // Extract cookie value
      const cookieValue = setCookie.split(';')[0];

      // Check if client is approved
      const request = createMockRequest('https://example.com/authorize', 'GET', {
        Cookie: cookieValue,
      });

      const result = await client.isClientApproved(request, clientId);

      expect(result).toBe(true);
    });

    it('returns false when client is not in list', async () => {
      const clientId1 = 'client-123';
      const clientId2 = 'client-456';

      // Approve only client-123
      const setCookie = await client.addApprovedClient(
        createMockRequest('https://example.com/authorize', 'GET'),
        clientId1
      );

      const cookieValue = setCookie.split(';')[0];

      // Check if client-456 is approved
      const request = createMockRequest('https://example.com/authorize', 'GET', {
        Cookie: cookieValue,
      });

      const result = await client.isClientApproved(request, clientId2);

      expect(result).toBe(false);
    });

    it('verifies cookie signature', async () => {
      const clientId = 'client-123';

      // Create a properly signed cookie
      const setCookie = await client.addApprovedClient(
        createMockRequest('https://example.com/authorize', 'GET'),
        clientId
      );

      const cookieValue = setCookie.split(';')[0];
      const [cookieName, signedValue] = cookieValue.split('=');

      // Tamper with the signature
      const [signature, payload] = signedValue.split('.');
      const tamperedCookie = `${cookieName}=badsignature.${payload}`;

      const request = createMockRequest('https://example.com/authorize', 'GET', {
        Cookie: tamperedCookie,
      });

      const result = await client.isClientApproved(request, clientId);

      expect(result).toBe(false);
    });
  });

  describe('addApprovedClient()', () => {
    it('adds client to empty list', async () => {
      const clientId = 'client-123';
      const request = createMockRequest('https://example.com/authorize', 'GET');

      const setCookie = await client.addApprovedClient(request, clientId);

      expect(setCookie).toBeDefined();
      expect(typeof setCookie).toBe('string');

      // Verify the client was added
      const cookieValue = setCookie.split(';')[0];
      const checkRequest = createMockRequest('https://example.com/authorize', 'GET', {
        Cookie: cookieValue,
      });

      const isApproved = await client.isClientApproved(checkRequest, clientId);
      expect(isApproved).toBe(true);
    });

    it('adds client to existing list', async () => {
      const clientId1 = 'client-123';
      const clientId2 = 'client-456';

      // Add first client
      const setCookie1 = await client.addApprovedClient(
        createMockRequest('https://example.com/authorize', 'GET'),
        clientId1
      );

      const cookieValue1 = setCookie1.split(';')[0];

      // Add second client
      const setCookie2 = await client.addApprovedClient(
        createMockRequest('https://example.com/authorize', 'GET', {
          Cookie: cookieValue1,
        }),
        clientId2
      );

      const cookieValue2 = setCookie2.split(';')[0];

      // Verify both clients are approved
      const checkRequest = createMockRequest('https://example.com/authorize', 'GET', {
        Cookie: cookieValue2,
      });

      const isApproved1 = await client.isClientApproved(checkRequest, clientId1);
      const isApproved2 = await client.isClientApproved(checkRequest, clientId2);

      expect(isApproved1).toBe(true);
      expect(isApproved2).toBe(true);
    });

    it("doesn't duplicate clients", async () => {
      const clientId = 'client-123';

      // Add same client twice
      const setCookie1 = await client.addApprovedClient(
        createMockRequest('https://example.com/authorize', 'GET'),
        clientId
      );

      const cookieValue1 = setCookie1.split(';')[0];

      const setCookie2 = await client.addApprovedClient(
        createMockRequest('https://example.com/authorize', 'GET', {
          Cookie: cookieValue1,
        }),
        clientId
      );

      const cookieValue2 = setCookie2.split(';')[0];

      // Extract and decode the payload to verify no duplicates
      const [_, signedValue2] = cookieValue2.split('=');
      const [__, payload2] = signedValue2.split('.');
      const decodedPayload = JSON.parse(atob(payload2));

      expect(decodedPayload).toEqual([clientId]);
      expect(decodedPayload.length).toBe(1);
    });

    it('signs cookie correctly', async () => {
      const clientId = 'client-123';
      const request = createMockRequest('https://example.com/authorize', 'GET');

      const setCookie = await client.addApprovedClient(request, clientId);

      const cookieValue = setCookie.split(';')[0];
      const [_, signedValue] = cookieValue.split('=');
      const parts = signedValue.split('.');

      // Should have two parts: signature and payload
      expect(parts.length).toBe(2);

      // Signature should be a hex string
      const [signature, payload] = parts;
      expect(signature).toMatch(/^[0-9a-f]+$/);

      // Payload should be base64
      expect(() => atob(payload)).not.toThrow();
    });

    it('returns valid Set-Cookie header', async () => {
      const clientId = 'client-123';
      const request = createMockRequest('https://example.com/authorize', 'GET');

      const setCookie = await client.addApprovedClient(request, clientId);

      expect(setCookie).toContain('__Host-MCP_APPROVED_CLIENTS-mcp=');
      expect(setCookie).toContain('HttpOnly');
      expect(setCookie).toContain('Secure');
      expect(setCookie).toContain('Path=/');
      expect(setCookie).toContain('SameSite=Lax');
      expect(setCookie).toContain('Max-Age=31536000'); // 1 year
    });
  });

  describe('OAuthError', () => {
    it('creates error with code and description', () => {
      const error = new OAuthError('invalid_request', 'Missing required parameter');

      expect(error).toBeInstanceOf(OAuthError);
      expect(error).toBeInstanceOf(Error);
      expect(error.code).toBe('invalid_request');
      expect(error.description).toBe('Missing required parameter');
      expect(error.message).toBe('Missing required parameter');
      expect(error.name).toBe('OAuthError');
    });

    it('has correct default status (400)', () => {
      const error = new OAuthError('invalid_request', 'Missing required parameter');

      expect(error.statusCode).toBe(400);
    });

    it('accepts custom status code', () => {
      const error = new OAuthError('server_error', 'Internal server error', 500);

      expect(error.statusCode).toBe(500);
    });

    it('toResponse() returns JSON with error fields', () => {
      const error = new OAuthError('invalid_client', 'Client authentication failed', 401);

      const response = error.toResponse();

      expect(response).toBeInstanceOf(Response);
      expect(response.headers.get('Content-Type')).toBe('application/json');

      return response.json().then((body: any) => {
        expect(body.error).toBe('invalid_client');
        expect(body.error_description).toBe('Client authentication failed');
      });
    });

    it('toResponse() sets correct status code', () => {
      const error1 = new OAuthError('invalid_request', 'Bad request');
      const response1 = error1.toResponse();
      expect(response1.status).toBe(400);

      const error2 = new OAuthError('invalid_client', 'Unauthorized', 401);
      const response2 = error2.toResponse();
      expect(response2.status).toBe(401);

      const error3 = new OAuthError('server_error', 'Internal error', 500);
      const response3 = error3.toResponse();
      expect(response3.status).toBe(500);
    });
  });
});
