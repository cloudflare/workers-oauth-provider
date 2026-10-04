import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest';
import { CimdFetchError, OAuthProvider as BaseOAuthProvider, type OAuthProviderOptions } from '../src/oauth-provider';
import {
  MockExecutionContext,
  TestApiHandler,
  createMockEnv,
  createMockRequest,
  testDefaultHandler,
  type TestEnv,
} from './test-helpers';

// private_key_jwt client authentication (RFC 7523 §2.2) for Client ID Metadata Document clients.

const ISSUER = 'https://example.com';
const TOKEN_ENDPOINT = 'https://example.com/oauth/token';
const CLIENT_ID = 'https://client.example.com/oauth/metadata.json';
const JWKS_URI = 'https://client.example.com/oauth/jwks.json';
const REDIRECT_URI = 'https://client.example.com/callback';
const CODE_VERIFIER = 'private-key-jwt-code-verifier-that-is-at-least-43-characters';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

type Alg = 'RS256' | 'ES256';
type OnError = NonNullable<OAuthProviderOptions<TestEnv>['onError']>;

interface SigningKey {
  alg: Alg;
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JsonWebKey & { kid: string };
}

async function generateSigningKey(alg: Alg, kid: string): Promise<SigningKey> {
  const params =
    alg === 'RS256'
      ? { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }
      : { name: 'ECDSA', namedCurve: 'P-256' };
  const pair = (await crypto.subtle.generateKey(params, true, ['sign', 'verify'])) as CryptoKeyPair;
  const publicJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
  return { alg, kid, privateKey: pair.privateKey, publicJwk: { ...publicJwk, kid } };
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

const encodeJson = (value: unknown) => base64Url(new TextEncoder().encode(JSON.stringify(value)));

let jtiCounter = 0;

/** Signs a client assertion. Claims and header fields can be overridden, or removed with `undefined`. */
async function signAssertion(
  key: SigningKey,
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {}
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const fullHeader = { alg: key.alg, kid: key.kid, typ: 'JWT', ...header };
  const fullClaims = {
    iss: CLIENT_ID,
    sub: CLIENT_ID,
    aud: TOKEN_ENDPOINT,
    exp: now + 300,
    iat: now,
    jti: `jti-${++jtiCounter}`,
    ...claims,
  };
  const strip = (value: Record<string, unknown>) =>
    Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined));
  const signingInput = `${encodeJson(strip(fullHeader))}.${encodeJson(strip(fullClaims))}`;
  const algorithm = key.alg === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };
  const signature = await crypto.subtle.sign(algorithm, key.privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
}

function form(params: Record<string, string | undefined>): string {
  return Object.entries(params)
    .filter(([, value]) => value !== undefined)
    .map(([name, value]) => `${name}=${encodeURIComponent(value!)}`)
    .join('&');
}

describe('CIMD private_key_jwt client authentication', () => {
  let originalFetch: typeof globalThis.fetch;
  let originalCloudflare: Cloudflare | undefined;
  let mockEnv: TestEnv;
  let mockCtx: MockExecutionContext;
  let provider: BaseOAuthProvider<TestEnv>;
  let onError: Mock<OnError>;
  let codeChallenge: string;
  /** Documents the mocked network serves, by URL. */
  let documents: Map<string, () => unknown>;
  let fetchMock: ReturnType<typeof vi.fn>;

  function createProvider(options: Partial<OAuthProviderOptions<TestEnv>> = {}) {
    return new BaseOAuthProvider<TestEnv>({
      apiRoute: ['/api/'],
      apiHandler: TestApiHandler,
      defaultHandler: testDefaultHandler,
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      scopesSupported: ['read', 'write'],
      clientIdMetadataDocumentEnabled: true,
      resourceMetadata: { resource: ISSUER },
      onError,
      ...options,
    });
  }

  beforeEach(async () => {
    vi.resetAllMocks();
    mockEnv = createMockEnv();
    mockCtx = new MockExecutionContext();
    originalFetch = globalThis.fetch;
    originalCloudflare = (globalThis as { Cloudflare?: Cloudflare }).Cloudflare;
    (globalThis as any).Cloudflare = { compatibilityFlags: { global_fetch_strictly_public: true } };
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    documents = new Map();
    fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      const document = documents.get(url);
      if (!document) return new Response('Not Found', { status: 404 });
      return new Response(JSON.stringify(document()), { headers: { 'Content-Type': 'application/json' } });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    onError = vi.fn<OnError>();
    provider = createProvider();

    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(CODE_VERIFIER));
    codeChallenge = base64Url(new Uint8Array(digest));
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    (globalThis as any).Cloudflare = originalCloudflare;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  function serveMetadata(metadata: Record<string, unknown>) {
    documents.set(CLIENT_ID, () => ({
      client_id: CLIENT_ID,
      client_name: 'Private Key Client',
      redirect_uris: [REDIRECT_URI],
      grant_types: ['authorization_code', 'refresh_token'],
      ...metadata,
    }));
  }

  async function authorize(): Promise<string> {
    const response = await provider.fetch(
      createMockRequest(
        `https://example.com/authorize?client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&state=s&code_challenge=${codeChallenge}&code_challenge_method=S256`
      ),
      mockEnv,
      mockCtx
    );
    expect(response.status).toBe(302);
    return new URL(response.headers.get('Location')!).searchParams.get('code')!;
  }

  function tokenRequest(params: Record<string, string | undefined>, headers: Record<string, string> = {}) {
    return provider.fetch(
      createMockRequest(
        TOKEN_ENDPOINT,
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
        form(params)
      ),
      mockEnv,
      mockCtx
    );
  }

  function exchangeCode(code: string, auth: Record<string, string | undefined>) {
    return tokenRequest({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: CODE_VERIFIER,
      ...auth,
    });
  }

  function lastInternalError() {
    const calls = onError.mock.calls;
    return calls[calls.length - 1]?.[0].internal;
  }

  describe('a client that requires private_key_jwt', () => {
    let key: SigningKey;

    beforeEach(async () => {
      key = await generateSigningKey('ES256', 'key-1');
      serveMetadata({ token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [key.publicJwk] } });
    });

    it('exchanges a code and refreshes with signed assertions', async () => {
      const code = await authorize();
      const tokenResponse = await exchangeCode(code, {
        client_id: CLIENT_ID,
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key),
      });
      expect(tokenResponse.status).toBe(200);
      const tokens = await tokenResponse.json<any>();
      expect(tokens.access_token).toEqual(expect.any(String));

      const refreshResponse = await tokenRequest({
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token,
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key),
      });
      expect(refreshResponse.status).toBe(200);
    });

    it('refuses a request that presents no credential', async () => {
      const code = await authorize();
      const response = await exchangeCode(code, { client_id: CLIENT_ID });

      expect(response.status).toBe(401);
      expect(await response.json<any>()).toMatchObject({ error: 'invalid_client' });
      expect(lastInternalError()).toMatchObject({
        reason: 'token_endpoint_auth_method_mismatch',
        detail: { registeredMethod: 'private_key_jwt', presentedMethod: 'none' },
      });
    });

    it('accepts an assertion whose audience is the issuer identifier', async () => {
      const code = await authorize();
      const response = await exchangeCode(code, {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key, { aud: ISSUER }),
      });
      expect(response.status).toBe(200);
    });

    it('accepts an RFC 7523bis typed assertion addressed to the issuer', async () => {
      const code = await authorize();
      const response = await exchangeCode(code, {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key, { aud: ISSUER }, { typ: 'client-authentication+jwt' }),
      });
      expect(response.status).toBe(200);
    });

    it.each<[string, Record<string, unknown>, Record<string, unknown>, Record<string, unknown>]>([
      ['another audience', { aud: 'https://other.example.com' }, {}, { reason: 'aud_mismatch' }],
      [
        'a typed assertion addressed to the token endpoint',
        { aud: TOKEN_ENDPOINT },
        { typ: 'client-authentication+jwt' },
        { reason: 'aud_mismatch' },
      ],
      ['an expired assertion', { exp: Math.floor(Date.now() / 1000) - 120 }, {}, { reason: 'expired' }],
      [
        'an assertion valid for over an hour',
        { exp: Math.floor(Date.now() / 1000) + 2 * 60 * 60 },
        {},
        { reason: 'lifetime_too_long' },
      ],
      ['a missing jti', { jti: undefined }, {}, { reason: 'invalid_claim', claim: 'jti' }],
      ['another issuer', { iss: 'https://attacker.example.com/client.json' }, {}, { reason: 'client_id_mismatch' }],
      ['another subject', { sub: 'user-123' }, {}, { reason: 'client_id_mismatch' }],
      ['a future nbf', { nbf: Math.floor(Date.now() / 1000) + 600 }, {}, { reason: 'nbf_in_future' }],
      ['another kind of JWT', {}, { typ: 'oauth-id-jag+jwt' }, { reason: 'invalid_typ' }],
      ['an unlisted algorithm', {}, { alg: 'HS256' }, { reason: 'invalid_alg' }],
      ['a critical extension', {}, { crit: ['exp'] }, { reason: 'assertion_malformed' }],
      ['an unknown kid', {}, { kid: 'key-2' }, { reason: 'no_matching_key' }],
    ])('rejects %s', async (_label, claims, header, error) => {
      const code = await authorize();
      const response = await exchangeCode(code, {
        client_id: CLIENT_ID,
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key, claims, header),
      });

      expect(response.status).toBe(401);
      expect(await response.json<any>()).toEqual({
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      });
      expect(lastInternalError()).toMatchObject({
        category: 'client-authentication',
        reason: 'client_assertion_invalid',
        detail: { clientId: CLIENT_ID, ...error },
      });

      // A rejected assertion consumes nothing: the code still works.
      const retry = await exchangeCode(code, {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key),
      });
      expect(retry.status).toBe(200);
    });

    it('rejects an assertion signed by a key the document does not list', async () => {
      const impostor = await generateSigningKey('ES256', 'key-1');
      const code = await authorize();
      const response = await exchangeCode(code, {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(impostor),
      });

      expect(response.status).toBe(401);
      expect(lastInternalError()).toMatchObject({ detail: { reason: 'signature_failed' } });
    });

    it('rejects a replayed assertion', async () => {
      const assertion = await signAssertion(key);
      const first = await exchangeCode(await authorize(), {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: assertion,
      });
      expect(first.status).toBe(200);

      const second = await exchangeCode(await authorize(), {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: assertion,
      });
      expect(second.status).toBe(401);
      expect(lastInternalError()).toMatchObject({ detail: { reason: 'replayed' } });
    });

    it('rejects an unsupported client_assertion_type', async () => {
      const response = await exchangeCode(await authorize(), {
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:saml2-bearer',
        client_assertion: await signAssertion(key),
      });

      expect(response.status).toBe(401);
      expect(lastInternalError()).toMatchObject({ reason: 'client_assertion_type_unsupported' });
    });

    it('rejects a client_id that disagrees with the assertion issuer', async () => {
      // The request names another (none) client; the assertion is then checked against that client.
      documents.set('https://other.example.com/client.json', () => ({
        client_id: 'https://other.example.com/client.json',
        client_name: 'Other',
        redirect_uris: ['https://other.example.com/callback'],
        token_endpoint_auth_method: 'none',
      }));
      const response = await exchangeCode(await authorize(), {
        client_id: 'https://other.example.com/client.json',
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key),
      });

      expect(response.status).toBe(401);
      expect(lastInternalError()).toMatchObject({ reason: 'token_endpoint_auth_method_mismatch' });
    });

    it.each<[string, Record<string, string | undefined>, Record<string, string>]>([
      ['a client secret', { client_secret: 'secret' }, {}],
      ['Basic credentials', {}, { Authorization: `Basic ${btoa(`${encodeURIComponent(CLIENT_ID)}:x`)}` }],
    ])('refuses an assertion sent alongside %s', async (_label, extra, headers) => {
      const response = await tokenRequest(
        {
          grant_type: 'authorization_code',
          code: 'unused',
          client_assertion_type: ASSERTION_TYPE,
          client_assertion: await signAssertion(key),
          ...extra,
        },
        headers
      );

      expect(response.status).toBe(400);
      expect(await response.json<any>()).toMatchObject({ error: 'invalid_request' });
    });

    it('refuses a client_assertion without its type', async () => {
      const response = await tokenRequest({
        grant_type: 'authorization_code',
        code: 'unused',
        client_assertion: await signAssertion(key),
      });

      expect(response.status).toBe(400);
      expect(lastInternalError()).toMatchObject({ reason: 'client_assertion_incomplete' });
    });

    it('authenticates a revocation request', async () => {
      const tokens = await (
        await exchangeCode(await authorize(), {
          client_assertion_type: ASSERTION_TYPE,
          client_assertion: await signAssertion(key),
        })
      ).json<any>();

      const revoke = await tokenRequest({
        token: tokens.refresh_token,
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key),
      });
      expect(revoke.status).toBe(200);

      const refresh = await tokenRequest({
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token,
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key),
      });
      expect(refresh.status).toBe(400);
    });
  });

  describe('keys published at jwks_uri', () => {
    it('verifies against the fetched JWKS and identifies the client from the assertion', async () => {
      const key = await generateSigningKey('RS256', 'rsa-1');
      serveMetadata({ token_endpoint_auth_method: 'private_key_jwt', jwks_uri: JWKS_URI });
      documents.set(JWKS_URI, () => ({ keys: [key.publicJwk] }));

      const response = await exchangeCode(await authorize(), {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key),
      });

      expect(response.status).toBe(200);
      expect(fetchMock).toHaveBeenCalledWith(
        JWKS_URI,
        expect.objectContaining({
          headers: expect.objectContaining({ 'User-Agent': expect.stringMatching(/^workers-oauth-provider\//) }),
        })
      );
    });

    it('caches the JWKS, and refetches it for a rotated kid once the cool-down allows', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const oldKey = await generateSigningKey('ES256', 'old');
      const newKey = await generateSigningKey('ES256', 'new');
      let published = [oldKey.publicJwk];
      serveMetadata({ token_endpoint_auth_method: 'private_key_jwt', jwks_uri: JWKS_URI });
      documents.set(JWKS_URI, () => ({ keys: published }));
      const jwksFetches = () => fetchMock.mock.calls.filter(([url]) => String(url) === JWKS_URI).length;

      for (let i = 0; i < 2; i++) {
        const response = await exchangeCode(await authorize(), {
          client_assertion_type: ASSERTION_TYPE,
          client_assertion: await signAssertion(oldKey),
        });
        expect(response.status).toBe(200);
      }
      expect(jwksFetches()).toBe(1);

      // Within the force-refresh cool-down an unknown kid can't make this server refetch, so a
      // stream of random kids can't be turned against the client's JWKS host.
      published = [newKey.publicJwk];
      const tooSoon = await exchangeCode(await authorize(), {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(newKey),
      });
      expect(tooSoon.status).toBe(401);
      expect(jwksFetches()).toBe(1);

      vi.setSystemTime(Date.now() + 31_000);
      const rotated = await exchangeCode(await authorize(), {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(newKey),
      });
      expect(rotated.status).toBe(200);
      expect(jwksFetches()).toBe(2);
    });

    it('reports a JWKS that cannot be fetched', async () => {
      const key = await generateSigningKey('ES256', 'key-1');
      serveMetadata({ token_endpoint_auth_method: 'private_key_jwt', jwks_uri: JWKS_URI });

      const response = await exchangeCode(await authorize(), {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key),
      });

      expect(response.status).toBe(401);
      expect(lastInternalError()).toMatchObject({ detail: { reason: 'jwks_fetch_failed' } });
    });

    it('holds the client to its token_endpoint_auth_signing_alg', async () => {
      const key = await generateSigningKey('ES256', 'key-1');
      serveMetadata({
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'RS256',
        jwks_uri: JWKS_URI,
      });
      documents.set(JWKS_URI, () => ({ keys: [key.publicJwk] }));

      const response = await exchangeCode(await authorize(), {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key),
      });

      expect(response.status).toBe(401);
      expect(lastInternalError()).toMatchObject({ detail: { reason: 'invalid_alg', got: 'ES256' } });
    });
  });

  describe('a client that offers none and private_key_jwt (ChatGPT)', () => {
    // ChatGPT's live document, which prefers private_key_jwt and also lists none.
    let key: SigningKey;

    beforeEach(async () => {
      key = await generateSigningKey('RS256', 'chatgpt');
      serveMetadata({
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
        token_endpoint_auth_signing_alg: 'RS256',
        jwks_uri: JWKS_URI,
      });
      documents.set(JWKS_URI, () => ({ keys: [key.publicJwk] }));
    });

    it('accepts either method, and records none so PKCE stays required', async () => {
      const unauthenticated = await exchangeCode(await authorize(), { client_id: CLIENT_ID });
      expect(unauthenticated.status).toBe(200);

      const authenticated = await exchangeCode(await authorize(), {
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key),
      });
      expect(authenticated.status).toBe(200);

      const client = await mockEnv.OAUTH_PROVIDER!.lookupClient(CLIENT_ID);
      expect(client?.tokenEndpointAuthMethod).toBe('none');
      expect(client).not.toHaveProperty('tokenEndpointAuthMethods');
      expect(client).not.toHaveProperty('clientAssertionKeys');

      await expect(
        provider.fetch(
          createMockRequest(
            `https://example.com/authorize?client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&state=s`
          ),
          mockEnv,
          mockCtx
        )
      ).rejects.toThrow('Public clients must use PKCE');
    });

    it('still rejects a bad assertion rather than falling back to none', async () => {
      const response = await exchangeCode(await authorize(), {
        client_id: CLIENT_ID,
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await signAssertion(key, { aud: 'https://other.example.com' }),
      });
      expect(response.status).toBe(401);
    });

    it('keeps working with none when the document has no usable keys', async () => {
      serveMetadata({
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
      });

      const response = await exchangeCode(await authorize(), { client_id: CLIENT_ID });
      expect(response.status).toBe(200);
    });
  });

  describe('documents whose private_key_jwt offer is unusable', () => {
    it.each<[string, Record<string, unknown>]>([
      ['supplies no keys', {}],
      ['uses an http: jwks_uri', { jwks_uri: 'http://client.example.com/jwks.json' }],
      ['supplies both jwks and jwks_uri', { jwks_uri: JWKS_URI, jwks: { keys: [{ kty: 'EC' }] } }],
      ['supplies an empty jwks', { jwks: { keys: [] } }],
      ['requires an unimplemented algorithm', { jwks_uri: JWKS_URI, token_endpoint_auth_signing_alg: 'PS256' }],
    ])('refuses a client whose sole method is private_key_jwt and which %s', async (_label, metadata) => {
      serveMetadata({ token_endpoint_auth_method: 'private_key_jwt', ...metadata });

      await expect(
        provider.fetch(
          createMockRequest(
            `https://example.com/authorize?client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&state=s&code_challenge=${codeChallenge}&code_challenge_method=S256`
          ),
          mockEnv,
          mockCtx
        )
      ).rejects.toThrow(CimdFetchError);
    });
  });

  it('does not accept an assertion from a registered (non-CIMD) client', async () => {
    // A default-handler request populates env.OAUTH_PROVIDER.
    await provider.fetch(createMockRequest('https://example.com/'), mockEnv, mockCtx);
    const client = await mockEnv.OAUTH_PROVIDER!.createClient({
      redirectUris: [REDIRECT_URI],
      tokenEndpointAuthMethod: 'none',
    });
    const key = await generateSigningKey('ES256', 'key-1');

    const response = await tokenRequest({
      grant_type: 'authorization_code',
      code: 'unused',
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: await signAssertion(key, { iss: client.clientId, sub: client.clientId }),
    });

    expect(response.status).toBe(401);
    expect(lastInternalError()).toMatchObject({
      reason: 'token_endpoint_auth_method_mismatch',
      detail: { presentedMethod: 'private_key_jwt' },
    });
  });

  describe('authorization server metadata', () => {
    async function metadata() {
      const response = await provider.fetch(
        createMockRequest('https://example.com/.well-known/oauth-authorization-server'),
        mockEnv,
        mockCtx
      );
      return response.json<any>();
    }

    it('advertises private_key_jwt and its algorithms when CIMD is supported', async () => {
      expect(await metadata()).toMatchObject({
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none', 'private_key_jwt'],
        token_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256'],
      });
    });

    it('advertises neither without the global_fetch_strictly_public flag', async () => {
      (globalThis as any).Cloudflare = { compatibilityFlags: {} };
      const body = await metadata();
      expect(body.token_endpoint_auth_methods_supported).not.toContain('private_key_jwt');
      expect(body).not.toHaveProperty('token_endpoint_auth_signing_alg_values_supported');
    });

    it('advertises neither when CIMD is disabled', async () => {
      provider = createProvider({ clientIdMetadataDocumentEnabled: false });
      const body = await metadata();
      expect(body.token_endpoint_auth_methods_supported).not.toContain('private_key_jwt');
      expect(body).not.toHaveProperty('token_endpoint_auth_signing_alg_values_supported');
    });
  });
});
