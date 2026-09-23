/**
 * RFC 9068 JWT access tokens, exercised only through what a deployer can reach: an
 * `OAuthAuthorizationServer` issuing over its token endpoint and publishing JWKS, and a
 * `createOAuthResourceServer` validating `offline`, `online`, or both. Adversarial cases
 * are rows in the flow they attack rather than tests of internal functions.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  JWT_ACCESS_TOKEN_GRANT_ID_CLAIM,
  JWT_ACCESS_TOKEN_PUBLIC_CLAIMS,
  OAuthAuthorizationServer,
  createJwtAccessTokens,
  createOAuthResourceServer,
  type JwtAlgorithm,
  type JwtKeySet,
  type JwtPublicKey,
  type JwtAccessTokensOptions,
  type OfflineTokenValidation,
} from '../src/oauth-provider';
import { MockExecutionContext, createMockEnv, createMockRequest, type TestEnv } from './test-helpers';

const ISSUER = 'https://auth.example.com';
const JWKS_URI = `${ISSUER}/.well-known/jwks.json`;
const CALENDAR = 'https://calendar.example.com/mcp';
const DRIVE = 'https://drive.example.com/mcp';
const REDIRECT_URI = 'https://client.example.com/callback';

type AuthProps = { userId: string; tenantId: string; upstreamAccessToken: string };
const PROPS: AuthProps = { userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'sk-confidential' };

// ---------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------

async function createKey(alg: JwtAlgorithm, kid: string, modulusLength = 2048) {
  const keyPair = (await crypto.subtle.generateKey(
    alg === 'RS256'
      ? { name: 'RSASSA-PKCS1-v1_5', modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }
      : { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair;
  const publicJwk: JwtPublicKey = {
    ...((await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey),
    kid,
    alg,
    use: 'sig',
    key_ops: ['verify'],
  };
  return { kid, alg, privateKey: keyPair.privateKey, publicJwk };
}
type Key = Awaited<ReturnType<typeof createKey>>;
const signingWith = (key: Key, verificationKeys: Key[] = []): JwtKeySet => ({
  signingKey: { kid: key.kid, alg: key.alg, privateKey: key.privateKey, publicJwk: key.publicJwk },
  verificationKeys: verificationKeys.map((k) => k.publicJwk),
});

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
const encodePart = (value: unknown) => base64url(new TextEncoder().encode(JSON.stringify(value)));
function decodePart(token: string, part: number): Record<string, any> {
  const encoded = token.split('.')[part].replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(atob(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, '=')));
}

/** Mint a token outside the authorization server, the way an attacker or another issuer would. */
async function signJwt(header: Record<string, unknown>, claims: unknown, key: Key | null): Promise<string> {
  const signingInput = `${encodePart(header)}.${encodePart(claims)}`;
  if (!key) return `${signingInput}.`;
  const algorithm = key.alg === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };
  const signature = await crypto.subtle.sign(algorithm, key.privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64url(new Uint8Array(signature))}`;
}

/** Claims the authorization server would have put in a calendar token, for forgeries to start from. */
function claimsFor(overrides: Record<string, unknown> = {}, now = Math.floor(Date.now() / 1000)) {
  return {
    iss: ISSUER,
    sub: 'user-123',
    aud: CALENDAR,
    client_id: 'client-123',
    scope: 'calendar:read',
    jti: 'jti-1',
    iat: now,
    exp: now + 3600,
    [JWT_ACCESS_TOKEN_GRANT_ID_CLAIM]: 'grant-123',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------------------
// The two Workers
// ---------------------------------------------------------------------------------------

function authorizationServer(
  env: TestEnv,
  keys: () => JwtKeySet,
  options: Partial<Pick<JwtAccessTokensOptions<TestEnv, AuthProps>, 'issuance' | 'publicClaims'>> & {
    issuer?: string;
    resources?: string[];
  } = {}
) {
  const issuer = options.issuer ?? ISSUER;
  return new OAuthAuthorizationServer<TestEnv, AuthProps>({
    issuer,
    resources: options.resources ?? [CALENDAR, DRIVE],
    authorizeEndpoint: '/authorize',
    tokenEndpoint: '/oauth/token',
    clientRegistrationEndpoint: '/oauth/register',
    scopesSupported: ['calendar:read', 'drive:read'],
    jwtAccessTokens: createJwtAccessTokens<TestEnv, AuthProps>({
      issuer,
      jwksUri: `${issuer}/.well-known/jwks.json`,
      keys,
      publicClaims: options.publicClaims ?? (({ props }) => ({ tenantId: props.tenantId })),
      issuance: options.issuance ?? true,
    }),
  });
}
type AS = ReturnType<typeof authorizationServer>;

/** Register a client, authorize, and return the code: everything before the token endpoint. */
async function authorize(as: AS, env: TestEnv, ctx: MockExecutionContext, resource = CALENDAR, issuer = ISSUER) {
  const registration = await as.fetch(
    createMockRequest(
      `${issuer}/oauth/register`,
      'POST',
      { 'Content-Type': 'application/json' },
      JSON.stringify({ redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: 'client_secret_post' })
    ),
    env,
    ctx
  );
  expect(registration.status).toBe(201);
  const client = await registration.json<any>();
  const url = new URL(`${issuer}/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', client.client_id);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', resource === DRIVE ? 'drive:read' : 'calendar:read');
  url.searchParams.set('resource', resource);
  const oauth = as.getOAuthApi(env);
  const request = await oauth.parseAuthRequest(createMockRequest(url.href));
  const { redirectTo } = await oauth.completeAuthorization({
    request,
    userId: PROPS.userId,
    metadata: {},
    scope: request.scope,
    props: PROPS,
  });
  const exchange = () =>
    as.fetch(
      createMockRequest(
        `${issuer}/oauth/token`,
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        new URLSearchParams({
          grant_type: 'authorization_code',
          code: new URL(redirectTo).searchParams.get('code')!,
          redirect_uri: REDIRECT_URI,
          client_id: client.client_id,
          client_secret: client.client_secret,
        }).toString()
      ),
      env,
      ctx
    );
  return { client, exchange };
}
async function issueToken(as: AS, env: TestEnv, ctx: MockExecutionContext, resource = CALENDAR): Promise<string> {
  const response = await (await authorize(as, env, ctx, resource)).exchange();
  expect(response.status).toBe(200);
  return (await response.json<any>()).access_token;
}

/** The resource Worker's view of the authorization server's JWKS: a Service Binding, with a call log. */
function jwksBinding(as: AS, env: TestEnv, ctx: MockExecutionContext, log: string[] = []) {
  return {
    log,
    source: {
      jwksUri: JWKS_URI,
      fetcher: () => ({
        fetch: (request: Request) => {
          log.push(request.url);
          return as.fetch(request, env, ctx);
        },
      }),
    },
  };
}

function offline(
  keys: OfflineTokenValidation<TestEnv, any>['keys'],
  overrides: Partial<OfflineTokenValidation<TestEnv, any>> = {}
): OfflineTokenValidation<TestEnv, any> {
  return {
    issuer: ISSUER,
    algorithms: ['RS256'],
    keys,
    mapClaimsToProps: ({ userId, scope, publicClaims, grantId, clientId }) =>
      publicClaims && typeof publicClaims === 'object' && !Array.isArray(publicClaims) && publicClaims.deny === true
        ? null
        : { userId, scope, grantId, clientId, tenantId: (publicClaims as any)?.tenantId, publicClaims },
    ...overrides,
  };
}

function resourceServer(
  validateToken: Parameters<typeof createOAuthResourceServer<TestEnv, any>>[0]['validateToken'],
  resource = CALENDAR,
  issuer = ISSUER
) {
  return createOAuthResourceServer<TestEnv, any>({
    resourceMetadata: { resource, authorization_servers: [issuer] },
    validateToken,
    handler: {
      fetch: (_request, _env, executionContext) => Response.json((executionContext as MockExecutionContext).props),
    },
  });
}
type RS = ReturnType<typeof resourceServer>;

async function call(rs: RS, env: TestEnv, ctx: MockExecutionContext, token: string, resource = CALENDAR) {
  const response = await rs.fetch(createMockRequest(resource, 'GET', { Authorization: `Bearer ${token}` }), env, ctx);
  return { status: response.status, body: response.status === 200 ? await response.json<any>() : null };
}

const jwksResponse = (keys: unknown[], headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ keys }), { headers: { 'Content-Type': 'application/json', ...headers } });

// ---------------------------------------------------------------------------------------

describe('JWT access tokens, end to end', () => {
  let env: TestEnv;
  let ctx: MockExecutionContext;
  let key: Key;

  beforeEach(async () => {
    env = createMockEnv();
    ctx = new MockExecutionContext();
    key = await createKey('RS256', 'key-2026-09');
  });

  it('issues a JWT the resource server verifies offline through the JWKS, and asks online for the rest', async () => {
    const jwtFor = new Set([CALENDAR]);
    const as = authorizationServer(env, () => signingWith(key), {
      issuance: ({ resource }) => jwtFor.has(resource),
    });

    // Issued over the token endpoint: the token is a signed at+jwt with the documented claims.
    const jwt = await issueToken(as, env, ctx);
    expect(decodePart(jwt, 0)).toEqual({ typ: 'at+jwt', alg: 'RS256', kid: key.kid });
    const claims = decodePart(jwt, 1);
    expect(claims).toMatchObject({ iss: ISSUER, sub: PROPS.userId, aud: CALENDAR, scope: 'calendar:read' });
    expect(claims[JWT_ACCESS_TOKEN_GRANT_ID_CLAIM]).toEqual(expect.any(String));
    expect(claims[JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]).toEqual({ tenantId: PROPS.tenantId });
    expect(JSON.stringify(claims)).not.toContain(PROPS.upstreamAccessToken);
    expect(claims.exp - claims.iat).toBe(3600);

    // Issuance is per token: drive stays opaque, and so does calendar once switched off.
    expect((await issueToken(as, env, ctx, DRIVE)).split(':')).toHaveLength(3);
    jwtFor.clear();
    const opaque = await issueToken(as, env, ctx);
    expect(opaque.split(':')).toHaveLength(3);

    // The JWKS is cacheable, carries only JWK members, and never private material.
    const jwks = await as.fetch(createMockRequest(JWKS_URI), env, ctx);
    expect(jwks.status).toBe(200);
    expect(jwks.headers.get('Cache-Control')).toBe('public, max-age=300');
    const published = (await jwks.json<{ keys: Record<string, unknown>[] }>()).keys;
    expect(published).toHaveLength(1);
    expect(Object.keys(published[0]).sort()).toEqual(['alg', 'e', 'kid', 'kty', 'n', 'use']);

    // Offline: the JWT verifies with one JWKS fetch over the binding; opaque cannot.
    const binding = jwksBinding(as, env, ctx);
    const offlineOnly = resourceServer({ offline: offline(binding.source) });
    expect(await call(offlineOnly, env, ctx, jwt)).toMatchObject({
      status: 200,
      body: { userId: PROPS.userId, tenantId: PROPS.tenantId, scope: ['calendar:read'] },
    });
    expect((await call(offlineOnly, env, ctx, opaque)).status).toBe(401);
    expect(binding.log).toEqual([JWKS_URI]);

    // Online: the authorization server, over what is a Service Binding in production.
    const onlineCalls: string[] = [];
    const online = () => ({
      validateToken: (token: string) => {
        onlineCalls.push(token);
        return as.resource(CALENDAR).validateToken<AuthProps>(token, env);
      },
    });
    const onlineOnly = resourceServer({ online });
    expect((await call(onlineOnly, env, ctx, opaque)).body).toMatchObject({ upstreamAccessToken: 'sk-confidential' });
    expect((await call(onlineOnly, env, ctx, jwt)).status).toBe(200);

    // Both: offline answers what it can without a round trip; the rest goes online.
    onlineCalls.length = 0;
    const both = resourceServer({ offline: offline(binding.source), online });
    expect((await call(both, env, ctx, jwt)).status).toBe(200);
    expect(onlineCalls).toEqual([]);
    expect((await call(both, env, ctx, opaque)).status).toBe(200);
    expect(onlineCalls).toEqual([opaque]);

    // A token for another resource is refused in every mode.
    const driveJwt = (jwtFor.add(DRIVE), await issueToken(as, env, ctx, DRIVE));
    for (const rs of [offlineOnly, onlineOnly, both]) expect((await call(rs, env, ctx, driveJwt)).status).toBe(401);
  });

  it('rejects forged, foreign and malformed tokens at the resource server, and fetches only the JWKS', async () => {
    const es256 = await createKey('ES256', 'es-key');
    const foreign = await createKey('RS256', key.kid); // an attacker's key, wearing the real kid
    const as = authorizationServer(env, () => signingWith(key, [es256]));
    const binding = jwksBinding(as, env, ctx);
    const rs = resourceServer({ offline: offline(binding.source) });
    const now = Math.floor(Date.now() / 1000);
    const header = (overrides: Record<string, unknown> = {}) => ({
      typ: 'at+jwt',
      alg: 'RS256',
      kid: key.kid,
      ...overrides,
    });
    const withoutClaim = (name: string) => {
      const rest: Record<string, unknown> = { ...claimsFor() };
      delete rest[name];
      return rest;
    };

    const rows: [string, () => Promise<string>, number][] = [
      ['a genuine token', () => signJwt(header(), claimsFor(), key), 200],
      ['typ application/at+jwt', () => signJwt(header({ typ: 'application/at+jwt' }), claimsFor(), key), 200],
      [
        'an aud array that contains the resource',
        () => signJwt(header(), claimsFor({ aud: [DRIVE, CALENDAR] }), key),
        200,
      ],
      ['a token in its last seconds', () => signJwt(header(), claimsFor({ exp: now + 5 }), key), 200],
      ['iat within the 30s skew', () => signJwt(header(), claimsFor({ iat: now + 29 }), key), 200],
      ['nbf within the 30s skew', () => signJwt(header(), claimsFor({ nbf: now + 29 }), key), 200],
      ['a signature from a foreign key with the real kid', () => signJwt(header(), claimsFor(), foreign), 401],
      ['alg none', () => signJwt(header({ alg: 'none' }), claimsFor(), null), 401],
      ['alg HS256', () => signJwt(header({ alg: 'HS256' }), claimsFor(), key), 401],
      [
        'an ES256 token when only RS256 is allowed',
        () => signJwt(header({ alg: 'ES256', kid: es256.kid }), claimsFor(), es256),
        401,
      ],
      ['a jku header', () => signJwt(header({ jku: 'https://attacker.example/jwks.json' }), claimsFor(), key), 401],
      ['a jwk header', () => signJwt(header({ jwk: foreign.publicJwk }), claimsFor(), key), 401],
      ['an x5u header', () => signJwt(header({ x5u: 'https://attacker.example/cert' }), claimsFor(), key), 401],
      ['an x5c header', () => signJwt(header({ x5c: ['MIIB'] }), claimsFor(), key), 401],
      ['a b64 header', () => signJwt(header({ b64: false }), claimsFor(), key), 401],
      ['a crit header', () => signJwt(header({ crit: ['exp'] }), claimsFor(), key), 401],
      ['typ JWT', () => signJwt(header({ typ: 'JWT' }), claimsFor(), key), 401],
      ['no kid', () => signJwt({ typ: 'at+jwt', alg: 'RS256' }, claimsFor(), key), 401],
      ['a kid over 128 characters', () => signJwt(header({ kid: 'k'.repeat(129) }), claimsFor(), key), 401],
      ['another issuer', () => signJwt(header(), claimsFor({ iss: 'https://other.example.com' }), key), 401],
      ['another audience', () => signJwt(header(), claimsFor({ aud: DRIVE }), key), 401],
      ['an expired token, even inside the skew', () => signJwt(header(), claimsFor({ exp: now - 5 }), key), 401],
      ['nbf beyond the skew', () => signJwt(header(), claimsFor({ nbf: now + 31 }), key), 401],
      ['iat in the future', () => signJwt(header(), claimsFor({ iat: now + 31, exp: now + 3600 }), key), 401],
      ['a non-string scope', () => signJwt(header(), claimsFor({ scope: 123 }), key), 401],
      ...(['sub', 'client_id', 'jti', 'exp', 'iat', JWT_ACCESS_TOKEN_GRANT_ID_CLAIM] as const).map(
        (name): [string, () => Promise<string>, number] => [
          `no ${name}`,
          () => signJwt(header(), withoutClaim(name), key),
          401,
        ]
      ),
      [
        'a tampered payload',
        async () => {
          const [h, p, s] = (await signJwt(header(), claimsFor(), key)).split('.');
          return `${h}.${encodePart({ ...decodePart(`${h}.${p}.${s}`, 1), scope: 'calendar:admin' })}.${s}`;
        },
        401,
      ],
      [
        'a token over 16 KiB',
        () => signJwt(header(), claimsFor({ [JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]: { pad: 'x'.repeat(17_000) } }), key),
        401,
      ],
      [
        'a public claim the mapper declines',
        () => signJwt(header(), claimsFor({ [JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]: { deny: true } }), key),
        401,
      ],
      ['not a JWT at all', async () => 'user:grant:secret', 401],
    ];
    for (const [name, mint, status] of rows) {
      expect({ name, status: (await call(rs, env, ctx, await mint())).status }).toEqual({ name, status });
    }

    // A __proto__ member in a public claim minted elsewhere is dropped before the mapper sees it.
    const proto = await signJwt(
      header(),
      claimsFor({ [JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]: JSON.parse('{"tenantId":"t","__proto__":{"polluted":true}}') }),
      key
    );
    const seen = await call(rs, env, ctx, proto);
    expect(seen.status).toBe(200);
    expect(Object.getOwnPropertyNames(seen.body.publicClaims)).toEqual(['tenantId']);
    expect(({} as any).polluted).toBeUndefined();

    // Every kid above was either known or rejected before key resolution, so one fetch served
    // the whole table, and nothing named by a token was ever fetched.
    expect(binding.log).toEqual([JWKS_URI]);

    // The same ES256 token is fine for a resource server that allows ES256.
    const es = resourceServer({ offline: offline(binding.source, { algorithms: ['ES256'] }) });
    expect(
      (await call(es, env, ctx, await signJwt(header({ alg: 'ES256', kid: es256.kid }), claimsFor(), es256))).status
    ).toBe(200);
  });

  it('rotates keys without invalidating tokens in flight, and refreshes for an unknown kid at most once per cooldown', async () => {
    const next = await createKey('RS256', 'key-2026-10');
    let keySet = signingWith(key);
    const as = authorizationServer(env, () => keySet);
    const binding = jwksBinding(as, env, ctx);
    const rs = resourceServer({ offline: offline(binding.source) });
    const realNow = Date.now;
    let skewMs = 0;
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => realNow() + skewMs);
    try {
      const first = await issueToken(as, env, ctx);
      expect((await call(rs, env, ctx, first)).status).toBe(200);
      expect(binding.log).toHaveLength(1);

      // 1. Stage the next public key. The resource server's cache does not need it yet.
      keySet = signingWith(key, [next]);
      expect((await call(rs, env, ctx, first)).status).toBe(200);
      expect(binding.log).toHaveLength(1);

      // 2. Promote it. The first token signed with it names a kid the cache lacks. Inside the
      // refresh cooldown that is indistinguishable from a guess and is refused; once the
      // cooldown has passed it costs exactly one refresh, which is why the rotation guidance
      // says to wait after publishing before signing.
      keySet = signingWith(next, [key]);
      const second = await issueToken(as, env, ctx);
      expect(decodePart(second, 0).kid).toBe(next.kid);
      expect((await call(rs, env, ctx, second)).status).toBe(401);
      expect(binding.log).toHaveLength(1);
      skewMs = 31_000;
      expect((await call(rs, env, ctx, second)).status).toBe(200);
      expect(binding.log).toHaveLength(2);
      expect((await call(rs, env, ctx, first)).status).toBe(200);

      // An invented kid is attacker input: inside the cooldown it never reaches the JWKS.
      const invented = (kid: string) => signJwt({ typ: 'at+jwt', alg: 'RS256', kid }, claimsFor(), next);
      for (let i = 0; i < 20; i++) expect((await call(rs, env, ctx, await invented(`guess-${i}`))).status).toBe(401);
      expect(binding.log).toHaveLength(2);
      skewMs = 62_000;
      expect((await call(rs, env, ctx, await invented('guess-later'))).status).toBe(401);
      expect(binding.log).toHaveLength(3);

      // 3. Retire the old key. It keeps verifying until the cache lifetime passes, then stops.
      keySet = signingWith(next);
      expect((await call(rs, env, ctx, first)).status).toBe(200);
      skewMs = 62_000 + 301_000;
      expect((await call(rs, env, ctx, first)).status).toBe(401);
      expect((await call(rs, env, ctx, second)).status).toBe(200);
    } finally {
      clock.mockRestore();
    }
  });

  it('caches the key set no longer than its Cache-Control allows, coalesces refreshes, and fails closed on a bad JWKS', async () => {
    const token = await signJwt({ typ: 'at+jwt', alg: 'RS256', kid: key.kid }, claimsFor(), key);
    const realNow = Date.now;
    let skewMs = 0;
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => realNow() + skewMs);
    // Fetch count after two validations at one instant, then after a third two seconds later.
    const fetchesFor = async (
      cacheControl: string,
      respond = () => jwksResponse([key.publicJwk], { 'Cache-Control': cacheControl })
    ) => {
      const fetch = vi.fn(async () => respond());
      const rs = resourceServer({
        offline: offline({ jwksUri: JWKS_URI, fetcher: () => ({ fetch }), cacheTtlSeconds: 3600 }),
      });
      skewMs = 0;
      expect((await call(rs, env, ctx, token)).status).toBe(200);
      await call(rs, env, ctx, token);
      const atOnce = fetch.mock.calls.length;
      skewMs = 2000;
      await call(rs, env, ctx, token);
      return [atOnce, fetch.mock.calls.length];
    };
    try {
      await expect(fetchesFor('no-store')).resolves.toEqual([2, 3]);
      await expect(fetchesFor('no-cache')).resolves.toEqual([2, 3]);
      await expect(fetchesFor('public, max-age=0')).resolves.toEqual([2, 3]);
      await expect(fetchesFor('NO-CACHE, max-age=300')).resolves.toEqual([2, 3]);
      await expect(fetchesFor('max-age=soon')).resolves.toEqual([2, 3]);
      await expect(fetchesFor('max-age=3600, max-age=1')).resolves.toEqual([1, 2]);
      await expect(fetchesFor('Public, Max-Age="1"')).resolves.toEqual([1, 2]);
      await expect(fetchesFor('private, s-maxage=0, stale-while-revalidate=30')).resolves.toEqual([1, 1]);
      await expect(fetchesFor('public')).resolves.toEqual([1, 1]);

      // Ten validations during one in-flight fetch share it, even when the response forbids reuse.
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      const gated = vi.fn(async () => {
        await gate;
        return jwksResponse([key.publicJwk], { 'Cache-Control': 'no-store' });
      });
      const shared = resourceServer({ offline: offline({ jwksUri: JWKS_URI, fetcher: () => ({ fetch: gated }) }) });
      const pending = Array.from({ length: 10 }, () => call(shared, env, ctx, token));
      release();
      for (const result of await Promise.all(pending)) expect(result.status).toBe(200);
      expect(gated).toHaveBeenCalledTimes(1);

      // A JWKS that cannot be used is an outage, not an invalid token: 503, never 401.
      for (const respond of [
        () => new Response('nope', { status: 503 }),
        () => new Response('{}', { headers: { 'Content-Type': 'application/json' } }),
        () => jwksResponse([{ kid: 'x'.repeat(70_000) }]),
      ]) {
        const rs = resourceServer({
          offline: offline({ jwksUri: JWKS_URI, fetcher: () => ({ fetch: async () => respond() }) }),
        });
        expect((await call(rs, env, ctx, token)).status).toBe(503);
      }
      // A key set that simply lacks the token's key is an invalid token.
      const other = await createKey('RS256', 'someone-else');
      const noKey = resourceServer({
        offline: offline({
          jwksUri: JWKS_URI,
          fetcher: () => ({ fetch: async () => jwksResponse([other.publicJwk]) }),
        }),
      });
      expect((await call(noKey, env, ctx, token)).status).toBe(401);
    } finally {
      clock.mockRestore();
    }
  });

  it('refuses unsafe key material at both endpoints and leaves the authorization code retryable', async () => {
    const other = await createKey('RS256', 'other');
    const weak = await createKey('RS256', 'weak', 1024);
    const withJwk = (patch: Partial<JsonWebKey> & Record<string, unknown>): JwtKeySet => ({
      signingKey: { ...signingWith(key).signingKey, publicJwk: { ...key.publicJwk, ...patch } as JwtPublicKey },
    });
    const rows: [string, JwtKeySet][] = [
      ['private material in the public JWK', withJwk({ d: 'AQAB' })],
      ['a public exponent of 3', withJwk({ e: 'Aw' })],
      ['an even public exponent', withJwk({ e: 'AQAC' })],
      ['key_ops that allow signing', withJwk({ key_ops: ['sign'] })],
      ['a 1024-bit RSA key', signingWith(weak)],
      [
        'a public JWK that is not the private key\u2019s pair',
        { signingKey: { ...signingWith(key).signingKey, publicJwk: other.publicJwk } },
      ],
      ['a duplicate kid', signingWith(key, [key])],
    ];
    for (const [name, bad] of rows) {
      let keySet = bad;
      const as = authorizationServer(env, () => keySet);
      const jwks = await as.fetch(createMockRequest(JWKS_URI), env, ctx);
      expect({ name, status: jwks.status }).toEqual({ name, status: 503 });

      const { exchange } = await authorize(as, env, ctx);
      const failed = await exchange();
      expect({ name, status: failed.status, error: (await failed.json<any>()).error }).toEqual({
        name,
        status: 500,
        error: 'server_error',
      });
      // Signing failed before the grant write, so the same code still exchanges once the keys are fixed.
      keySet = signingWith(key);
      expect({ name, status: (await exchange()).status }).toEqual({ name, status: 200 });
    }
  });

  it('projects only public claims from a snapshot, and refuses a projection that cannot travel in a token', async () => {
    let projection: (input: { props: AuthProps; scope: readonly string[] }) => unknown = ({ props }) => ({
      tenantId: props.tenantId,
    });
    const as = authorizationServer(env, () => signingWith(key), {
      publicClaims: (input) => projection(input) as any,
    });

    // The projector sees a frozen snapshot: its attempts to change the token change nothing.
    projection = (input) => {
      expect(Object.isFrozen(input)).toBe(true);
      expect(() => ((input as any).scope = ['calendar:admin'])).toThrow();
      return { tenantId: input.props.tenantId, scope: [...input.scope] };
    };
    const claims = decodePart(await issueToken(as, env, ctx), 1);
    expect(claims.scope).toBe('calendar:read');
    expect(claims[JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]).toEqual({ tenantId: PROPS.tenantId, scope: ['calendar:read'] });

    const deep = (depth: number): unknown => (depth === 0 ? true : { next: deep(depth - 1) });
    const rows: [string, unknown][] = [
      ['a __proto__ member', JSON.parse('{"__proto__":{"polluted":true}}')],
      ['a value that is not JSON', { when: () => 'now' }],
      ['nesting deeper than 64 levels', deep(65)],
      ['more than a token can carry', { pad: 'x'.repeat(17_000) }],
    ];
    for (const [name, value] of rows) {
      projection = () => value;
      const { exchange } = await authorize(as, env, ctx);
      const failed = await exchange();
      expect({ name, status: failed.status }).toEqual({ name, status: 500 });
      projection = () => ({ ok: true });
      expect({ name, retried: (await exchange()).status }).toEqual({ name, retried: 200 });
    }

    // Omitting the projection leaves the public claim out entirely.
    const bare = authorizationServer(env, () => signingWith(key), { publicClaims: () => undefined });
    expect(decodePart(await issueToken(bare, env, ctx), 1)).not.toHaveProperty(JWT_ACCESS_TOKEN_PUBLIC_CLAIMS);
  });

  it('runs on plain http for loopback development, and only there', async () => {
    const issuer = 'http://localhost:8787';
    const resource = 'http://127.0.0.1:8788/mcp';
    const as = authorizationServer(env, () => signingWith(key), { issuer, resources: [resource] });
    const { exchange } = await authorize(as, env, ctx, resource, issuer);
    const token = (await (await exchange()).json<any>()).access_token as string;
    expect(decodePart(token, 1)).toMatchObject({ iss: issuer, aud: resource });

    const rs = resourceServer(
      {
        offline: offline(
          {
            jwksUri: `${issuer}/.well-known/jwks.json`,
            fetcher: () => ({ fetch: (request: Request) => as.fetch(request, env, ctx) }),
          },
          { issuer }
        ),
      },
      resource,
      issuer
    );
    expect((await call(rs, env, ctx, token, resource)).status).toBe(200);

    expect(() =>
      createJwtAccessTokens<TestEnv>({
        issuer: 'http://auth.example.com',
        jwksUri: 'http://auth.example.com/jwks',
        keys: () => signingWith(key),
      })
    ).toThrow();
    expect(() => resourceServer({ offline: offline({ jwksUri: 'http://auth.example.com/jwks' }) })).toThrow();
  });

  it('validates its configuration up front', async () => {
    expect(() =>
      createJwtAccessTokens<TestEnv>({
        issuer: ISSUER,
        jwksUri: JWKS_URI,
        keys: () => signingWith(key),
        issuance: 'jwt' as any,
      })
    ).toThrow('issuance must be a boolean or a function');
    expect(() => createJwtAccessTokens<TestEnv>({ issuer: ISSUER, jwksUri: JWKS_URI, keys: 'nope' as any })).toThrow(
      'keys must be a function'
    );
    expect(() => resourceServer({})).toThrow('validateToken must name an offline or online mode');
    expect(() => resourceServer({ online: 'binding' as any })).toThrow('validateToken.online must be a function');
    expect(() => resourceServer({ offline: offline({ jwksUri: JWKS_URI }, { algorithms: [] as any }) })).toThrow();
    expect(() =>
      resourceServer({ offline: offline({ jwksUri: JWKS_URI }, { mapClaimsToProps: undefined as any }) })
    ).toThrow('mapClaimsToProps must be a function');
    expect(() => resourceServer({ offline: offline({ jwksUri: JWKS_URI, cacheTtlSeconds: 0 }) })).toThrow(
      'cacheTtlSeconds must be an integer between 1 and 86400'
    );

    // An online binding that is missing at request time is an outage, not an invalid token.
    const rs = resourceServer({ online: () => undefined });
    expect((await call(rs, env, ctx, 'any')).status).toBe(503);
  });
});
