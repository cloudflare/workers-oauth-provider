import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { decodeJwt, decodeProtectedHeader, SignJWT, importJWK, UnsecuredJWT } from 'jose';
import {
  createJwtAccessTokenValidator,
  OAuthAuthorizationServer,
  type AccessTokenOptions,
  type JwtAccessTokenOptions,
  type JwtClaimValue,
  type JwtKey,
  type OAuthHelpers,
} from '../src/oauth-provider';
import { createMockEnv, MockExecutionContext, type TestEnv } from './test-helpers';

const ISSUER = 'https://auth.example.com';
const RESOURCE = 'https://mcp.example.com/mcp';
const OTHER_RESOURCE = 'https://other.example.com/mcp';
const REDIRECT_URI = 'https://client.example/callback';
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXkdBjftJeZ4CVP-mB92K27uhbUJU1p1r';

async function generateKey(kid: string): Promise<JwtKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  return { ...(jwk as JwtKey), kty: 'EC', crv: 'P-256', kid };
}

function publicOf(key: JwtKey): JwtKey {
  const { d: _d, ...rest } = key;
  return rest as JwtKey;
}

async function challengeFor(verifier: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  return btoa(String.fromCharCode(...digest))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

let env: TestEnv;
let current: JwtKey;

/** A server issuing JWTs with `jwt`, or the full `accessTokens` configuration when given. */
function createServer(jwt?: JwtAccessTokenOptions<TestEnv>, accessTokens?: AccessTokenOptions<TestEnv>) {
  return new OAuthAuthorizationServer<TestEnv>({
    issuer: ISSUER,
    resources: [RESOURCE, OTHER_RESOURCE],
    defaultResource: RESOURCE,
    authorizeEndpoint: '/authorize',
    tokenEndpoint: '/oauth/token',
    scopesSupported: ['read', 'write'],
    accessTokenTTL: 300,
    accessTokens: accessTokens ?? (jwt ? { issuing: 'jwt', jwt } : undefined),
  });
}

function defaultJwtOptions(overrides: Partial<JwtAccessTokenOptions<TestEnv>> = {}): JwtAccessTokenOptions<TestEnv> {
  return { keys: () => ({ current }), ...overrides };
}

/** Run a full authorization code flow and return the token response. */
async function authorize(
  server: OAuthAuthorizationServer<TestEnv>,
  options: { props?: unknown; scope?: string } = {}
): Promise<{ access_token: string; refresh_token: string; clientId: string; code: string; response: Response }> {
  const oauth: OAuthHelpers = server.getOAuthApi(env);
  const client = await oauth.createClient({ redirectUris: [REDIRECT_URI], tokenEndpointAuthMethod: 'none' });
  const authUrl = new URL(`${ISSUER}/authorize`);
  authUrl.search = new URLSearchParams({
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: REDIRECT_URI,
    scope: options.scope ?? 'read write',
    code_challenge: await challengeFor(VERIFIER),
    code_challenge_method: 'S256',
    resource: RESOURCE,
  }).toString();
  const request = await oauth.parseAuthRequest(new Request(authUrl));
  const { redirectTo } = await oauth.completeAuthorization({
    request,
    userId: 'user-1',
    scope: request.scope,
    metadata: {},
    props: options.props ?? { accountTags: ['acct-1'], secret: 'upstream-token' },
  });
  const code = new URL(redirectTo).searchParams.get('code')!;
  const response = await exchangeCode(server, client.clientId, code);
  const body = response.ok ? await response.clone().json<any>() : {};
  return { ...body, clientId: client.clientId, code, response };
}

function exchangeCode(server: OAuthAuthorizationServer<TestEnv>, clientId: string, code: string) {
  return tokenRequest(server, {
    grant_type: 'authorization_code',
    code,
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    code_verifier: VERIFIER,
    resource: RESOURCE,
  });
}

function tokenRequest(server: OAuthAuthorizationServer<TestEnv>, body: Record<string, string>) {
  return server.fetch(
    new Request(`${ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    }),
    env,
    new MockExecutionContext()
  );
}

beforeEach(async () => {
  env = createMockEnv();
  current = await generateKey('key-2026-09');
});

afterEach(() => {
  env.OAUTH_KV.clear();
  vi.restoreAllMocks();
});

describe('JWT access tokens', () => {
  it('issues an ES256 at+jwt with RFC 9068 claims and the custom claims the deployer adds', async () => {
    const server = createServer(
      defaultJwtOptions({
        claims: ({ props, grantId, audience }) => {
          expect(audience).toBe(RESOURCE);
          expect(grantId).toMatch(/.+/);
          return { cf_account_tags: (props as { accountTags: string[] }).accountTags };
        },
      })
    );
    const { access_token, refresh_token, clientId } = await authorize(server);

    expect(decodeProtectedHeader(access_token)).toEqual({ alg: 'ES256', typ: 'at+jwt', kid: 'key-2026-09' });
    const claims = decodeJwt(access_token);
    expect(claims).toMatchObject({
      iss: ISSUER,
      sub: 'user-1',
      aud: RESOURCE,
      client_id: clientId,
      scope: 'read write',
      cf_account_tags: ['acct-1'],
    });
    expect(claims.exp! - claims.iat!).toBe(300);
    expect(typeof claims.jti).toBe('string');
    expect(typeof claims.grant_id).toBe('string');
    // Props stay confidential: only what the claims hook returned is in the token.
    expect(JSON.stringify(claims)).not.toContain('upstream-token');
    // Refresh tokens remain opaque.
    expect(refresh_token.split('.')).toHaveLength(1);
  });

  it('validates through the stored record, so props decrypt and the audience is enforced', async () => {
    const server = createServer(defaultJwtOptions());
    const { access_token } = await authorize(server);

    const validated = await server.validateToken(RESOURCE, access_token, env);
    expect(validated).toMatchObject({ audience: RESOURCE, userId: 'user-1', scope: ['read', 'write'] });
    expect(validated!.props).toEqual({ accountTags: ['acct-1'], secret: 'upstream-token' });
    expect(await server.validateToken(OTHER_RESOURCE, access_token, env)).toBeNull();
  });

  it('rejects a token whose signature, algorithm or issuer does not match', async () => {
    const server = createServer(defaultJwtOptions());
    const { access_token } = await authorize(server);
    const [header, payload, signature] = access_token.split('.');

    const tampered = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    tampered.sub = 'user-2';
    const tamperedPayload = btoa(JSON.stringify(tampered)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(await server.validateToken(RESOURCE, `${header}.${tamperedPayload}.${signature}`, env)).toBeNull();

    const unsigned = new UnsecuredJWT(decodeJwt(access_token)).encode();
    expect(await server.validateToken(RESOURCE, unsigned, env)).toBeNull();

    const attacker = await generateKey('key-2026-09');
    const forged = await new SignJWT(decodeJwt(access_token))
      .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: 'key-2026-09' })
      .sign(await importJWK(attacker, 'ES256'));
    expect(await server.validateToken(RESOURCE, forged, env)).toBeNull();
  });

  it('publishes the public keys and advertises jwks_uri', async () => {
    const next = publicOf(await generateKey('key-2026-12'));
    const server = createServer({ keys: () => ({ current, additional: [next] }) });

    const jwks = await server.fetch(new Request(`${ISSUER}/.well-known/jwks.json`), env, new MockExecutionContext());
    expect(jwks.headers.get('Content-Type')).toBe('application/jwk-set+json');
    const { keys } = await jwks.json<{ keys: JwtKey[] }>();
    expect(keys.map((key) => key.kid)).toEqual(['key-2026-09', 'key-2026-12']);
    for (const key of keys) {
      expect(key).not.toHaveProperty('d');
      expect(key).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' });
    }

    const metadata = await server.fetch(
      new Request(`${ISSUER}/.well-known/oauth-authorization-server`),
      env,
      new MockExecutionContext()
    );
    expect((await metadata.json<any>()).jwks_uri).toBe(`${ISSUER}/.well-known/jwks.json`);
  });

  it('rotates keys: a token signed by the old key verifies while the old key is still published', async () => {
    const oldKey = current;
    let keySet: { current: JwtKey; additional?: JwtKey[] } = { current: oldKey };
    const server = createServer({ keys: () => keySet });
    const { access_token } = await authorize(server);
    const published = async () =>
      (
        await (
          await server.fetch(new Request(`${ISSUER}/.well-known/jwks.json`), env, new MockExecutionContext())
        ).json<{ keys: JwtKey[] }>()
      ).keys;
    let keys = await published();
    const offline = createJwtAccessTokenValidator<TestEnv>({ issuer: ISSUER, keys: () => keys })(env);

    // New key current, old key still published: offline validators keep accepting the old token.
    keySet = { current: await generateKey('key-2026-12'), additional: [publicOf(oldKey)] };
    keys = await published();
    expect(await offline(RESOURCE, access_token)).not.toBeNull();

    // Old key dropped: offline validators reject its tokens. validateToken() still finds the record,
    // which is why the old key is only dropped once its tokens have expired.
    keySet = { current: keySet.current };
    keys = await published();
    expect(await offline(RESOURCE, access_token)).toBeNull();
    expect(await server.validateToken(RESOURCE, access_token, env)).not.toBeNull();
  });

  it('revokes immediately: an access token, and every token when its refresh token is revoked', async () => {
    const server = createServer(defaultJwtOptions());
    const first = await authorize(server);
    await tokenRequest(server, { token: first.access_token, client_id: first.clientId });
    expect(await server.validateToken(RESOURCE, first.access_token, env)).toBeNull();

    const second = await authorize(server);
    await tokenRequest(server, {
      token: second.refresh_token,
      token_type_hint: 'refresh_token',
      client_id: second.clientId,
    });
    expect(await server.validateToken(RESOURCE, second.access_token, env)).toBeNull();
  });

  it('issues a new JWT on refresh', async () => {
    const server = createServer(defaultJwtOptions({ claims: () => ({ cf_epoch: 1 }) }));
    const { refresh_token, clientId, access_token } = await authorize(server);

    const response = await tokenRequest(server, {
      grant_type: 'refresh_token',
      refresh_token,
      client_id: clientId,
    });
    expect(response.status).toBe(200);
    const refreshed = await response.json<any>();
    expect(refreshed.access_token).not.toBe(access_token);
    expect(decodeJwt(refreshed.access_token)).toMatchObject({ sub: 'user-1', aud: RESOURCE, cf_epoch: 1 });
    expect(await server.validateToken(RESOURCE, refreshed.access_token, env)).not.toBeNull();
  });

  it('leaves the authorization code usable when signing fails, and rejects reserved custom claims', async () => {
    let failing = true;
    const server = createServer(
      defaultJwtOptions({
        claims: (): Record<string, JwtClaimValue> => (failing ? { sub: 'someone-else' } : { cf_account_tags: [] }),
      })
    );
    const first = await authorize(server);
    expect(first.response.status).toBe(500);

    failing = false;
    const retry = await exchangeCode(server, first.clientId, first.code);
    expect(retry.status).toBe(200);
    expect(decodeJwt((await retry.json<any>()).access_token).sub).toBe('user-1');
  });

  it('switches over safely: keys published before issuance, and a rollback keeps JWTs valid', async () => {
    const jwt = defaultJwtOptions();

    // 1. Readers first: JWT configured, still issuing opaque. The JWKS is live before any JWT exists.
    const staging = createServer(undefined, { issuing: 'opaque', jwt });
    const jwks = await staging.fetch(new Request(`${ISSUER}/.well-known/jwks.json`), env, new MockExecutionContext());
    expect(jwks.status).toBe(200);
    const beforeSwitch = await authorize(staging);
    expect(beforeSwitch.access_token.split(':')).toHaveLength(3);

    // 2. Flip issuance. Opaque tokens from before the switch keep working.
    const issuing = createServer(undefined, { issuing: 'jwt', jwt });
    const afterSwitch = await authorize(issuing);
    expect(decodeProtectedHeader(afterSwitch.access_token).typ).toBe('at+jwt');
    expect(await issuing.validateToken(RESOURCE, beforeSwitch.access_token, env)).not.toBeNull();

    // 3. Roll back issuance but keep accepting: outstanding JWTs stay valid, new tokens are opaque.
    const rolledBack = createServer(undefined, { issuing: 'opaque', jwt });
    expect(await rolledBack.validateToken(RESOURCE, afterSwitch.access_token, env)).not.toBeNull();
    expect((await authorize(rolledBack)).access_token.split(':')).toHaveLength(3);

    // Dropping jwt entirely stops accepting JWTs, which is why rollback keeps it.
    expect(await createServer().validateToken(RESOURCE, afterSwitch.access_token, env)).toBeNull();
  });

  it('rejects inconsistent access-token configuration at construction', () => {
    expect(() => createServer(undefined, { issuing: 'jwt' })).toThrow(/accessTokens\.jwt is not configured/);
    expect(() => createServer(undefined, { issuing: 'bearer' as 'jwt', jwt: defaultJwtOptions() })).toThrow(
      /issuing must be/
    );
  });

  it('keeps opaque tokens issued before JWTs were enabled valid until they expire', async () => {
    const opaque = await authorize(createServer());
    expect(opaque.access_token.split(':')).toHaveLength(3);

    const jwtServer = createServer(defaultJwtOptions());
    expect(await jwtServer.validateToken(RESOURCE, opaque.access_token, env)).not.toBeNull();
  });

  it('rejects keys that are not EC P-256', async () => {
    const rsa = (await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair;
    const rsaJwk = { ...(await crypto.subtle.exportKey('jwk', rsa.privateKey)), kid: 'rsa' } as unknown as JwtKey;
    const server = createServer({ keys: () => ({ current: rsaJwk }) });
    const response = await server.fetch(
      new Request(`${ISSUER}/.well-known/jwks.json`),
      env,
      new MockExecutionContext()
    );
    expect(response.status).toBe(500);
  });
});

describe('createJwtAccessTokenValidator', () => {
  /** The keys of the authorization server's own JWKS, as a resource server would load them. */
  async function publishedKeys(server: OAuthAuthorizationServer<TestEnv>): Promise<JwtKey[]> {
    const response = await server.fetch(
      new Request(`${ISSUER}/.well-known/jwks.json`),
      env,
      new MockExecutionContext()
    );
    return (await response.json<{ keys: JwtKey[] }>()).keys;
  }

  it('validates offline against the keys it is given and enforces the resource audience', async () => {
    const server = createServer(defaultJwtOptions({ claims: () => ({ cf_account_tags: ['acct-1'] }) }));
    const { access_token, clientId } = await authorize(server);
    const keys = await publishedKeys(server);

    const validate = createJwtAccessTokenValidator<TestEnv>({ issuer: ISSUER, keys: () => keys })(env);
    const result = await validate(RESOURCE, access_token);
    expect(result).toMatchObject({
      audience: RESOURCE,
      userId: 'user-1',
      clientId,
      scope: ['read', 'write'],
    });
    // Without mapClaims nothing is guessed into props: identity is on the validation result.
    expect(result!.props).toBeUndefined();
    expect(result).toHaveProperty('props');
    expect(await validate(OTHER_RESOURCE, access_token)).toBeNull();

    const mapped = createJwtAccessTokenValidator<TestEnv, { accounts: string[] }>({
      issuer: ISSUER,
      keys: () => keys,
      mapClaims: (claims) => ({ accounts: claims.cf_account_tags as string[] }),
    })(env);
    expect((await mapped(RESOURCE, access_token))!.props).toEqual({ accounts: ['acct-1'] });

    // Typed props without a mapper would be a promise the runtime can't keep, so it doesn't compile.
    // @ts-expect-error mapClaims is required when Props is set
    createJwtAccessTokenValidator<TestEnv, { accounts: string[] }>({ issuer: ISSUER, keys: () => keys });
    expect(await validate(RESOURCE, 'user-1:grant:secret')).toBeNull();
  });

  it('uses only EC P-256 keys, whatever else the key set holds', async () => {
    const server = createServer(defaultJwtOptions());
    const { access_token } = await authorize(server);
    // A raw exported key (with key_ops and d) is reduced to its public part; unusable keys are skipped.
    const unrelated = { kty: 'RSA', n: 'AQAB', e: 'AQAB', kid: 'rsa-key' } as unknown as JwtKey;
    const validate = createJwtAccessTokenValidator<TestEnv>({ issuer: ISSUER, keys: () => [unrelated, current] })(env);
    expect(await validate(RESOURCE, access_token)).not.toBeNull();

    const onlyUnrelated = createJwtAccessTokenValidator<TestEnv>({ issuer: ISSUER, keys: () => [unrelated] })(env);
    expect(await onlyUnrelated(RESOURCE, access_token)).toBeNull();
  });

  it("rejects another issuer's token without loading keys", async () => {
    const server = createServer(defaultJwtOptions());
    const { access_token } = await authorize(server);
    const keys = await publishedKeys(server);
    let loads = 0;
    const loadKeys = () => {
      loads++;
      return keys;
    };

    const other = createJwtAccessTokenValidator<TestEnv>({ issuer: 'https://other-auth.example.com', keys: loadKeys })(
      env
    );
    expect(await other(RESOURCE, access_token)).toBeNull();
    expect(loads).toBe(0);

    const ours = createJwtAccessTokenValidator<TestEnv>({ issuer: ISSUER, keys: loadKeys })(env);
    expect(await ours(RESOURCE, access_token)).not.toBeNull();
    expect(loads).toBe(1);
  });

  it('composes with other validators in the application for several authorization servers', async () => {
    const server = createServer(defaultJwtOptions());
    const { access_token } = await authorize(server);
    const keys = await publishedKeys(server);
    const legacyValidateToken = vi.fn(async () => null);

    // Route by the token: JWTs to the JWT validator, anything else to the opaque one.
    const ours = createJwtAccessTokenValidator<TestEnv>({ issuer: ISSUER, keys: () => keys })(env);
    const validateToken = async (resource: string, token: string) =>
      token.split('.').length === 3 ? ours(resource, token) : legacyValidateToken();

    expect(await validateToken(RESOURCE, access_token)).toMatchObject({ userId: 'user-1' });
    expect(legacyValidateToken).not.toHaveBeenCalled();
    expect(await validateToken(RESOURCE, 'opaque-token')).toBeNull();
    expect(legacyValidateToken).toHaveBeenCalledOnce();
  });

  it('lets mapClaims reject a verified token', async () => {
    const server = createServer(defaultJwtOptions());
    const { access_token } = await authorize(server);
    const keys = await publishedKeys(server);
    const rejecting = createJwtAccessTokenValidator<TestEnv, never>({
      issuer: ISSUER,
      keys: () => keys,
      mapClaims: () => null,
    })(env);
    expect(await rejecting(RESOURCE, access_token)).toBeNull();
  });

  it('fails closed when the keys cannot be loaded', async () => {
    const server = createServer(defaultJwtOptions());
    const { access_token } = await authorize(server);
    const validate = createJwtAccessTokenValidator<TestEnv>({
      issuer: ISSUER,
      keys: () => {
        throw new Error('key store unavailable');
      },
    })(env);
    // The resource server turns a thrown validator error into a 503, never an unauthenticated pass.
    await expect(validate(RESOURCE, access_token)).rejects.toThrow('key store unavailable');
  });
});
