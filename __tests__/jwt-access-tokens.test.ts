import { describe, expect, it, vi } from 'vitest';
import {
  JWT_ACCESS_TOKEN_GRANT_ID_CLAIM,
  JWT_ACCESS_TOKEN_PUBLIC_CLAIMS,
  createJwtAccessTokens,
  createJwtAccessTokenValidator,
  type JwtAccessTokenAlgorithm,
  type JwtAccessTokenPublicKey,
} from '../src/jwt-access-tokens';
import { createOAuthResourceServer } from '../src/oauth-resource-server';

const ISSUER = 'https://auth.example.com';
const RESOURCE = 'https://calendar.example.com/mcp';
const JWKS_URI = `${ISSUER}/.well-known/jwks.json`;

interface TestProps {
  userId: string;
  tenantId: string;
  upstreamAccessToken: string;
}

async function createKey(alg: JwtAccessTokenAlgorithm, kid: string) {
  const keyPair = (await crypto.subtle.generateKey(
    alg === 'RS256'
      ? {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        }
      : { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair;
  const exported = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
  const publicJwk: JwtAccessTokenPublicKey = {
    ...exported,
    kid,
    alg,
    use: 'sig',
    key_ops: ['verify'],
  };
  return { privateKey: keyPair.privateKey, publicJwk };
}

function issueInput(props: TestProps, overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    props,
    userId: 'user-123',
    grantId: 'grant-123',
    clientId: 'client-123',
    scope: ['calendar:read'],
    audience: RESOURCE,
    issuedAt: now,
    expiresAt: now + 3600,
    env: {},
    ...overrides,
  };
}

function decodePart(token: string, part: number): Record<string, unknown> {
  const encoded = token.split('.')[part].replace(/-/g, '+').replace(/_/g, '/');
  const json = atob(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, '='));
  return JSON.parse(json);
}

function encodePart(value: Record<string, unknown>): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function encodeBinary(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function signCustomJwt(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  privateKey: CryptoKey
): Promise<string> {
  const signingInput = `${encodePart(header)}.${encodePart(claims)}`;
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${encodeBinary(new Uint8Array(signature))}`;
}

describe('JWT access tokens', () => {
  it.each(['RS256', 'ES256'] as const)('issues and verifies an RFC 9068 %s access token', async (alg) => {
    const key = await createKey(alg, `${alg}-current`);
    const props: TestProps = {
      userId: 'user-123',
      tenantId: 'tenant-a',
      upstreamAccessToken: 'must-not-leak',
    };
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({ current: { kid: key.publicJwk.kid, alg, privateKey: key.privateKey, publicJwk: key.publicJwk } }),
    });

    const issued = await accessTokens.issue(issueInput(props));
    expect(issued.token.split('.')).toHaveLength(3);
    expect(decodePart(issued.token, 0)).toEqual({ typ: 'at+jwt', alg, kid: `${alg}-current` });
    expect(decodePart(issued.token, 1)).toMatchObject({
      iss: ISSUER,
      sub: 'user-123',
      aud: RESOURCE,
      client_id: 'client-123',
      scope: 'calendar:read',
      [JWT_ACCESS_TOKEN_GRANT_ID_CLAIM]: 'grant-123',
    });
    expect(JSON.stringify(decodePart(issued.token, 1))).not.toContain('must-not-leak');
    expect(await accessTokens.verify(issued.token, [RESOURCE], {})).toMatchObject({
      audience: RESOURCE,
      userId: 'user-123',
      clientId: 'client-123',
      grantId: 'grant-123',
      scope: ['calendar:read'],
    });
    expect(accessTokens.recognizes(issued.token)).toBe(true);
  });

  it('includes only the explicitly projected client-readable claim', async () => {
    const key = await createKey('RS256', 'public-claims');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: { kid: 'public-claims', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
      publicClaims: ({ props, audience }) => ({ tenantId: props.tenantId, audience }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'must-not-leak' })
    );
    const claims = decodePart(issued.token, 1);

    expect(claims[JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]).toEqual({ tenantId: 'tenant-a', audience: RESOURCE });
    expect(JSON.stringify(claims)).not.toContain('must-not-leak');
  });

  it('snapshots validated issue fields before running the public-claims projector', async () => {
    const key = await createKey('RS256', 'snapshot-input');
    const callerScope = ['calendar:read'];
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: {
          kid: 'snapshot-input',
          alg: 'RS256',
          privateKey: key.privateKey,
          publicJwk: key.publicJwk,
        },
      }),
      publicClaims: (input) => {
        try {
          (input.scope as string[]).push('admin');
        } catch {
          // The runtime snapshot is frozen as well as readonly in the type.
        }
        try {
          (input as { userId: string }).userId = 'attacker';
        } catch {
          // Canonical fields are snapshotted before application code runs.
        }
        return { scope: [...input.scope], frozen: Object.isFrozen(input.scope) };
      },
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' }, { scope: callerScope })
    );
    const claims = decodePart(issued.token, 1);

    expect(callerScope).toEqual(['calendar:read']);
    expect(claims).toMatchObject({
      sub: 'user-123',
      scope: 'calendar:read',
      [JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]: { scope: ['calendar:read'], frozen: true },
    });
  });

  it('maps verified public claims to typed resource-server props', async () => {
    const key = await createKey('RS256', 'validator');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: { kid: 'validator', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
      publicClaims: ({ props }) => ({ tenantId: props.tenantId }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    const mapper = vi.fn(({ userId, scope, publicClaims }) => ({
      userId,
      scopes: scope,
      tenantId: (publicClaims as { tenantId: string }).tenantId,
    }));
    const validate = createJwtAccessTokenValidator<{}, { userId: string; scopes: string[]; tenantId: string }>({
      issuer: ISSUER,
      audience: RESOURCE,
      keys: () => [key.publicJwk],
      mapClaimsToProps: mapper,
    });

    await expect(validate({ token: issued.token, request: new Request(RESOURCE), env: {} })).resolves.toEqual({
      audience: RESOURCE,
      expiresAt: issued.claims.exp,
      props: { userId: 'user-123', scopes: ['calendar:read'], tenantId: 'tenant-a' },
    });
    expect(mapper).toHaveBeenCalledOnce();

    const resourceServer = createOAuthResourceServer<{}, { userId: string; scopes: string[]; tenantId: string }>({
      resourceMetadata: { resource: RESOURCE, authorization_servers: [ISSUER] },
      validateToken: validate,
      handler: {
        fetch(_request, _env, ctx) {
          return Response.json(ctx.props);
        },
      },
    });
    const executionContext = {
      waitUntil() {},
      passThroughOnException() {},
    } as unknown as ExecutionContext;
    const response = await resourceServer.fetch(
      new Request(RESOURCE, { headers: { Authorization: `Bearer ${issued.token}` } }),
      {},
      executionContext
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      userId: 'user-123',
      scopes: ['calendar:read'],
      tenantId: 'tenant-a',
    });
  });

  it('rejects tampering, the wrong audience, and expired tokens before mapping props', async () => {
    const key = await createKey('RS256', 'validation');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: { kid: 'validation', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    const mapClaimsToProps = vi.fn(() => ({ userId: 'user-123' }));
    const validate = createJwtAccessTokenValidator<{}, { userId: string }>({
      issuer: ISSUER,
      audience: RESOURCE,
      keys: () => [key.publicJwk],
      mapClaimsToProps,
      clockSkewSeconds: 0,
    });

    const parts = issued.token.split('.');
    const changedClaims = { ...decodePart(issued.token, 1), sub: 'attacker' };
    const tampered = `${parts[0]}.${encodePart(changedClaims)}.${parts[2]}`;
    await expect(validate({ token: tampered, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();

    const wrongAudience = createJwtAccessTokenValidator<{}, { userId: string }>({
      issuer: ISSUER,
      audience: 'https://drive.example.com/mcp',
      keys: () => [key.publicJwk],
      mapClaimsToProps,
    });
    await expect(wrongAudience({ token: issued.token, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();

    const expired = await accessTokens.issue(
      issueInput(
        { userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' },
        { issuedAt: 100, expiresAt: 200 }
      )
    );
    await expect(validate({ token: expired.token, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();
    expect(mapClaimsToProps).not.toHaveBeenCalled();
  });

  it('handles RFC JWT syntax while rejecting premature or malformed claims before key resolution', async () => {
    const key = await createKey('RS256', 'syntax');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({ current: { kid: 'syntax', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk } }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    const header = decodePart(issued.token, 0);
    const claims = decodePart(issued.token, 1);
    const keys = vi.fn(() => [key.publicJwk]);
    const validate = createJwtAccessTokenValidator<{}, { userId: string }>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
      keys,
      mapClaimsToProps: ({ userId }) => ({ userId }),
      clockSkewSeconds: 0,
    });

    const interoperable = await signCustomJwt(
      { ...header, typ: 'at+JWT' },
      { ...claims, aud: [RESOURCE, 'https://another.example.com/mcp'] },
      key.privateKey
    );
    await expect(validate({ token: interoperable, request: new Request(RESOURCE), env: {} })).resolves.toMatchObject({
      props: { userId: 'user-123' },
    });
    await expect(accessTokens.verify(interoperable, [RESOURCE], {})).resolves.toBeNull();

    const future = await signCustomJwt(header, { ...claims, nbf: Math.floor(Date.now() / 1000) + 300 }, key.privateKey);
    await expect(validate({ token: future, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();

    const malformedScope = await signCustomJwt(header, { ...claims, scope: 'read  write' }, key.privateKey);
    await expect(validate({ token: malformedScope, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();

    const controlledEncoding = await signCustomJwt({ ...header, b64: false }, claims, key.privateKey);
    await expect(validate({ token: controlledEncoding, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();

    const tokenParts = issued.token.split('.');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const finalSignatureCharacter = alphabet.indexOf(tokenParts[2].slice(-1));
    tokenParts[2] = `${tokenParts[2].slice(0, -1)}${alphabet[finalSignatureCharacter + 1]}`;
    await expect(
      validate({ token: tokenParts.join('.'), request: new Request(RESOURCE), env: {} })
    ).resolves.toBeNull();

    keys.mockClear();
    const wrongIssuer = `${encodePart(header)}.${encodePart({ ...claims, iss: 'https://attacker.example.com' })}.signature`;
    await expect(validate({ token: wrongIssuer, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();
    const invalidUtf8 = `${encodeBinary(new Uint8Array([0xc3, 0x28]))}.${encodePart(claims)}.signature`;
    await expect(validate({ token: invalidUtf8, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();
    expect(keys).not.toHaveBeenCalled();
  });

  it('does not follow token-controlled keys or accept an untrusted algorithm', async () => {
    const key = await createKey('RS256', 'headers');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({ current: { kid: 'headers', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk } }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    const validate = createJwtAccessTokenValidator<{}, {}>({
      issuer: ISSUER,
      audience: RESOURCE,
      keys: () => [key.publicJwk],
      mapClaimsToProps: () => ({}),
    });
    const parts = issued.token.split('.');
    const controlledJku = `${encodePart({ ...decodePart(issued.token, 0), jku: 'https://attacker.example/jwks' })}.${parts[1]}.${parts[2]}`;
    const none = `${encodePart({ typ: 'at+jwt', alg: 'none', kid: 'headers' })}.${parts[1]}.forged`;

    await expect(validate({ token: controlledJku, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();
    await expect(validate({ token: none, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();
  });

  it('publishes the current and retiring public keys and verifies tokens across rotation', async () => {
    const oldKey = await createKey('RS256', 'old');
    const newKey = await createKey('RS256', 'new');
    const oldTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: { kid: 'old', alg: 'RS256', privateKey: oldKey.privateKey, publicJwk: oldKey.publicJwk },
      }),
    });
    const oldToken = await oldTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    const jwksCachedBeforePrepublication = (await oldTokens.getJwks({})).keys;
    const rotatedTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: { kid: 'new', alg: 'RS256', privateKey: newKey.privateKey, publicJwk: newKey.publicJwk },
        verificationKeys: [oldKey.publicJwk],
      }),
    });

    await expect(rotatedTokens.verify(oldToken.token, [RESOURCE], {})).resolves.toMatchObject({
      jti: oldToken.claims.jti,
    });
    await expect(rotatedTokens.getJwks({})).resolves.toMatchObject({ keys: [{ kid: 'new' }, { kid: 'old' }] });
    expect((await rotatedTokens.getJwks({})).keys.every((jwk) => !('d' in jwk))).toBe(true);

    const prepublishedTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: { kid: 'old', alg: 'RS256', privateKey: oldKey.privateKey, publicJwk: oldKey.publicJwk },
        verificationKeys: [newKey.publicJwk],
      }),
    });
    const jwksCachedAfterPrepublication = (await prepublishedTokens.getJwks({})).keys;
    const newToken = await rotatedTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    const validateWithPrepublishedCache = createJwtAccessTokenValidator<{}, {}>({
      issuer: ISSUER,
      audience: RESOURCE,
      keys: () => jwksCachedAfterPrepublication,
      mapClaimsToProps: () => ({}),
    });
    await expect(
      validateWithPrepublishedCache({ token: newToken.token, request: new Request(RESOURCE), env: {} })
    ).resolves.toMatchObject({ audience: RESOURCE });
    const validateWithStaleCache = createJwtAccessTokenValidator<{}, {}>({
      issuer: ISSUER,
      audience: RESOURCE,
      keys: () => jwksCachedBeforePrepublication,
      mapClaimsToProps: () => ({}),
    });
    await expect(
      validateWithStaleCache({ token: newToken.token, request: new Request(RESOURCE), env: {} })
    ).resolves.toBeNull();
  });

  it('rejects private material, duplicate kids, unsafe public claims, and oversized tokens', async () => {
    const key = await createKey('RS256', 'invalid');
    const privateJwk = (await crypto.subtle.exportKey('jwk', key.privateKey)) as JwtAccessTokenPublicKey;
    const privateMaterial = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: {
          kid: 'invalid',
          alg: 'RS256',
          privateKey: key.privateKey,
          publicJwk: { ...privateJwk, kid: 'invalid', alg: 'RS256' },
        },
      }),
    });
    await expect(privateMaterial.getJwks({})).rejects.toThrow('must not contain private key material');

    const duplicateKids = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: { kid: 'invalid', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
        verificationKeys: [key.publicJwk],
      }),
    });
    await expect(duplicateKids.getJwks({})).rejects.toThrow('unique kid');

    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const unsafeClaims = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({ current: { kid: 'invalid', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk } }),
      publicClaims: () => circular as never,
    });
    await expect(
      unsafeClaims.issue(issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' }))
    ).rejects.toThrow('finite JSON');

    let deeplyNested: unknown = null;
    for (let depth = 0; depth < 128; depth++) deeplyNested = [deeplyNested];
    const deepClaims = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({ current: { kid: 'invalid', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk } }),
      publicClaims: () => deeplyNested as never,
    });
    await expect(
      deepClaims.issue(issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' }))
    ).rejects.toThrow('maximum JSON depth');

    const oversized = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      maxTokenBytes: 1024,
      keys: () => ({ current: { kid: 'invalid', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk } }),
      publicClaims: () => 'x'.repeat(2000),
    });
    const sign = vi.spyOn(crypto.subtle, 'sign');
    await expect(
      oversized.issue(issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' }))
    ).rejects.toThrow('exceeds');
    expect(sign).not.toHaveBeenCalled();
    sign.mockRestore();

    await expect(
      oversized.issue(
        issueInput(
          { userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' },
          { scope: ['read write'] }
        )
      )
    ).rejects.toThrow('valid OAuth scope tokens');
  });

  it('rejects weak, incompatible, and mismatched signing keys', async () => {
    const strong = await createKey('RS256', 'strong');
    const unrelated = await createKey('RS256', 'unrelated');
    const mismatched = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: {
          kid: 'unrelated',
          alg: 'RS256',
          privateKey: strong.privateKey,
          publicJwk: unrelated.publicJwk,
        },
      }),
    });
    await expect(
      mismatched.issue(issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' }))
    ).rejects.toThrow('does not match publicJwk');
    await expect(mismatched.getJwks({})).rejects.toThrow('does not match publicJwk');

    const weakPair = (await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair;
    const weakJwk = {
      ...((await crypto.subtle.exportKey('jwk', weakPair.publicKey)) as JsonWebKey),
      kid: 'weak',
      alg: 'RS256' as const,
    } as JwtAccessTokenPublicKey;
    const weak = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({ current: { kid: 'weak', alg: 'RS256', privateKey: weakPair.privateKey, publicJwk: weakJwk } }),
    });
    await expect(weak.getJwks({})).rejects.toThrow('at least 2048 bits');

    const sha384Pair = (await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-384',
      },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair;
    const sha384Jwk = {
      ...((await crypto.subtle.exportKey('jwk', sha384Pair.publicKey)) as JsonWebKey),
      kid: 'sha384',
      alg: 'RS256' as const,
    } as JwtAccessTokenPublicKey;
    const wrongHash = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: { kid: 'sha384', alg: 'RS256', privateKey: sha384Pair.privateKey, publicJwk: sha384Jwk },
      }),
    });
    await expect(wrongHash.getJwks({})).rejects.toThrow('PKCS#1 SHA-256');
  });

  it('rejects a nullish props mapping and snapshots explicitly public JSON claims', async () => {
    const key = await createKey('RS256', 'snapshot');
    const shared = { label: 'safe' };
    const projected = { first: shared, second: shared };
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: { kid: 'snapshot', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
      publicClaims: () => projected,
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    shared.label = 'mutated-after-issuance';
    expect(decodePart(issued.token, 1)[JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]).toEqual({
      first: { label: 'safe' },
      second: { label: 'safe' },
    });

    const specialKeyClaims = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        current: { kid: 'snapshot', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
      publicClaims: () => JSON.parse('{"__proto__":{"polluted":true},"safe":"value"}') as never,
    });
    const specialKeyToken = await specialKeyClaims.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    const specialValue = decodePart(specialKeyToken.token, 1)[JWT_ACCESS_TOKEN_PUBLIC_CLAIMS] as Record<
      string,
      unknown
    >;
    expect(Object.prototype.hasOwnProperty.call(specialValue, '__proto__')).toBe(true);
    expect(specialValue.safe).toBe('value');
    expect(specialValue.__proto__).toEqual({ polluted: true });

    const validate = createJwtAccessTokenValidator<{}, {}>({
      issuer: ISSUER,
      audience: RESOURCE,
      keys: () => [key.publicJwk],
      mapClaimsToProps: () => undefined as never,
    });
    await expect(validate({ token: issued.token, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();
  });

  it('rejects deeply nested unverified public claims before resolving keys or mapping props', async () => {
    const key = await createKey('RS256', 'deep-input');
    const now = Math.floor(Date.now() / 1000);
    let deeplyNested: unknown = null;
    for (let depth = 0; depth < 128; depth++) deeplyNested = [deeplyNested];
    const header = encodePart({ typ: 'at+jwt', alg: 'RS256', kid: 'deep-input' });
    const claims = encodePart({
      iss: ISSUER,
      sub: 'user-123',
      aud: RESOURCE,
      exp: now + 3600,
      iat: now,
      jti: 'deep-input',
      client_id: 'client-123',
      scope: 'calendar:read',
      [JWT_ACCESS_TOKEN_GRANT_ID_CLAIM]: 'grant-123',
      [JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]: deeplyNested,
    });
    const keys = vi.fn(() => [key.publicJwk]);
    const mapper = vi.fn(() => ({}));
    const validate = createJwtAccessTokenValidator({
      issuer: ISSUER,
      audience: RESOURCE,
      keys,
      mapClaimsToProps: mapper,
    });

    await expect(
      validate({ token: `${header}.${claims}.c2ln`, request: new Request(RESOURCE), env: {} })
    ).resolves.toBeNull();
    expect(keys).not.toHaveBeenCalled();
    expect(mapper).not.toHaveBeenCalled();
  });
});
