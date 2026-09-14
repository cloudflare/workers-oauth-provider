import { describe, expect, it, vi } from 'vitest';
import {
  JWT_ACCESS_TOKEN_GRANT_ID_CLAIM,
  JWT_ACCESS_TOKEN_PUBLIC_CLAIMS,
  createJwtAccessTokens,
  createJwksKeyResolver,
  createJwtAccessTokenValidator,
  jwtInternals,
  type JwtAlgorithm,
  type JwtPublicKey,
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

async function createKey(alg: JwtAlgorithm, kid: string) {
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
  const publicJwk: JwtPublicKey = {
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
  it('passes the token kid and alg to the keys resolver so a rotated key can be fetched', async () => {
    const key = await createKey('RS256', 'rotated-key');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'rotated-key', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-1', upstreamAccessToken: 'secret' })
    );
    // A resolver that only holds the key the token names, as a cache refreshed on a miss would.
    const keys = vi.fn((_env: {}, hint: { kid?: string; alg: string }) =>
      hint.kid === 'rotated-key' ? [key.publicJwk] : []
    );
    const validate = createJwtAccessTokenValidator<{}, { userId: string }>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
      keys,
      mapClaimsToProps: ({ userId }) => ({ userId }),
    });
    await expect(validate({ token: issued.token, request: new Request(RESOURCE), env: {} })).resolves.toMatchObject({
      props: { userId: 'user-123' },
    });
    expect(keys).toHaveBeenCalledWith({}, { kid: 'rotated-key', alg: 'RS256' });
  });

  it('rejects an RSA public key whose exponent makes signatures forgeable', async () => {
    const key = await createKey('RS256', 'weak-exponent');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'weak-exponent', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-1', upstreamAccessToken: 'secret' })
    );
    // e = 1 and e = 2: WebCrypto imports both, and PKCS#1 v1.5 verification under them is trivial.
    for (const e of ['AQ', 'Ag']) {
      const validate = createJwtAccessTokenValidator<{}, { userId: string }>({
        issuer: ISSUER,
        audience: RESOURCE,
        algorithms: ['RS256'],
        keys: () => [{ ...key.publicJwk, e }],
        mapClaimsToProps: ({ userId }) => ({ userId }),
      });
      // A resource server is handed someone else's JWKS: an unusable key is skipped, and a
      // token left with no key to verify against is invalid_token rather than an outage.
      await expect(validate({ token: issued.token, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();
      const publisher = createJwtAccessTokens<{}, TestProps>({
        issuer: ISSUER,
        jwksUri: JWKS_URI,
        keys: () => ({
          signingKey: {
            kid: 'weak-exponent',
            alg: 'RS256',
            privateKey: key.privateKey,
            publicJwk: { ...key.publicJwk, e },
          },
        }),
      });
      await expect(publisher.getJwks({})).rejects.toThrow('odd public exponent of at least 3');
    }
  });

  it('skips a foreign or unusable key rather than failing every request', async () => {
    const key = await createKey('RS256', 'signing');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'signing', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-1', upstreamAccessToken: 'secret' })
    );

    // RFC 7517 §4.4 makes `alg` optional, and an authorization server may publish keys for
    // other purposes alongside its access-token key. Neither may take the resource down.
    const { alg: _alg, ...algLess } = key.publicJwk;
    const foreignKeys = [
      algLess as JwtPublicKey,
      { ...key.publicJwk, kid: 'encryption', use: 'enc' } as JwtPublicKey,
      key.publicJwk,
    ];
    const validate = createJwtAccessTokenValidator<{}, { userId: string }>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
      keys: () => foreignKeys,
      mapClaimsToProps: ({ userId }) => ({ userId }),
    });
    await expect(validate({ token: issued.token, request: new Request(RESOURCE), env: {} })).resolves.toMatchObject({
      props: { userId: 'user-123' },
    });

    // A resolver that has no key for this token answers invalid_token, not a 503.
    const empty = createJwtAccessTokenValidator<{}, { userId: string }>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
      keys: () => [],
      mapClaimsToProps: ({ userId }) => ({ userId }),
    });
    await expect(empty({ token: issued.token, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();
  });

  it('publishes only JWK members and keeps a __proto__ public claim inert', async () => {
    const key = await createKey('RS256', 'published');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: {
          kid: 'published',
          alg: 'RS256',
          privateKey: key.privateKey,
          // An application key record carries its own bookkeeping beside the JWK.
          publicJwk: { ...key.publicJwk, kmsKeyId: 'arn:secret', retireAfter: 1 } as JwtPublicKey,
        },
      }),
    });
    const jwks = await accessTokens.getJwks({});
    expect(Object.keys(jwks.keys[0]).sort()).toEqual(['alg', 'e', 'kid', 'kty', 'n', 'use']);

    // The application owns publicClaims, so a __proto__ member is a loud error rather than
    // a silent drop: no resource server can copy such a claim onto an object safely.
    const withProto = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'published', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
      publicClaims: () => JSON.parse('{"attrs":{"__proto__":{"isAdmin":true}}}'),
    });
    await expect(
      withProto.issue(issueInput({ userId: 'user-123', tenantId: 'tenant-1', upstreamAccessToken: 'secret' }))
    ).rejects.toThrow('__proto__');
  });

  it('drops a __proto__ member from a public claim minted elsewhere', async () => {
    const key = await createKey('RS256', 'foreign');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'foreign', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-1', upstreamAccessToken: 'secret' })
    );
    const header = decodePart(issued.token, 0);
    const claims = decodePart(issued.token, 1);
    const polluted = await signCustomJwt(
      header,
      { ...claims, [JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]: JSON.parse('{"__proto__":{"isAdmin":true}}') },
      key.privateKey
    );
    const validate = createJwtAccessTokenValidator<{}, { admin: boolean }>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
      keys: () => [key.publicJwk],
      mapClaimsToProps: ({ publicClaims }) => {
        // The obvious thing a resource server writes, and it must stay safe.
        const copied = Object.assign({}, publicClaims as object) as { isAdmin?: boolean };
        return { admin: copied.isAdmin === true };
      },
    });
    await expect(validate({ token: polluted, request: new Request(RESOURCE), env: {} })).resolves.toMatchObject({
      props: { admin: false },
    });
  });

  it('rejects a foreign issuer, a disallowed algorithm, and each missing required claim', async () => {
    // Every one of these is a rejection the offline validator is solely responsible for:
    // unlike verify()/isOwnJwt(), it has no separate issuer or typ pre-check.
    const key = await createKey('RS256', 'required-claims');
    const es256 = await createKey('ES256', 'es-key');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'required-claims', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-1', upstreamAccessToken: 'secret' })
    );
    const header = decodePart(issued.token, 0);
    const claims = decodePart(issued.token, 1);
    const mapClaimsToProps = vi.fn(({ userId }: { userId: string }) => ({ userId }));
    const keys = vi.fn(() => [key.publicJwk, es256.publicJwk]);
    const validate = createJwtAccessTokenValidator<{}, { userId: string }>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
      keys,
      mapClaimsToProps,
    });
    const run = (token: string) => validate({ token, request: new Request(RESOURCE), env: {} });

    // Control: the untampered token is accepted, so each rejection below is the claim.
    await expect(run(issued.token)).resolves.toMatchObject({ props: { userId: 'user-123' } });

    const omit = (name: string) => {
      const { [name]: _removed, ...rest } = claims;
      return rest;
    };
    const variants: Array<[string, Record<string, unknown>, Record<string, unknown>]> = [
      ['foreign issuer', header, { ...claims, iss: 'https://attacker.example.com' }],
      ['foreign audience', header, { ...claims, aud: 'https://other.example.com/mcp' }],
      ['generic typ', { ...header, typ: 'JWT' }, claims],
      ['no kid', { alg: 'RS256', typ: 'at+jwt' }, claims],
      ['no sub', header, omit('sub')],
      ['no client_id', header, omit('client_id')],
      ['no jti', header, omit('jti')],
      ['no grant id', header, omit(JWT_ACCESS_TOKEN_GRANT_ID_CLAIM)],
    ];
    for (const [label, variantHeader, variantClaims] of variants) {
      mapClaimsToProps.mockClear();
      const token = await signCustomJwt(variantHeader, variantClaims, key.privateKey);
      await expect(run(token), label).resolves.toBeNull();
      expect(mapClaimsToProps, label).not.toHaveBeenCalled();
    }

    // An algorithm outside the allowlist is refused even though its key is in the set,
    // and it is refused before the resolver is consulted.
    keys.mockClear();
    const esToken = await signEs256Jwt({ alg: 'ES256', typ: 'at+jwt', kid: 'es-key' }, claims, es256.privateKey);
    await expect(run(esToken)).resolves.toBeNull();
    expect(keys).not.toHaveBeenCalled();

    // `alg: none` with a structurally valid third segment, so parsing is not what rejects it.
    const unsigned = `${encodePart({ alg: 'none', typ: 'at+jwt', kid: 'required-claims' })}.${encodePart(claims)}.AAAA`;
    await expect(run(unsigned)).resolves.toBeNull();
    expect(keys).not.toHaveBeenCalled();
  });

  it('accepts an http issuer, JWKS URI, and audience on loopback hosts for local development', async () => {
    const localIssuer = 'http://localhost:8787';
    const localResource = 'http://localhost:8788/mcp';
    const key = await createKey('RS256', 'local-current');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: localIssuer,
      jwksUri: `${localIssuer}/.well-known/jwks.json`,
      keys: () => ({
        signingKey: { kid: 'local-current', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
    });
    const props: TestProps = { userId: 'user-123', tenantId: 'tenant-1', upstreamAccessToken: 'secret' };
    const issued = await accessTokens.issue(issueInput(props, { audience: localResource }));
    expect(decodePart(issued.token, 1)).toMatchObject({ iss: localIssuer, aud: localResource });

    const validate = createJwtAccessTokenValidator({
      issuer: localIssuer,
      audience: localResource,
      algorithms: ['RS256'],
      keys: () => [key.publicJwk],
      mapClaimsToProps: ({ userId }) => ({ userId }),
    });
    await expect(
      validate({ token: issued.token, request: new Request(localResource), env: {} })
    ).resolves.toMatchObject({ audience: localResource, props: { userId: 'user-123' } });

    expect(() =>
      createJwtAccessTokens<{}, TestProps>({
        issuer: 'http://auth.example.com',
        jwksUri: 'http://auth.example.com/.well-known/jwks.json',
        keys: () => ({ signingKey: { kid: 'x', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk } }),
      })
    ).toThrow('issuer must be an absolute HTTPS URL');
  });

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
      keys: () => ({
        signingKey: { kid: key.publicJwk.kid, alg, privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
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
    expect(jwtInternals(accessTokens).isOwnJwt(issued.token)).toBe(true);
  });

  it('includes only the explicitly projected client-readable claim', async () => {
    const key = await createKey('RS256', 'public-claims');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'public-claims', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
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
        signingKey: {
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
        signingKey: { kid: 'validator', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
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
      algorithms: ['RS256'],
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
        signingKey: { kid: 'validation', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    const mapClaimsToProps = vi.fn(() => ({ userId: 'user-123' }));
    const validate = createJwtAccessTokenValidator<{}, { userId: string }>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
      keys: () => [key.publicJwk],
      mapClaimsToProps,
    });

    const parts = issued.token.split('.');
    const changedClaims = { ...decodePart(issued.token, 1), sub: 'attacker' };
    const tampered = `${parts[0]}.${encodePart(changedClaims)}.${parts[2]}`;
    await expect(validate({ token: tampered, request: new Request(RESOURCE), env: {} })).resolves.toBeNull();

    const wrongAudience = createJwtAccessTokenValidator<{}, { userId: string }>({
      issuer: ISSUER,
      audience: 'https://drive.example.com/mcp',
      algorithms: ['RS256'],
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
      keys: () => ({
        signingKey: { kid: 'syntax', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
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
      keys: () => ({
        signingKey: { kid: 'headers', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    const validate = createJwtAccessTokenValidator<{}, {}>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
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
        signingKey: { kid: 'old', alg: 'RS256', privateKey: oldKey.privateKey, publicJwk: oldKey.publicJwk },
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
        signingKey: { kid: 'new', alg: 'RS256', privateKey: newKey.privateKey, publicJwk: newKey.publicJwk },
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
        signingKey: { kid: 'old', alg: 'RS256', privateKey: oldKey.privateKey, publicJwk: oldKey.publicJwk },
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
      algorithms: ['RS256'],
      keys: () => jwksCachedAfterPrepublication,
      mapClaimsToProps: () => ({}),
    });
    await expect(
      validateWithPrepublishedCache({ token: newToken.token, request: new Request(RESOURCE), env: {} })
    ).resolves.toMatchObject({ audience: RESOURCE });
    const validateWithStaleCache = createJwtAccessTokenValidator<{}, {}>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
      keys: () => jwksCachedBeforePrepublication,
      mapClaimsToProps: () => ({}),
    });
    await expect(
      validateWithStaleCache({ token: newToken.token, request: new Request(RESOURCE), env: {} })
    ).resolves.toBeNull();
  });

  it('rejects private material, duplicate kids, unsafe public claims, and oversized tokens', async () => {
    const key = await createKey('RS256', 'invalid');
    const privateJwk = (await crypto.subtle.exportKey('jwk', key.privateKey)) as JwtPublicKey;
    const privateMaterial = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: {
          kid: 'invalid',
          alg: 'RS256',
          privateKey: key.privateKey,
          publicJwk: { ...privateJwk, kid: 'invalid', alg: 'RS256' },
        },
      }),
    });
    await expect(privateMaterial.getJwks({})).rejects.toThrow('must not contain private key material');

    // Checked on the caller's own record: the published-member allowlist drops `key_ops`,
    // so a check running after the copy could never see it.
    const signOnlyKeyOps = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: {
          kid: 'invalid',
          alg: 'RS256',
          privateKey: key.privateKey,
          publicJwk: { ...key.publicJwk, key_ops: ['sign'] },
        },
      }),
    });
    await expect(signOnlyKeyOps.getJwks({})).rejects.toThrow("key_ops must include 'verify'");

    const duplicateKids = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'invalid', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
        verificationKeys: [key.publicJwk],
      }),
    });
    await expect(duplicateKids.getJwks({})).rejects.toThrow('unique kid');

    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const unsafeClaims = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'invalid', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
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
      keys: () => ({
        signingKey: { kid: 'invalid', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
      publicClaims: () => deeplyNested as never,
    });
    await expect(
      deepClaims.issue(issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' }))
    ).rejects.toThrow('maximum JSON depth');

    const oversized = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'invalid', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
      publicClaims: () => 'x'.repeat(20_000),
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
        signingKey: {
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
    } as JwtPublicKey;
    const weak = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({ signingKey: { kid: 'weak', alg: 'RS256', privateKey: weakPair.privateKey, publicJwk: weakJwk } }),
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
    } as JwtPublicKey;
    const wrongHash = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'sha384', alg: 'RS256', privateKey: sha384Pair.privateKey, publicJwk: sha384Jwk },
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
        signingKey: { kid: 'snapshot', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
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
        signingKey: { kid: 'snapshot', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
      publicClaims: () => JSON.parse('{"__proto__":{"polluted":true},"safe":"value"}') as never,
    });
    // A null-prototype clone keeps such a key inert here, but the claim is consumed by
    // resource servers this issuer does not control, and the ordinary way to read it
    // (Object.assign or a spread onto a plain object) reassigns that object's prototype.
    // The hazard cannot be exported, so issuance refuses it.
    await expect(
      specialKeyClaims.issue(issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' }))
    ).rejects.toThrow('__proto__');

    const validate = createJwtAccessTokenValidator<{}, {}>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
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
      algorithms: ['RS256'],
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

async function signEs256Jwt(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  privateKey: CryptoKey
): Promise<string> {
  const signingInput = `${encodePart(header)}.${encodePart(claims)}`;
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${encodeBinary(new Uint8Array(signature))}`;
}

describe('createJwksKeyResolver', () => {
  function jwksResponse(keys: unknown[], headers: Record<string, string> = {}): Response {
    return new Response(JSON.stringify({ keys }), {
      headers: { 'Content-Type': 'application/json', ...headers },
    });
  }

  it('caches a key set, and refreshes for an unknown kid at most once per cooldown', async () => {
    const first = await createKey('RS256', 'key-1');
    const second = await createKey('RS256', 'key-2');
    let served = [first.publicJwk];
    const fetch = vi.fn(async () => jwksResponse(served));
    const resolve = createJwksKeyResolver<{}>({ jwksUri: JWKS_URI, fetcher: () => ({ fetch }) });
    const now = Math.floor(Date.now() / 1000);
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now * 1000);

    try {
      await expect(resolve({}, { kid: 'key-1', alg: 'RS256' })).resolves.toMatchObject([{ kid: 'key-1' }]);
      expect(fetch).toHaveBeenCalledTimes(1);
      expect((fetch.mock.calls[0] as unknown as [Request])[0].url).toBe(JWKS_URI);

      // A known kid is served from cache.
      await resolve({}, { kid: 'key-1', alg: 'RS256' });
      expect(fetch).toHaveBeenCalledTimes(1);

      // Invented kids inside the cooldown window never reach the authorization server:
      // `kid` is unauthenticated attacker-chosen input, and a refresh per miss would make
      // every resource server an amplifier. Serving a stale set is safe — verification
      // still has to succeed against it.
      served = [first.publicJwk, second.publicJwk];
      for (let i = 0; i < 25; i++) {
        await expect(resolve({}, { kid: `invented-${i}`, alg: 'RS256' })).resolves.toHaveLength(1);
      }
      expect(fetch).toHaveBeenCalledTimes(1);

      // Past the cooldown, one unknown kid picks up the rotation.
      clock.mockReturnValue((now + 31) * 1000);
      await expect(resolve({}, { kid: 'key-2', alg: 'RS256' })).resolves.toHaveLength(2);
      expect(fetch).toHaveBeenCalledTimes(2);
    } finally {
      clock.mockRestore();
    }
  });

  it('honours a shorter max-age than the configured TTL', async () => {
    const key = await createKey('RS256', 'short-lived');
    const fetch = vi.fn(async () => jwksResponse([key.publicJwk], { 'Cache-Control': 'public, max-age=1' }));
    const resolve = createJwksKeyResolver<{}>({
      jwksUri: JWKS_URI,
      fetcher: () => ({ fetch }),
      cacheTtlSeconds: 3600,
    });
    const now = Math.floor(Date.now() / 1000);
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now * 1000);
    try {
      await resolve({}, { kid: 'short-lived', alg: 'RS256' });
      await resolve({}, { kid: 'short-lived', alg: 'RS256' });
      expect(fetch).toHaveBeenCalledTimes(1);

      clock.mockReturnValue((now + 2) * 1000);
      await resolve({}, { kid: 'short-lived', alg: 'RS256' });
      expect(fetch).toHaveBeenCalledTimes(2);
    } finally {
      clock.mockRestore();
    }
  });

  it('rejects a failed, malformed, or oversized response and validates its own configuration', async () => {
    expect(() => createJwksKeyResolver<{}>({ jwksUri: 'http://auth.example.com/jwks.json' })).toThrow(
      'jwksUri must be an absolute HTTPS URL'
    );
    expect(() => createJwksKeyResolver<{}>({ jwksUri: JWKS_URI, cacheTtlSeconds: 0 })).toThrow(
      'cacheTtlSeconds must be an integer between 1 and 86400'
    );

    const failing = createJwksKeyResolver<{}>({
      jwksUri: JWKS_URI,
      fetcher: () => ({ fetch: async () => new Response('nope', { status: 503 }) }),
    });
    await expect(failing({}, { kid: 'any', alg: 'RS256' })).rejects.toThrow('status 503');

    const malformed = createJwksKeyResolver<{}>({
      jwksUri: JWKS_URI,
      fetcher: () => ({ fetch: async () => new Response('{}', { headers: { 'Content-Type': 'application/json' } }) }),
    });
    await expect(malformed({}, { kid: 'any', alg: 'RS256' })).rejects.toThrow('no keys array');

    const oversized = createJwksKeyResolver<{}>({
      jwksUri: JWKS_URI,
      fetcher: () => ({ fetch: async () => jwksResponse([{ kid: 'x'.repeat(70_000) }]) }),
    });
    await expect(oversized({}, { kid: 'any', alg: 'RS256' })).rejects.toThrow('exceeds the size limit');
  });

  it('validates a token end to end through the resolver', async () => {
    const key = await createKey('RS256', 'resolver-key');
    const accessTokens = createJwtAccessTokens<{}, TestProps>({
      issuer: ISSUER,
      jwksUri: JWKS_URI,
      keys: () => ({
        signingKey: { kid: 'resolver-key', alg: 'RS256', privateKey: key.privateKey, publicJwk: key.publicJwk },
      }),
    });
    const issued = await accessTokens.issue(
      issueInput({ userId: 'user-123', tenantId: 'tenant-a', upstreamAccessToken: 'secret' })
    );
    const validate = createJwtAccessTokenValidator<{}, { userId: string }>({
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ['RS256'],
      keys: createJwksKeyResolver<{}>({
        jwksUri: JWKS_URI,
        fetcher: () => ({ fetch: async () => jwksResponse((await accessTokens.getJwks({})).keys) }),
      }),
      mapClaimsToProps: ({ userId }) => ({ userId }),
    });
    await expect(validate({ token: issued.token, request: new Request(RESOURCE), env: {} })).resolves.toMatchObject({
      props: { userId: 'user-123' },
      audience: RESOURCE,
    });
  });
});
