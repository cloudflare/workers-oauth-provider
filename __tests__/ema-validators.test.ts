/**
 * Unit tests for the pure EMA validators in `src/ema/*`.
 *
 * These tests demonstrate the testability win from the restructure: each
 * validator is a free function operating on plain data, so we don't need to
 * spin up an `OAuthProvider`, mock a fetch, or seed a KV store. They run in
 * milliseconds and pin individual checks one-by-one — adding a new claim
 * check becomes a few lines, not a full integration setup.
 */

import { describe, expect, it } from 'vitest';

import { EMA_ID_JAG_JWT_TYPE, EMA_SUPPORTED_JWT_ALGORITHMS, type EmaSupportedAlg } from '../src/ema/constants';
import { parseIdJag } from '../src/ema/parser';
import { emaErrorToWire } from '../src/ema/result';
import { selectJwk } from '../src/ema/signature';
import type { EmaTrustedIssuer, JsonWebKeySet } from '../src/ema/types';
import {
  computeEmaAccessTokenTTL,
  parseEmaScopeParam,
  resolveTrustedIssuer,
  validateEmaMapperResult,
  validateIdJagClaims,
  validateIdJagHeader,
} from '../src/ema/validators';

function b64url(input: string): string {
  return btoa(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function buildAssertion(header: object, payload: object): string {
  // The signature segment must be valid base64url; the actual byte content is
  // irrelevant for parser tests since signature verification is a separate step.
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.${b64url('sig')}`;
}

const trustedIssuer: EmaTrustedIssuer = {
  issuer: 'https://idp.example.com',
  jwksUri: 'https://idp.example.com/jwks.json',
  algorithms: ['RS256'],
  audience: 'https://as.example.com',
};

const validClaims = {
  iss: 'https://idp.example.com',
  sub: 'user-123',
  aud: 'https://as.example.com',
  resource: 'https://mcp.example.com',
  client_id: 'client-xyz',
  jti: 'jti-abc',
  exp: 2_000_000_000,
  iat: 1_999_999_700,
  scope: 'read write',
};

const claimsArgs = {
  trustedIssuer,
  expectedAudience: 'https://as.example.com',
  clientId: 'client-xyz',
  configuredResource: 'https://mcp.example.com',
  matchOriginOnly: false,
  now: 1_999_999_800,
  clockSkewSeconds: 60,
  maxAssertionLifetimeSeconds: 300,
};

describe('parseIdJag', () => {
  it('rejects an empty assertion as missing', () => {
    expect(parseIdJag('', 1024)).toMatchObject({ ok: false, error: { reason: 'assertion_missing' } });
  });

  it('rejects an oversized assertion', () => {
    expect(parseIdJag('x'.repeat(2000), 1024)).toMatchObject({
      ok: false,
      error: { reason: 'assertion_too_large' },
    });
  });

  it('rejects a non-3-segment assertion', () => {
    expect(parseIdJag('one.two', 1024)).toMatchObject({ ok: false, error: { reason: 'assertion_malformed' } });
  });

  it('rejects assertions with malformed JSON', () => {
    expect(parseIdJag('aaa.bbb.ccc', 1024)).toMatchObject({
      ok: false,
      error: { reason: 'assertion_malformed' },
    });
  });

  it('parses a valid 3-segment assertion', () => {
    const assertion = buildAssertion({ typ: EMA_ID_JAG_JWT_TYPE, alg: 'RS256' }, validClaims);
    const result = parseIdJag(assertion, 1024);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.header).toMatchObject({ typ: EMA_ID_JAG_JWT_TYPE, alg: 'RS256' });
      expect(result.value.rawClaims.iss).toBe('https://idp.example.com');
    }
  });
});

describe('validateIdJagHeader', () => {
  it('requires the oauth-id-jag+jwt typ', () => {
    const r = validateIdJagHeader({ typ: 'JWT', alg: 'RS256' }, EMA_ID_JAG_JWT_TYPE, EMA_SUPPORTED_JWT_ALGORITHMS);
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_typ' } });
  });

  it('rejects alg=none', () => {
    const r = validateIdJagHeader(
      { typ: EMA_ID_JAG_JWT_TYPE, alg: 'none' },
      EMA_ID_JAG_JWT_TYPE,
      EMA_SUPPORTED_JWT_ALGORITHMS
    );
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_alg' } });
  });

  it('rejects unsupported alg', () => {
    const r = validateIdJagHeader(
      { typ: EMA_ID_JAG_JWT_TYPE, alg: 'HS256' },
      EMA_ID_JAG_JWT_TYPE,
      EMA_SUPPORTED_JWT_ALGORITHMS
    );
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_alg' } });
  });

  it('extracts kid when present', () => {
    const r = validateIdJagHeader(
      { typ: EMA_ID_JAG_JWT_TYPE, alg: 'RS256', kid: 'k1' },
      EMA_ID_JAG_JWT_TYPE,
      EMA_SUPPORTED_JWT_ALGORITHMS
    );
    expect(r).toMatchObject({ ok: true, value: { typ: EMA_ID_JAG_JWT_TYPE, alg: 'RS256', kid: 'k1' } });
  });

  it('treats empty kid as absent', () => {
    const r = validateIdJagHeader(
      { typ: EMA_ID_JAG_JWT_TYPE, alg: 'RS256', kid: '' },
      EMA_ID_JAG_JWT_TYPE,
      EMA_SUPPORTED_JWT_ALGORITHMS
    );
    expect(r.ok && r.value.kid).toBeUndefined();
  });
});

describe('resolveTrustedIssuer', () => {
  const issuers: EmaTrustedIssuer[] = [
    { issuer: 'https://idp1.example.com', jwksUri: 'https://idp1.example.com/jwks.json', algorithms: ['RS256'] },
    { issuer: 'https://idp2.example.com', jwksUri: 'https://idp2.example.com/jwks.json', algorithms: ['ES256'] },
  ];
  const resolver = ({ iss }: { iss: string }) => issuers.find((c) => c.issuer === iss) ?? null;
  const ctx = {
    env: {} as unknown,
    request: new Request('https://as.example.com/oauth/token'),
    clientInfo: { clientId: 'client-xyz' } as any,
  };

  it('rejects non-string iss', async () => {
    const r = await resolveTrustedIssuer({ iss: 42, alg: 'RS256', resolver, ...ctx });
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_claim', claim: 'iss' } });
  });

  it('rejects when the resolver returns null (issuer not trusted)', async () => {
    const r = await resolveTrustedIssuer({ iss: 'https://attacker.example.com', alg: 'RS256', resolver, ...ctx });
    expect(r).toMatchObject({ ok: false, error: { reason: 'issuer_not_trusted' } });
  });

  it('rejects when alg is not in the resolved issuer allowlist', async () => {
    const r = await resolveTrustedIssuer({ iss: 'https://idp1.example.com', alg: 'ES256', resolver, ...ctx });
    expect(r).toMatchObject({ ok: false, error: { reason: 'issuer_not_trusted' } });
  });

  it('returns the matching issuer when alg is allowed', async () => {
    const r = await resolveTrustedIssuer({ iss: 'https://idp2.example.com', alg: 'ES256', resolver, ...ctx });
    expect(r.ok && r.value.issuer).toBe('https://idp2.example.com');
  });

  it('supports async resolvers (e.g. KV/D1 lookups)', async () => {
    const asyncResolver = async ({ iss }: { iss: string }) =>
      iss === 'https://tenant-a.idp.example' ? issuers[0] : null;
    const r = await resolveTrustedIssuer({
      iss: 'https://tenant-a.idp.example',
      alg: 'RS256',
      // The resolver intentionally returns idp1's config for tenant-a's iss to
      // verify the confused-deputy guard fires.
      resolver: asyncResolver,
      ...ctx,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'issuer_not_trusted' } });
  });

  it('rejects when the resolver returns an issuer whose `issuer` field disagrees with iss', async () => {
    const lyingResolver = () => ({ ...issuers[0], issuer: 'https://different.example.com' });
    const r = await resolveTrustedIssuer({
      iss: 'https://idp1.example.com',
      alg: 'RS256',
      resolver: lyingResolver,
      ...ctx,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'issuer_not_trusted' } });
  });

  it('rejects when the resolver returns a malformed config (non-HTTPS jwksUri)', async () => {
    const badResolver = () => ({
      issuer: 'https://idp1.example.com',
      jwksUri: 'http://idp1.example.com/jwks.json',
    });
    const r = await resolveTrustedIssuer({
      iss: 'https://idp1.example.com',
      alg: 'RS256',
      resolver: badResolver,
      ...ctx,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'issuer_not_trusted' } });
  });

  it('rejects when the resolver throws', async () => {
    const throwingResolver = () => {
      throw new Error('database is down');
    };
    const r = await resolveTrustedIssuer({
      iss: 'https://idp1.example.com',
      alg: 'RS256',
      resolver: throwingResolver,
      ...ctx,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'issuer_not_trusted' } });
  });
});

describe('selectJwk', () => {
  const jwks: JsonWebKeySet = {
    keys: [
      { kty: 'RSA', kid: 'r1', use: 'sig', n: 'aaa', e: 'AQAB' },
      { kty: 'RSA', kid: 'r2', use: 'sig', n: 'bbb', e: 'AQAB' },
      { kty: 'EC', kid: 'e1', use: 'sig', crv: 'P-256', x: 'xxx', y: 'yyy' },
    ],
  };

  it('picks the key matching the assertion kid', () => {
    const r = selectJwk(jwks, 'RS256' as EmaSupportedAlg, 'r2');
    expect(r.ok && r.value.kid).toBe('r2');
  });

  it('rejects when kid is provided but absent from JWKS', () => {
    const r = selectJwk(jwks, 'RS256' as EmaSupportedAlg, 'nope');
    expect(r).toMatchObject({ ok: false, error: { reason: 'no_matching_key' } });
  });

  it('rejects when no kid is given and multiple keys match the alg', () => {
    const r = selectJwk(jwks, 'RS256' as EmaSupportedAlg, undefined);
    expect(r).toMatchObject({ ok: false, error: { reason: 'no_matching_key' } });
  });

  it('picks the unique alg-compatible key when kid is absent', () => {
    const r = selectJwk(jwks, 'ES256' as EmaSupportedAlg, undefined);
    expect(r.ok && r.value.kid).toBe('e1');
  });
});

describe('validateIdJagClaims', () => {
  it('accepts a fully valid claim set', () => {
    const r = validateIdJagClaims({ rawClaims: { ...validClaims }, ...claimsArgs });
    expect(r.ok).toBe(true);
  });

  it('rejects missing required claims with the claim name', () => {
    const { sub: _omit, ...rest } = validClaims;
    const r = validateIdJagClaims({ rawClaims: rest, ...claimsArgs });
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_claim', claim: 'sub' } });
  });

  it('rejects aud mismatch', () => {
    const r = validateIdJagClaims({
      rawClaims: { ...validClaims, aud: 'https://other.example.com' },
      ...claimsArgs,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'aud_mismatch' } });
  });

  it('accepts aud as an array containing the expected audience', () => {
    const r = validateIdJagClaims({
      rawClaims: { ...validClaims, aud: ['https://x.example', 'https://as.example.com'] },
      ...claimsArgs,
    });
    expect(r.ok).toBe(true);
  });

  it('rejects client_id mismatch', () => {
    const r = validateIdJagClaims({ rawClaims: { ...validClaims, client_id: 'other' }, ...claimsArgs });
    expect(r).toMatchObject({ ok: false, error: { reason: 'client_id_mismatch' } });
  });

  it('rejects invalid resource URI', () => {
    const r = validateIdJagClaims({ rawClaims: { ...validClaims, resource: 'not a url' }, ...claimsArgs });
    expect(r).toMatchObject({ ok: false, error: { reason: 'resource_invalid' } });
  });

  it('rejects resource that does not match the configured one', () => {
    const r = validateIdJagClaims({
      rawClaims: { ...validClaims, resource: 'https://attacker.example.com' },
      ...claimsArgs,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'resource_mismatch' } });
  });

  it('rejects expired assertions beyond clock-skew tolerance', () => {
    // claimsArgs.clockSkewSeconds = 60, so the assertion must be > 60s past exp.
    const r = validateIdJagClaims({
      rawClaims: { ...validClaims, exp: claimsArgs.now - 120 },
      ...claimsArgs,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'expired' } });
  });

  it('accepts assertions within clock-skew tolerance of exp (RFC 7523 §3 rule 4)', () => {
    const r = validateIdJagClaims({
      rawClaims: { ...validClaims, exp: claimsArgs.now - 10 },
      ...claimsArgs,
    });
    expect(r.ok).toBe(true);
  });

  it('rejects iat too far in the future', () => {
    const r = validateIdJagClaims({
      rawClaims: { ...validClaims, iat: claimsArgs.now + 1000 },
      ...claimsArgs,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'iat_in_future' } });
  });

  it('rejects nbf too far in the future', () => {
    const r = validateIdJagClaims({
      rawClaims: { ...validClaims, nbf: claimsArgs.now + 1000 },
      ...claimsArgs,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'nbf_in_future' } });
  });

  it('rejects assertions whose lifetime exceeds the maximum', () => {
    const r = validateIdJagClaims({
      rawClaims: { ...validClaims, iat: 1_000_000_000, exp: 1_999_999_999 },
      ...claimsArgs,
      now: 1_500_000_000,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'lifetime_too_long' } });
  });

  it('rejects malformed scope grammar', () => {
    const r = validateIdJagClaims({
      rawClaims: { ...validClaims, scope: 'valid bad\x01token' },
      ...claimsArgs,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_claim', claim: 'scope' } });
  });
});

describe('parseEmaScopeParam', () => {
  it('returns the assertion scopes when scope param is omitted', () => {
    const r = parseEmaScopeParam(undefined, ['read', 'write']);
    expect(r).toMatchObject({ ok: true, value: ['read', 'write'] });
  });

  it('parses a space-separated string', () => {
    const r = parseEmaScopeParam('read write', ['read', 'write']);
    expect(r).toMatchObject({ ok: true, value: ['read', 'write'] });
  });

  it('downscopes to the intersection with assertion scopes', () => {
    const r = parseEmaScopeParam('read admin', ['read', 'write']);
    expect(r).toMatchObject({ ok: true, value: ['read'] });
  });

  it('rejects malformed scope', () => {
    const r = parseEmaScopeParam('bad\x01scope', []);
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_scope_param' } });
  });

  it('rejects non-string non-array values', () => {
    const r = parseEmaScopeParam(42, []);
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_scope_param' } });
  });
});

describe('validateEmaMapperResult', () => {
  it('null is mapper_denied', () => {
    expect(validateEmaMapperResult(null)).toMatchObject({ ok: false, error: { reason: 'mapper_denied' } });
  });

  it('rejects userId with ":" separator', () => {
    const r = validateEmaMapperResult({ userId: 'a:b', scope: [], props: {} });
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_mapped_user' } });
  });

  it('rejects empty userId', () => {
    const r = validateEmaMapperResult({ userId: '', scope: [], props: {} });
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_mapped_user' } });
  });

  it('rejects non-array scope', () => {
    const r = validateEmaMapperResult({ userId: 'u', scope: 'read', props: {} });
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_mapped_scope' } });
  });

  it('rejects malformed scope tokens', () => {
    const r = validateEmaMapperResult({ userId: 'u', scope: ['bad\x01'], props: {} });
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_mapped_scope' } });
  });

  it('rejects when props is missing', () => {
    const r = validateEmaMapperResult({ userId: 'u', scope: [] });
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_mapped_props' } });
  });

  it('rejects when accessTokenTTL is non-positive', () => {
    const r = validateEmaMapperResult({ userId: 'u', scope: [], props: {}, accessTokenTTL: -1 });
    expect(r).toMatchObject({ ok: false, error: { reason: 'invalid_mapped_ttl' } });
  });

  it('returns the validated mapper output on success', () => {
    const r = validateEmaMapperResult({ userId: 'u', scope: ['read'], props: { x: 1 }, accessTokenTTL: 600 });
    expect(r.ok && r.value.userId).toBe('u');
    expect(r.ok && r.value.scope).toEqual(['read']);
    expect(r.ok && r.value.accessTokenTTL).toBe(600);
  });
});

describe('computeEmaAccessTokenTTL', () => {
  it('uses the configured default TTL regardless of the assertion remaining lifetime', () => {
    const r = computeEmaAccessTokenTTL({
      configuredDefaultSeconds: 3600,
      assertionExp: 2_000_000_000,
      mapperTtl: undefined,
      now: 1_999_999_700,
    });
    // Assertion has 300s left but the issued access token follows the AS's
    // configured TTL (3600s) — the assertion is a one-shot grant, not a
    // lifetime cap on the token.
    expect(r).toMatchObject({ ok: true, value: 3600 });
  });

  it('uses the mapper-supplied TTL when provided', () => {
    const r = computeEmaAccessTokenTTL({
      configuredDefaultSeconds: 3600,
      assertionExp: 2_000_000_000,
      mapperTtl: 86_400,
      now: 1_999_999_700,
    });
    expect(r).toMatchObject({ ok: true, value: 86_400 });
  });

  it('rejects with assertion_expired_after_processing when no positive lifetime remains', () => {
    const r = computeEmaAccessTokenTTL({
      configuredDefaultSeconds: 3600,
      assertionExp: 1_999_999_700,
      mapperTtl: undefined,
      now: 1_999_999_800,
    });
    expect(r).toMatchObject({ ok: false, error: { reason: 'assertion_expired_after_processing' } });
  });
});

describe('emaErrorToWire', () => {
  it('maps resource errors to invalid_target', () => {
    expect(emaErrorToWire({ reason: 'resource_invalid', resource: 'x' })).toMatchObject({ code: 'invalid_target' });
    expect(emaErrorToWire({ reason: 'resource_mismatch', expected: 'a', got: 'b' })).toMatchObject({
      code: 'invalid_target',
    });
  });

  it('maps assertion-missing to invalid_request', () => {
    expect(emaErrorToWire({ reason: 'assertion_missing' })).toMatchObject({ code: 'invalid_request' });
  });

  it('maps scope-param errors to invalid_request', () => {
    expect(emaErrorToWire({ reason: 'invalid_scope_param' })).toMatchObject({ code: 'invalid_request' });
  });

  it('keeps "Invalid assertion" as the default invalid_grant message', () => {
    expect(emaErrorToWire({ reason: 'signature_failed' })).toMatchObject({
      code: 'invalid_grant',
      message: 'Invalid assertion',
    });
  });
});
