import type { OAuthClientJsonWebKey, OAuthClientJsonWebKeySet } from './oauth-client-metadata';

/** RFC 7523 client assertion type used by `private_key_jwt`. */
export const JWT_BEARER_CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

const PRIVATE_KEY_JWT_MAX_BYTES = 16 * 1024;
const PRIVATE_KEY_JWT_JWKS_MAX_BYTES = 64 * 1024;
const PRIVATE_KEY_JWT_JWKS_TIMEOUT_MS = 10_000;
const PRIVATE_KEY_JWT_CLOCK_SKEW_SECONDS = 60;
const PRIVATE_KEY_JWT_REPLAY_PREFIX = 'private-key-jwt:';
const PRIVATE_KEY_JWT_SUPPORTED_ALGORITHMS = new Set(['RS256', 'ES256']);

/** Client metadata needed to authenticate a `private_key_jwt` assertion. */
export interface PrivateKeyJwtClient {
  clientId: string;
  jwksUri?: string;
  jwks?: OAuthClientJsonWebKeySet;
  tokenEndpointAuthSigningAlg?: string;
  tokenEndpointAuthSigningAlgValuesSupported?: string[];
}

/** Stable internal reason for a rejected `private_key_jwt` assertion. */
export type PrivateKeyJwtErrorReason =
  | 'assertion_malformed'
  | 'algorithm_not_allowed'
  | 'claims_invalid'
  | 'jwks_fetch_failed'
  | 'key_not_found'
  | 'signature_invalid'
  | 'assertion_replayed';

export type PrivateKeyJwtResult = { ok: true } | { ok: false; reason: PrivateKeyJwtErrorReason };

interface ParsedClientAssertion {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
}

/**
 * Reads an unverified client identifier solely to locate the client's
 * registered metadata. Authentication still requires full claim and signature
 * validation against that metadata.
 */
export function readPrivateKeyJwtClientId(assertion: unknown): string | undefined {
  const parsed = parseClientAssertion(assertion);
  const issuer = parsed?.claims.iss;
  return typeof issuer === 'string' && issuer.length > 0 ? issuer : undefined;
}

/** Validates and consumes a `private_key_jwt` client assertion. */
export async function authenticatePrivateKeyJwt(input: {
  assertion: unknown;
  client: PrivateKeyJwtClient;
  tokenEndpoint: string;
  now: number;
  env: { OAUTH_KV: KVNamespace };
}): Promise<PrivateKeyJwtResult> {
  const parsed = parseClientAssertion(input.assertion);
  if (!parsed) return { ok: false, reason: 'assertion_malformed' };

  const algorithm = readAlgorithm(parsed.header, input.client);
  if (!algorithm) return { ok: false, reason: 'algorithm_not_allowed' };

  const jwks = input.client.jwks ?? (await fetchPublicJwks(input.client.jwksUri));
  if (!jwks) return { ok: false, reason: 'jwks_fetch_failed' };

  const jwk = selectVerificationKey(jwks, algorithm, parsed.header.kid);
  if (!jwk) return { ok: false, reason: 'key_not_found' };

  if (!(await verifySignature(algorithm, jwk, parsed.signingInput, parsed.signature))) {
    return { ok: false, reason: 'signature_invalid' };
  }

  const claims = validateClaims(parsed.claims, input.client.clientId, input.tokenEndpoint, input.now);
  if (!claims) return { ok: false, reason: 'claims_invalid' };

  const replayKey = `${PRIVATE_KEY_JWT_REPLAY_PREFIX}${await sha256Hex(`${input.client.clientId}\n${claims.jti}`)}`;
  if (await input.env.OAUTH_KV.get(replayKey)) return { ok: false, reason: 'assertion_replayed' };

  // KV is eventually consistent, so this is best-effort across simultaneous
  // requests in different colos. The short-lived signed assertion still
  // bounds the race, and the marker remains until the assertion expires.
  await input.env.OAUTH_KV.put(replayKey, '1', {
    expirationTtl: Math.max(60, claims.exp - input.now),
  });

  return { ok: true };
}

function parseClientAssertion(assertion: unknown): ParsedClientAssertion | undefined {
  if (typeof assertion !== 'string' || assertion.length === 0 || assertion.length > PRIVATE_KEY_JWT_MAX_BYTES) {
    return undefined;
  }

  const parts = assertion.split('.');
  if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) return undefined;

  try {
    const [encodedHeader, encodedClaims, encodedSignature] = parts;
    return {
      header: parseJsonObject(encodedHeader),
      claims: parseJsonObject(encodedClaims),
      signingInput: new TextEncoder().encode(`${encodedHeader}.${encodedClaims}`),
      signature: base64UrlToBytes(encodedSignature),
    };
  } catch {
    return undefined;
  }
}

function readAlgorithm(header: Record<string, unknown>, client: PrivateKeyJwtClient): string | undefined {
  // This verifier does not implement any critical JOSE extensions or the
  // unencoded-payload option from RFC 7797.
  if (header.crit !== undefined || header.b64 !== undefined) return undefined;

  const algorithm = header.alg;
  if (typeof algorithm !== 'string' || !PRIVATE_KEY_JWT_SUPPORTED_ALGORITHMS.has(algorithm)) return undefined;
  if (client.tokenEndpointAuthSigningAlg && algorithm !== client.tokenEndpointAuthSigningAlg) return undefined;
  if (
    client.tokenEndpointAuthSigningAlgValuesSupported &&
    !client.tokenEndpointAuthSigningAlgValuesSupported.includes(algorithm)
  ) {
    return undefined;
  }
  return algorithm;
}

function validateClaims(
  claims: Record<string, unknown>,
  clientId: string,
  tokenEndpoint: string,
  now: number
): { jti: string; exp: number } | undefined {
  if (claims.iss !== clientId || claims.sub !== clientId) return undefined;

  const audience = claims.aud;
  if (
    !(
      audience === tokenEndpoint ||
      (Array.isArray(audience) &&
        audience.length > 0 &&
        audience.every((value) => typeof value === 'string') &&
        audience.includes(tokenEndpoint))
    )
  ) {
    return undefined;
  }

  const exp = claims.exp;
  if (typeof exp !== 'number' || !Number.isInteger(exp) || exp + PRIVATE_KEY_JWT_CLOCK_SKEW_SECONDS <= now) {
    return undefined;
  }

  const jti = claims.jti;
  if (typeof jti !== 'string' || jti.length === 0) return undefined;

  if (claims.nbf !== undefined) {
    const nbf = claims.nbf;
    if (typeof nbf !== 'number' || !Number.isInteger(nbf) || nbf > now + PRIVATE_KEY_JWT_CLOCK_SKEW_SECONDS) {
      return undefined;
    }
  }

  if (claims.iat !== undefined) {
    const iat = claims.iat;
    if (typeof iat !== 'number' || !Number.isInteger(iat) || iat > now + PRIVATE_KEY_JWT_CLOCK_SKEW_SECONDS) {
      return undefined;
    }
  }

  return { jti, exp };
}

function selectVerificationKey(
  jwks: OAuthClientJsonWebKeySet,
  algorithm: string,
  kid: unknown
): OAuthClientJsonWebKey | undefined {
  if (kid !== undefined && (typeof kid !== 'string' || kid.length === 0)) return undefined;

  const keys = jwks.keys.filter((key) => {
    if (kid && key.kid !== kid) return false;
    if (key.alg && key.alg !== algorithm) return false;
    if (key.use && key.use !== 'sig') return false;
    if (key.key_ops && !key.key_ops.includes('verify')) return false;
    if (algorithm === 'RS256' && key.kty !== 'RSA') return false;
    if (algorithm === 'ES256' && key.kty !== 'EC') return false;
    return true;
  });

  if (kid) return keys[0];
  return keys.length === 1 ? keys[0] : undefined;
}

async function verifySignature(
  algorithm: string,
  jwk: OAuthClientJsonWebKey,
  signingInput: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  try {
    const importAlgorithm: Parameters<SubtleCrypto['importKey']>[2] =
      algorithm === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } : { name: 'ECDSA', namedCurve: 'P-256' };
    const verifyAlgorithm: Parameters<SubtleCrypto['verify']>[0] =
      algorithm === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };
    const key = await crypto.subtle.importKey('jwk', jwk, importAlgorithm, false, ['verify']);
    return await crypto.subtle.verify(verifyAlgorithm, key, signature, signingInput);
  } catch {
    return false;
  }
}

async function fetchPublicJwks(jwksUri: string | undefined): Promise<OAuthClientJsonWebKeySet | undefined> {
  if (!jwksUri) return undefined;

  let url: URL;
  try {
    url = new URL(jwksUri);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) return undefined;

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), PRIVATE_KEY_JWT_JWKS_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      headers: { Accept: 'application/json', 'Cache-Control': 'no-store' },
      signal: abortController.signal,
      cache: 'no-store',
    });
    if (!response.ok) return undefined;

    const value = await readJsonWithSizeLimit(response, PRIVATE_KEY_JWT_JWKS_MAX_BYTES);
    return parsePublicJwks(value);
  } catch {
    return undefined;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function readJsonWithSizeLimit(response: Response, maxBytes: number): Promise<unknown> {
  const contentLength = response.headers.get('Content-Length');
  if (contentLength !== null && Number(contentLength) > maxBytes) throw new Error('JWKS response is too large');

  const reader = response.body?.getReader();
  if (!reader) throw new Error('JWKS response body is empty');

  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error('JWKS response is too large');
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes));
}

function parsePublicJwks(value: unknown): OAuthClientJsonWebKeySet | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const keys = (value as { keys?: unknown }).keys;
  if (!Array.isArray(keys)) return undefined;

  const privateMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
  const publicKeys: OAuthClientJsonWebKey[] = [];
  for (const value of keys) {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
    const key = value as Record<string, unknown>;
    if (typeof key.kty !== 'string' || key.kty.length === 0) return undefined;
    if (Object.keys(key).some((member) => privateMembers.has(member))) return undefined;
    publicKeys.push({ ...key } as unknown as OAuthClientJsonWebKey);
  }
  return { keys: publicKeys };
}

function parseJsonObject(encoded: string): Record<string, unknown> {
  const parsed = JSON.parse(
    new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(base64UrlToBytes(encoded))
  );
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('Expected object');
  return parsed as Record<string, unknown>;
}

function base64UrlToBytes(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '='));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
