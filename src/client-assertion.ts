/**
 * `private_key_jwt` client authentication (RFC 7523 §2.2 and §3, OpenID Connect Core §9) for
 * clients identified by a Client ID Metadata Document.
 *
 * Reuses the EMA pipeline's JWT parser, key selection, WebCrypto verification, cached JWKS
 * fetcher, and KV replay store, so both assertion paths share one reviewed implementation.
 */

import type { EmaSupportedAlg } from './ema/constants';
import { createKvJtiStore } from './ema/jti';
import { createDefaultJwksProvider } from './ema/jwks';
import { parseIdJag } from './ema/parser';
import { err, ok, type EmaValidationError, type Result } from './ema/result';
import { selectJwk, verifyIdJagSignature } from './ema/signature';
import type { EmaJwksProvider, JsonWebKeySet, OAuthJsonWebKey } from './ema/types';

/** RFC 7523 §2.2 `client_assertion_type` for a JWT client assertion. */
export const JWT_BEARER_CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** JWS algorithms accepted on a client assertion. */
export const CLIENT_ASSERTION_ALGORITHMS: readonly EmaSupportedAlg[] = ['RS256', 'ES256'];

/** Largest compact JWS accepted as a client assertion. */
const CLIENT_ASSERTION_MAX_BYTES = 16 * 1024;

/** Allowed clock skew on `exp`, `nbf`, and `iat`. */
const CLIENT_ASSERTION_CLOCK_SKEW_SECONDS = 60;

/**
 * Longest remaining lifetime accepted on an assertion. A client assertion is minted per request,
 * and the bound caps how long its replay marker stays in KV.
 */
const CLIENT_ASSERTION_MAX_LIFETIME_SECONDS = 60 * 60;

/** Most client JWKS kept in the per-isolate cache; their URLs come from client metadata. */
const CLIENT_JWKS_CACHE_MAX_ENTRIES = 256;

/** KV prefix for client assertion replay markers. Stable across versions. */
const CLIENT_ASSERTION_JTI_KV_PREFIX = 'client-assertion-jti:';

/** draft-ietf-oauth-rfc7523bis explicit type. A typed assertion must use the issuer as its sole audience. */
const CLIENT_AUTHENTICATION_JWT_TYPES = new Set(['client-authentication+jwt', 'application/client-authentication+jwt']);

/** Whether a public JWK could verify an assertion signed with `alg`, by key type and curve. */
export function isKeyUsableForAlgorithm(key: OAuthJsonWebKey, alg: EmaSupportedAlg): boolean {
  if (key.use !== undefined && key.use !== 'sig') return false;
  if (key.alg !== undefined && key.alg !== alg) return false;
  if (Array.isArray(key.key_ops) && !key.key_ops.includes('verify')) return false;
  return alg === 'RS256' ? key.kty === 'RSA' : key.kty === 'EC' && key.crv === 'P-256';
}

/** Keys and algorithms a CIMD client registered for `private_key_jwt`. */
export interface ClientAssertionKeys {
  /** Inline public JWKS from the metadata document. Exactly one of `jwks` and `jwksUri` is set. */
  readonly jwks?: JsonWebKeySet;
  /** HTTPS JWKS URL from the metadata document. */
  readonly jwksUri?: string;
  /** Algorithms the client may sign with, narrowed by its `token_endpoint_auth_signing_alg` metadata. */
  readonly algorithms: readonly EmaSupportedAlg[];
}

/** Request context a client assertion is validated against. */
export interface ClientAssertionInput {
  /** The `client_assertion` form parameter. */
  readonly assertion: unknown;
  /** The client the request identified, whose `client_id` must be the assertion's `iss` and `sub`. */
  readonly clientId: string;
  readonly keys: ClientAssertionKeys;
  /** RFC 8414 issuer identifier of this authorization server. */
  readonly issuer: string;
  /** Absolute token endpoint URL, accepted as an audience on an untyped (RFC 7523) assertion. */
  readonly tokenEndpoint: string;
  readonly env: { OAUTH_KV: KVNamespace };
}

/** Verifies `private_key_jwt` client assertions. One instance per provider owns the JWKS cache. */
export interface ClientAssertionVerifier {
  verify(input: ClientAssertionInput): Promise<Result<void, EmaValidationError>>;
}

/**
 * Reads the unverified `iss` of a client assertion, so a request that omits `client_id` can still
 * locate the client. The assertion is verified against that client's keys before it is trusted.
 */
export function readClientAssertionIssuer(assertion: unknown): string | undefined {
  if (typeof assertion !== 'string') return undefined;
  const parsed = parseIdJag(assertion, CLIENT_ASSERTION_MAX_BYTES);
  if (!parsed.ok) return undefined;
  const iss = parsed.value.rawClaims.iss;
  return typeof iss === 'string' && iss.length > 0 ? iss : undefined;
}

/** Creates a verifier with its own JWKS cache and replay store. */
export function createClientAssertionVerifier(): ClientAssertionVerifier {
  const jwksProvider = createDefaultJwksProvider({ maxEntries: CLIENT_JWKS_CACHE_MAX_ENTRIES });
  const jtiStore = createKvJtiStore(CLIENT_ASSERTION_JTI_KV_PREFIX);

  return {
    async verify(input) {
      if (typeof input.assertion !== 'string') return err({ reason: 'assertion_missing' });
      const parsed = parseIdJag(input.assertion, CLIENT_ASSERTION_MAX_BYTES);
      if (!parsed.ok) return parsed;

      const header = validateHeader(parsed.value.header, input.keys.algorithms);
      if (!header.ok) return header;

      // Claims are checked before any key is fetched, so an assertion that could never be accepted
      // doesn't make this server fetch the client's JWKS. Nothing here is trusted until the
      // signature verifies below.
      const now = Math.floor(Date.now() / 1000);
      const claims = validateClaims(parsed.value.rawClaims, input, header.value.typed, now);
      if (!claims.ok) return claims;

      const verified = await verifySignature({
        parsed: parsed.value,
        alg: header.value.alg,
        kid: header.value.kid,
        keys: input.keys,
        jwksProvider,
        now,
      });
      if (!verified.ok) return verified;

      return jtiStore.markUsed({
        issuer: input.clientId,
        jti: claims.value.jti,
        // The assertion stays acceptable for the clock skew past exp, so its marker must too.
        exp: claims.value.exp + CLIENT_ASSERTION_CLOCK_SKEW_SECONDS,
        now: Math.floor(Date.now() / 1000),
        env: input.env,
      });
    },
  };
}

function validateHeader(
  header: Record<string, unknown>,
  algorithms: readonly EmaSupportedAlg[]
): Result<{ alg: EmaSupportedAlg; kid: string | undefined; typed: boolean }, EmaValidationError> {
  // No JOSE extension is implemented, so none may be marked critical, and RFC 7797 unencoded
  // payloads would change what the signature covers.
  if (header.crit !== undefined || header.b64 !== undefined) return err({ reason: 'assertion_malformed' });

  const alg = header.alg;
  if (typeof alg !== 'string' || !(algorithms as readonly string[]).includes(alg)) {
    return err({ reason: 'invalid_alg', got: alg });
  }

  // An untyped or plain "JWT" assertion follows RFC 7523. Any other explicit type (an ID-JAG, an
  // access token) is a different kind of JWT and must not authenticate a client.
  const typ = header.typ;
  let typed = false;
  if (typ !== undefined) {
    const normalized = typeof typ === 'string' ? typ.toLowerCase() : '';
    typed = CLIENT_AUTHENTICATION_JWT_TYPES.has(normalized);
    if (!typed && normalized !== 'jwt') return err({ reason: 'invalid_typ', got: typ });
  }

  const kid = header.kid;
  if (kid !== undefined && (typeof kid !== 'string' || kid.length === 0)) {
    return err({ reason: 'assertion_malformed' });
  }

  return ok({ alg: alg as EmaSupportedAlg, kid, typed });
}

function validateClaims(
  claims: Record<string, unknown>,
  input: ClientAssertionInput,
  typed: boolean,
  now: number
): Result<{ jti: string; exp: number }, EmaValidationError> {
  // RFC 7523 §3 items 1 and 2.B: a client authenticates as itself.
  if (claims.iss !== input.clientId) {
    return err({ reason: 'client_id_mismatch', expected: input.clientId, got: String(claims.iss) });
  }
  if (claims.sub !== input.clientId) {
    return err({ reason: 'client_id_mismatch', expected: input.clientId, got: String(claims.sub) });
  }

  // draft-ietf-oauth-rfc7523bis §4: a typed assertion names the issuer as its only audience, as a
  // string. RFC 7523 §3 item 3 lets an untyped one also name the token endpoint, among others.
  const aud = claims.aud;
  const audienceOk = typed
    ? aud === input.issuer
    : aud === input.issuer ||
      aud === input.tokenEndpoint ||
      (Array.isArray(aud) &&
        aud.every((value) => typeof value === 'string') &&
        (aud.includes(input.issuer) || aud.includes(input.tokenEndpoint)));
  if (!audienceOk) {
    return err({
      reason: 'aud_mismatch',
      expected: input.issuer,
      got: Array.isArray(aud) ? aud.map(String) : String(aud),
    });
  }

  const exp = claims.exp;
  if (typeof exp !== 'number' || !Number.isInteger(exp)) return err({ reason: 'invalid_claim', claim: 'exp' });
  if (exp + CLIENT_ASSERTION_CLOCK_SKEW_SECONDS <= now) return err({ reason: 'expired', exp, now });
  if (exp - now > CLIENT_ASSERTION_MAX_LIFETIME_SECONDS) {
    return err({ reason: 'lifetime_too_long', lifetime: exp - now, max: CLIENT_ASSERTION_MAX_LIFETIME_SECONDS });
  }

  const nbf = claims.nbf;
  if (nbf !== undefined) {
    if (typeof nbf !== 'number' || !Number.isInteger(nbf)) return err({ reason: 'invalid_claim', claim: 'nbf' });
    if (nbf > now + CLIENT_ASSERTION_CLOCK_SKEW_SECONDS) {
      return err({ reason: 'nbf_in_future', nbf, now, skew: CLIENT_ASSERTION_CLOCK_SKEW_SECONDS });
    }
  }

  const iat = claims.iat;
  if (iat !== undefined) {
    if (typeof iat !== 'number' || !Number.isInteger(iat)) return err({ reason: 'invalid_claim', claim: 'iat' });
    if (iat > now + CLIENT_ASSERTION_CLOCK_SKEW_SECONDS) {
      return err({ reason: 'iat_in_future', iat, now, skew: CLIENT_ASSERTION_CLOCK_SKEW_SECONDS });
    }
  }

  // RFC 7523 makes jti optional, but without one an intercepted assertion replays until it expires.
  const jti = claims.jti;
  if (typeof jti !== 'string' || jti.length === 0) return err({ reason: 'invalid_claim', claim: 'jti' });

  return ok({ jti, exp });
}

async function verifySignature(args: {
  parsed: { signingInput: Uint8Array; signature: Uint8Array };
  alg: EmaSupportedAlg;
  kid: string | undefined;
  keys: ClientAssertionKeys;
  jwksProvider: EmaJwksProvider;
  now: number;
}): Promise<Result<void, EmaValidationError>> {
  const { keys, alg, kid, parsed } = args;
  const verifyWith = async (jwks: JsonWebKeySet): Promise<Result<void, EmaValidationError>> => {
    const jwk = selectJwk(jwks, alg, kid);
    if (!jwk.ok) return jwk;
    const verified = await verifyIdJagSignature({
      alg,
      jwk: jwk.value,
      signingInput: parsed.signingInput,
      signature: parsed.signature,
    });
    return verified ? ok(undefined) : err({ reason: 'signature_failed' });
  };

  if (keys.jwks) return verifyWith(keys.jwks);
  if (!keys.jwksUri) return err({ reason: 'no_matching_key' });

  // The cache is keyed by the JWKS URL, so two clients sharing one key set share one entry.
  const source = { issuer: keys.jwksUri, jwksUri: keys.jwksUri };
  const initial = await args.jwksProvider.fetch(source, { forceRefresh: false, now: args.now });
  if (!initial.ok) return initial;
  const result = await verifyWith(initial.value);
  if (result.ok) return result;

  // A missing kid, or a kid whose key no longer verifies, may mean the client rotated its keys
  // since the set was cached. Refetch once; the provider's cool-down bounds how often a stream of
  // bad assertions can make this server fetch the client's JWKS.
  const refreshed = await args.jwksProvider.fetch(source, { forceRefresh: true, now: args.now });
  if (!refreshed.ok) return refreshed;
  return verifyWith(refreshed.value);
}
