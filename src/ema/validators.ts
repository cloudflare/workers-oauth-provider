/**
 * Pure validators for the MCP Enterprise-Managed Authorization flow.
 *
 * Each function takes plain data, performs one well-defined check, and
 * returns `Result<T, EmaValidationError>`. No `this`. No I/O. No clock —
 * `now` is always passed in so tests stay deterministic.
 *
 * Composed by the orchestrator (`src/ema/orchestrator.ts`) into the full
 * token-request pipeline.
 */

import type { ClientInfo } from '../oauth-provider';
import { isValidOAuthScopeToken, resourceMatches, validateResourceUri } from '../oauth-provider';
import { EMA_DEFAULT_JWT_ALGORITHM, EMA_SUPPORTED_JWT_ALGORITHMS, type EmaSupportedAlg } from './constants';
import { err, ok, type EmaValidationError, type Result } from './result';
import type {
  EmaClaimsMapperResult,
  EmaIdJagClaims,
  EmaTrustedIssuer,
  EmaTrustedIssuerResolver,
  ValidatedIdJag,
  ValidatedIdJagHeader,
} from './types';

// ─── Header ───────────────────────────────────────────────────────────────────

/**
 * Validate the JOSE header of an ID-JAG. Enforces the `typ=oauth-id-jag+jwt`
 * marker (RFC 8725 §3.11) and an `alg` within the AS's global allowlist.
 * Per-issuer `algorithms` is checked separately in `selectTrustedIssuer`.
 */
export function validateIdJagHeader(
  header: Record<string, unknown>,
  expectedTyp: string,
  supportedAlgs: ReadonlySet<EmaSupportedAlg>
): Result<ValidatedIdJagHeader, EmaValidationError> {
  const typ = header.typ;
  if (typeof typ !== 'string' || typ !== expectedTyp) {
    return err({ reason: 'invalid_typ', got: typ });
  }

  const alg = header.alg;
  if (typeof alg !== 'string' || alg === 'none' || !supportedAlgs.has(alg as EmaSupportedAlg)) {
    return err({ reason: 'invalid_alg', got: alg });
  }

  const kidRaw = header.kid;
  const kid = typeof kidRaw === 'string' && kidRaw.length > 0 ? kidRaw : undefined;

  return ok({ typ, alg, kid });
}

// ─── Issuer trust ─────────────────────────────────────────────────────────────

interface ResolveTrustedIssuerInput<Env> {
  iss: unknown;
  alg: EmaSupportedAlg;
  resolver: EmaTrustedIssuerResolver<Env>;
  env: Env;
  request: Request;
  clientInfo: ClientInfo;
}

/**
 * Resolve the `iss` claim through the deployer-supplied resolver, then
 * validate the returned configuration before signature verification ever
 * runs against it.
 *
 * Every failure here collapses to `issuer_not_trusted` so an attacker
 * cannot distinguish "unknown IdP" from "resolver returned a malformed
 * config" from "alg not in the IdP's allowlist".
 *
 * The resolver's returned `issuer` field MUST equal the input `iss`.
 * Otherwise a buggy resolver could be tricked into returning a config
 * for IdP B while validating a JWT that claims to be from IdP A,
 * which would let an attacker forge any IdP they like (since the JWKS
 * would be fetched from B's URI).
 */
export async function resolveTrustedIssuer<Env>(
  input: ResolveTrustedIssuerInput<Env>
): Promise<Result<EmaTrustedIssuer, EmaValidationError>> {
  const { iss, alg, resolver, env, request, clientInfo } = input;

  if (typeof iss !== 'string' || iss.length === 0) {
    return err({ reason: 'invalid_claim', claim: 'iss' });
  }

  let resolved: EmaTrustedIssuer | null;
  try {
    resolved = await resolver({ iss, env, request, clientInfo });
  } catch {
    return err({ reason: 'issuer_not_trusted', iss });
  }

  if (!resolved) {
    return err({ reason: 'issuer_not_trusted', iss });
  }

  // The resolver's returned `issuer` must match the input — this prevents
  // a confused-deputy attack where the resolver is coaxed into returning
  // a different IdP's config than the one the assertion claims.
  if (resolved.issuer !== iss) {
    return err({ reason: 'issuer_not_trusted', iss });
  }

  if (!isWellFormedTrustedIssuer(resolved)) {
    return err({ reason: 'issuer_not_trusted', iss });
  }

  const allowedAlgorithms = resolved.algorithms ?? [EMA_DEFAULT_JWT_ALGORITHM];
  if (!allowedAlgorithms.includes(alg)) {
    return err({ reason: 'issuer_not_trusted', iss });
  }

  return ok(resolved);
}

/**
 * Per-request structural validation of an `EmaTrustedIssuer` returned by
 * a dynamic resolver. Mirrors the construction-time checks that the
 * static-array shape used to get for free.
 */
function isWellFormedTrustedIssuer(issuer: EmaTrustedIssuer): boolean {
  try {
    new URL(issuer.issuer);
  } catch {
    return false;
  }

  let jwksUrl: URL;
  try {
    jwksUrl = new URL(issuer.jwksUri);
  } catch {
    return false;
  }
  if (jwksUrl.protocol !== 'https:') return false;

  const algorithms = issuer.algorithms ?? [EMA_DEFAULT_JWT_ALGORITHM];
  if (algorithms.length === 0) return false;
  for (const alg of algorithms) {
    if (!EMA_SUPPORTED_JWT_ALGORITHMS.has(alg as EmaSupportedAlg)) return false;
  }

  if (issuer.audience !== undefined) {
    try {
      new URL(issuer.audience);
    } catch {
      return false;
    }
  }

  return true;
}

// ─── Claims ───────────────────────────────────────────────────────────────────

interface ValidateClaimsInput {
  rawClaims: Record<string, unknown>;
  trustedIssuer: EmaTrustedIssuer;
  expectedAudience: string;
  clientId: string;
  configuredResource: string;
  matchOriginOnly: boolean;
  now: number;
  clockSkewSeconds: number;
  maxAssertionLifetimeSeconds: number;
}

/**
 * Validate every required ID-JAG claim and produce a typed `ValidatedIdJag`.
 *
 * Enforces (in order):
 *   - presence + type of `iss`, `sub`, `aud`, `resource`, `client_id`, `jti`, `exp`, `iat`
 *   - `aud` contains the AS's expected audience
 *   - `client_id` matches the authenticated client
 *   - `resource` is a valid RFC 8707 URI and matches the AS's configured resource
 *   - `exp` is in the future
 *   - `iat` is not more than `clockSkewSeconds` in the future
 *   - `nbf` (if present) is ≤ `now + clockSkewSeconds`
 *   - `exp - iat` does not exceed `maxAssertionLifetimeSeconds + clockSkewSeconds`
 *   - `scope` (if present) conforms to RFC 6749 §3.3 grammar
 */
export function validateIdJagClaims(input: ValidateClaimsInput): Result<ValidatedIdJag, EmaValidationError> {
  const { rawClaims, trustedIssuer, expectedAudience, clientId, configuredResource, matchOriginOnly } = input;
  const { now, clockSkewSeconds, maxAssertionLifetimeSeconds } = input;

  const iss = readRequiredString(rawClaims, 'iss');
  if (!iss.ok) return iss;

  // Defense-in-depth: trustedIssuer.issuer must equal claims.iss because that's
  // how `selectTrustedIssuer` picked it. Reassert here so the function is
  // self-contained and the type narrows.
  if (iss.value !== trustedIssuer.issuer) {
    return err({ reason: 'issuer_not_trusted', iss: iss.value });
  }

  const sub = readRequiredString(rawClaims, 'sub');
  if (!sub.ok) return sub;

  const aud = readAudienceClaim(rawClaims);
  if (!aud.ok) return aud;

  const resource = readRequiredString(rawClaims, 'resource');
  if (!resource.ok) return resource;

  const claimClientId = readRequiredString(rawClaims, 'client_id');
  if (!claimClientId.ok) return claimClientId;

  const jti = readRequiredString(rawClaims, 'jti');
  if (!jti.ok) return jti;

  const exp = readNumericDateClaim(rawClaims, 'exp');
  if (!exp.ok) return exp;

  const iat = readNumericDateClaim(rawClaims, 'iat');
  if (!iat.ok) return iat;

  const audiences = Array.isArray(aud.value) ? aud.value : [aud.value];
  if (!audiences.includes(expectedAudience)) {
    return err({ reason: 'aud_mismatch', expected: expectedAudience, got: aud.value });
  }

  if (claimClientId.value !== clientId) {
    return err({ reason: 'client_id_mismatch', expected: clientId, got: claimClientId.value });
  }

  if (!validateResourceUri(resource.value)) {
    return err({ reason: 'resource_invalid', resource: resource.value });
  }

  if (!resourceMatches(resource.value, configuredResource, matchOriginOnly)) {
    return err({ reason: 'resource_mismatch', expected: configuredResource, got: resource.value });
  }

  if (exp.value <= now) {
    return err({ reason: 'expired', exp: exp.value, now });
  }

  if (iat.value > now + clockSkewSeconds) {
    return err({ reason: 'iat_in_future', iat: iat.value, now, skew: clockSkewSeconds });
  }

  // Optional `nbf` (not-before) claim, RFC 7519 §4.1.5 / RFC 7523 §3 rule 5.
  if (rawClaims.nbf !== undefined) {
    const nbf = readNumericDateClaim(rawClaims, 'nbf');
    if (!nbf.ok) return nbf;
    if (nbf.value > now + clockSkewSeconds) {
      return err({ reason: 'nbf_in_future', nbf: nbf.value, now, skew: clockSkewSeconds });
    }
  }

  const lifetime = exp.value - iat.value;
  if (lifetime > maxAssertionLifetimeSeconds + clockSkewSeconds) {
    return err({ reason: 'lifetime_too_long', lifetime, max: maxAssertionLifetimeSeconds });
  }

  let scope: string | undefined;
  let assertionScopes: string[] = [];
  if (rawClaims.scope !== undefined) {
    const parsed = readRequiredString(rawClaims, 'scope');
    if (!parsed.ok) return parsed;
    const tokens = parseScopeGrammar(parsed.value);
    if (!tokens.ok) {
      return err({ reason: 'invalid_claim', claim: 'scope' });
    }
    scope = parsed.value;
    assertionScopes = tokens.value;
  }

  const claims: EmaIdJagClaims = {
    ...rawClaims,
    iss: iss.value,
    sub: sub.value,
    aud: aud.value,
    resource: resource.value,
    client_id: claimClientId.value,
    jti: jti.value,
    exp: exp.value,
    iat: iat.value,
    scope,
  };

  return ok({ claims, resource: resource.value, assertionScopes });
}

// ─── Scope parameter parsing ──────────────────────────────────────────────────

/**
 * Parse the `scope` parameter of the token request and downscope it to the
 * assertion's own scope claim. If the request omits `scope`, the assertion's
 * scopes are used directly.
 */
export function parseEmaScopeParam(
  scope: unknown,
  assertionScopes: readonly string[]
): Result<string[], EmaValidationError> {
  let requested: string[];
  if (scope === undefined) {
    requested = [...assertionScopes];
  } else if (typeof scope === 'string') {
    const parsed = parseScopeGrammar(scope);
    if (!parsed.ok) return err({ reason: 'invalid_scope_param' });
    requested = parsed.value;
  } else if (Array.isArray(scope) && scope.every((value) => typeof value === 'string')) {
    requested = [];
    for (const part of scope as string[]) {
      const parsed = parseScopeGrammar(part);
      if (!parsed.ok) return err({ reason: 'invalid_scope_param' });
      requested.push(...parsed.value);
    }
  } else {
    return err({ reason: 'invalid_scope_param' });
  }

  if (assertionScopes.length > 0) {
    const allowed = new Set(assertionScopes);
    requested = requested.filter((token) => allowed.has(token));
  }

  return ok(requested);
}

// ─── Mapper result ────────────────────────────────────────────────────────────

/**
 * Validate the shape of the value returned by the deployer's `mapClaims`
 * callback. A `null` return is treated as a deny decision.
 *
 * The `userId.includes(':')` rejection mirrors the opaque token format
 * (`userId:grantId:secret`) used elsewhere in this provider.
 */
export function validateEmaMapperResult(result: unknown): Result<EmaClaimsMapperResult, EmaValidationError> {
  if (result === null) {
    return err({ reason: 'mapper_denied' });
  }

  if (typeof result !== 'object') {
    return err({ reason: 'invalid_mapped_user' });
  }

  const r = result as Partial<EmaClaimsMapperResult>;

  if (typeof r.userId !== 'string' || r.userId.length === 0 || r.userId.includes(':')) {
    return err({ reason: 'invalid_mapped_user' });
  }

  if (!Array.isArray(r.scope) || !r.scope.every((s) => typeof s === 'string' && isValidOAuthScopeToken(s))) {
    return err({ reason: 'invalid_mapped_scope' });
  }

  if (!('props' in r) || r.props === undefined) {
    return err({ reason: 'invalid_mapped_props' });
  }

  if (r.accessTokenTTL !== undefined) {
    if (typeof r.accessTokenTTL !== 'number' || !Number.isFinite(r.accessTokenTTL) || r.accessTokenTTL <= 0) {
      return err({ reason: 'invalid_mapped_ttl' });
    }
  }

  return ok({
    userId: r.userId,
    scope: r.scope,
    props: r.props,
    metadata: r.metadata,
    accessTokenTTL: r.accessTokenTTL,
  });
}

// ─── TTL clamp ────────────────────────────────────────────────────────────────

interface ClampTtlInput {
  configuredDefaultSeconds: number;
  assertionExp: number;
  mapperTtl: number | undefined;
  now: number;
}

/**
 * Compute the access token TTL.
 *
 * The mapper-supplied override wins; otherwise the AS's default applies.
 * The assertion's `exp` governs how long the ID-JAG is valid as a grant,
 * not how long the access token issued in exchange lives — RFC 7523 §3
 * does not bind access-token lifetime to assertion lifetime, and the MCP
 * EMA spec example issues access tokens far longer than the 300s ID-JAG.
 *
 * Returns `assertion_expired_after_processing` if the assertion crossed
 * `exp` while we were validating it (TOCTOU race between claim check and
 * here).
 */
export function clampEmaAccessTokenTTL(input: ClampTtlInput): Result<number, EmaValidationError> {
  const { configuredDefaultSeconds, assertionExp, mapperTtl, now } = input;

  if (assertionExp - now <= 0) {
    return err({ reason: 'assertion_expired_after_processing' });
  }

  return ok(mapperTtl ?? configuredDefaultSeconds);
}

// ─── Local helpers (not exported) ─────────────────────────────────────────────

function readRequiredString(claims: Record<string, unknown>, claimName: string): Result<string, EmaValidationError> {
  const value = claims[claimName];
  if (typeof value !== 'string' || value.length === 0) {
    return err({ reason: 'invalid_claim', claim: claimName });
  }
  return ok(value);
}

function readAudienceClaim(claims: Record<string, unknown>): Result<string | string[], EmaValidationError> {
  const aud = claims.aud;
  if (typeof aud === 'string' && aud.length > 0) {
    return ok(aud);
  }
  if (Array.isArray(aud) && aud.length > 0 && aud.every((v) => typeof v === 'string' && v.length > 0)) {
    return ok(aud);
  }
  return err({ reason: 'invalid_claim', claim: 'aud' });
}

function readNumericDateClaim(claims: Record<string, unknown>, claimName: string): Result<number, EmaValidationError> {
  const value = claims[claimName];
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    return err({ reason: 'invalid_claim', claim: claimName });
  }
  return ok(value);
}

function parseScopeGrammar(scope: string): Result<string[], { reason: 'invalid_scope_grammar' }> {
  if (!scope) return ok([]);
  const tokens = scope.split(' ').filter(Boolean);
  for (const token of tokens) {
    if (!isValidOAuthScopeToken(token)) return err({ reason: 'invalid_scope_grammar' });
  }
  return ok(tokens);
}
