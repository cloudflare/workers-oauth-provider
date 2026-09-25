import {
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
  type JWTPayload,
} from 'jose';
import type { OAuthResourceTokenValidation, OAuthResourceTokenValidator } from './oauth-resource-server';

/**
 * The one signature algorithm for access tokens: ECDSA P-256 with SHA-256.
 *
 * Cloudflare Codex RFC-031 makes ML-DSA-44 the default signature algorithm and ECDSA P-256 the
 * default wherever ML-DSA is not available. Workers WebCrypto does not provide ML-DSA, so the
 * library signs with ES256 only. RS256 (RSA-PKCS1v1.5) is REVIEW tier and not offered.
 */
export const JWT_ACCESS_TOKEN_ALGORITHM = 'ES256' as const;

/** RFC 9068 media type for JWT access tokens, published as the JOSE `typ` header. */
export const JWT_ACCESS_TOKEN_TYPE = 'at+jwt' as const;

/** A JSON value allowed in a custom access-token claim. */
export type JwtClaimValue = null | boolean | number | string | JwtClaimValue[] | { [key: string]: JwtClaimValue };

/** An EC P-256 JSON Web Key with the `kid` that names it in the JWKS. */
export interface JwtKey extends JWK {
  kty: 'EC';
  crv: 'P-256';
  kid: string;
}

/**
 * The keys an authorization server signs with and publishes, resolved per request so rotation
 * is a secret change, not a deploy. Store the private key in an approved secrets system and
 * rotate at least every 90 days (Codex RFC-031): publish the next key in `additional` first,
 * then make it `current` and move the old one to `additional`, then drop the old one once its
 * tokens have expired.
 */
export interface JwtKeySet {
  /** The EC P-256 private JWK (includes `d`) that signs new access tokens. */
  current: JwtKey;
  /** Public JWKs published beside it but never used to sign: the next key, or the previous one. */
  additional?: JwtKey[];
}

/** What the `claims` hook knows about the access token being issued. */
export interface JwtClaimsInput<Env = Cloudflare.Env, Props = any> {
  userId: string;
  grantId: string;
  clientId: string;
  scope: string[];
  audience: string;
  /** The grant's decrypted props. Anything returned from `claims` is readable by the client. */
  props: Props;
  env: Env;
}

/**
 * Experimental: exempt from 1.x semver, see docs/jwt-access-tokens.md.
 *
 * Signed JWT access tokens for `OAuthAuthorizationServer`.
 *
 * Only the access token changes. Authorization codes and refresh tokens stay opaque, and the
 * provider still stores a record per access token, so `validateToken()` sees revocation
 * immediately. A resource server that validates offline with
 * {@link createJwtAccessTokenValidator} does not, so keep `accessTokenTTL` short.
 *
 * @experimental
 */
export interface JwtAccessTokenOptions<Env = Cloudflare.Env, Props = any> {
  /** Resolve the signing key and any additional published keys. */
  keys(env: Env): JwtKeySet | Promise<JwtKeySet>;
  /**
   * Add top-level claims. JWT payloads are signed, not encrypted: never return secrets.
   * Claims the provider sets are rejected: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`,
   * `client_id`, `scope` and `grant_id`.
   */
  claims?(
    input: JwtClaimsInput<Env, Props>
  ): Record<string, JwtClaimValue> | void | Promise<Record<string, JwtClaimValue> | void>;
}

/**
 * Access-token formats for `OAuthAuthorizationServer`. `issuing` is the one format new tokens
 * use. Configuring `jwt` accepts JWTs and publishes their keys. Opaque tokens are always accepted
 * until their records expire, and refresh tokens are always opaque.
 *
 * Switching to JWTs, each step safe to roll back:
 * 1. `{ issuing: 'opaque', jwt }` publishes the JWKS before any JWT exists.
 * 2. `{ issuing: 'jwt', jwt }` issues JWTs; earlier opaque tokens keep working until they expire.
 * To roll back, issue `'opaque'` again and keep `jwt`, so outstanding JWTs stay valid.
 *
 * Experimental: exempt from 1.x semver, see docs/jwt-access-tokens.md.
 *
 * @experimental
 */
export interface AccessTokenOptions<Env = Cloudflare.Env, Props = any> {
  /** The format new access tokens are issued in. `'jwt'` requires `jwt`. */
  issuing: 'opaque' | 'jwt';
  /** Accept JWT access tokens and publish their keys. Required to issue them. */
  jwt?: JwtAccessTokenOptions<Env, Props>;
}

/** Claims every access token carries (RFC 9068 §2.2, plus the provider's grant ID). */
export interface JwtAccessTokenClaims extends JWTPayload {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  client_id: string;
  scope?: string;
  /** The provider grant the token belongs to. */
  grant_id: string;
}

/**
 * Options for {@link createJwtAccessTokenValidator}.
 *
 * @experimental
 */
export interface JwtAccessTokenValidatorOptions<Env = Cloudflare.Env, Props = undefined> {
  /** The authorization server whose tokens this validator accepts: its exact `iss`. */
  issuer: string;
  /**
   * The authorization server's public keys: the `keys` of its JWKS. How you get them is yours:
   * fetch `/.well-known/jwks.json` (over a Service Binding or the internet) and cache it, or read
   * them from configuration. A thrown error fails closed.
   */
  keys(env: Env): JwtKey[] | Promise<JwtKey[]>;
  /**
   * Build `ctx.props` from the verified claims, or return `null` to reject the token. Without it,
   * `ctx.props` is `undefined`; the verified subject, client and scopes are always on `ctx.auth`.
   */
  mapClaims?(claims: JwtAccessTokenClaims, env: Env): Props | null | Promise<Props | null>;
}

const RESERVED_CLAIMS = new Set(['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'client_id', 'scope', 'grant_id']);
const REQUIRED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id', 'grant_id'];
const CLOCK_TOLERANCE_SECONDS = 30;
const MAX_TOKEN_LENGTH = 16 * 1024;

/** Check access-token options at construction, so a misconfiguration fails before the first request. */
export function validateAccessTokenOptions(options: AccessTokenOptions<any, any>): void {
  if (!options || typeof options !== 'object') throw new TypeError('accessTokens must be an object');
  if (options.issuing !== 'opaque' && options.issuing !== 'jwt') {
    throw new TypeError("accessTokens.issuing must be 'opaque' or 'jwt'");
  }
  const jwt = options.jwt;
  if (jwt === undefined) {
    if (options.issuing === 'jwt') {
      throw new TypeError("accessTokens.issuing is 'jwt' but accessTokens.jwt is not configured");
    }
    return;
  }
  if (!jwt || typeof jwt.keys !== 'function') throw new TypeError('accessTokens.jwt.keys must be a function');
  if (jwt.claims !== undefined && typeof jwt.claims !== 'function') {
    throw new TypeError('accessTokens.jwt.claims must be a function');
  }
}

/** A resolved, checked key set. */
export interface ResolvedJwtKeys {
  current: JwtKey;
  /** Every public key, current first, as published in the JWKS. */
  publicKeys: JwtKey[];
}

/** Resolve and check the configured keys. */
export async function resolveJwtKeys(options: JwtAccessTokenOptions<any, any>, env: unknown): Promise<ResolvedJwtKeys> {
  const keySet = await options.keys(env);
  const current = keySet?.current;
  checkKey(current, 'current');
  if (typeof current.d !== 'string' || !current.d)
    throw new TypeError('accessTokens.jwt.keys(): current must be a private JWK');
  const additional = keySet.additional ?? [];
  if (!Array.isArray(additional)) throw new TypeError('accessTokens.jwt.keys(): additional must be an array');
  additional.forEach((key, index) => checkKey(key, `additional[${index}]`));

  const publicKeys = [current, ...additional].map(toPublicJwk);
  const kids = new Set(publicKeys.map((key) => key.kid));
  if (kids.size !== publicKeys.length) throw new TypeError('accessTokens.jwt.keys(): every kid must be unique');
  return { current, publicKeys };
}

/** Sign an access token with the current key. */
export async function signAccessToken(key: JwtKey, claims: JwtAccessTokenClaims): Promise<string> {
  const privateKey = await importJWK(key, JWT_ACCESS_TOKEN_ALGORITHM);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: JWT_ACCESS_TOKEN_ALGORITHM, typ: JWT_ACCESS_TOKEN_TYPE, kid: key.kid })
    .sign(privateKey);
}

/** Merge custom claims over the provider's claims, rejecting reserved names and non-JSON values. */
export function mergeCustomClaims(
  base: JwtAccessTokenClaims,
  custom: Record<string, JwtClaimValue> | void | undefined
): JwtAccessTokenClaims {
  if (custom === undefined) return base;
  if (custom === null || typeof custom !== 'object' || Array.isArray(custom)) {
    throw new TypeError('accessTokens.jwt.claims must return an object');
  }
  const merged: JwtAccessTokenClaims = { ...base };
  for (const [name, value] of Object.entries(custom)) {
    if (RESERVED_CLAIMS.has(name)) throw new TypeError(`accessTokens.jwt.claims must not set reserved claim "${name}"`);
    merged[name] = cloneClaimValue(value, 0);
  }
  return merged;
}

/**
 * Whether a bearer value looks like a JWT access token: a compact JWS whose protected header
 * names `typ: at+jwt`. Cheap and unauthenticated; always verify before trusting anything in it.
 */
export function looksLikeJwtAccessToken(token: string): boolean {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH || token.split('.').length !== 3) return false;
  try {
    return decodeProtectedHeader(token).typ?.toLowerCase() === JWT_ACCESS_TOKEN_TYPE;
  } catch {
    return false;
  }
}

/**
 * Where the authorization server stored a JWT access token's record: its `sub` and `grant_id`,
 * read without verification. The record is looked up by the token's hash, so a token that is not
 * exactly one this server issued has no record, whatever these claims say.
 */
export function readAccessTokenLocation(token: string): { userId: string; grantId: string } | null {
  if (!looksLikeJwtAccessToken(token)) return null;
  try {
    const { sub, grant_id } = decodeJwt(token);
    return typeof sub === 'string' && sub && typeof grant_id === 'string' && grant_id
      ? { userId: sub, grantId: grant_id }
      : null;
  } catch {
    return null;
  }
}

/**
 * Experimental: exempt from 1.x semver, see docs/jwt-access-tokens.md.
 *
 * Validate the provider's JWT access tokens offline in a resource server, without calling the
 * authorization server. Returns a factory for `OAuthResourceServer`'s `validateToken`:
 *
 * ```ts
 * new OAuthResourceServer({
 *   resourceMetadata: { resource, authorization_servers: ['https://auth.example.com'] },
 *   handler,
 *   validateToken: createJwtAccessTokenValidator({
 *     issuer: 'https://auth.example.com',
 *     keys: (env) => JSON.parse(env.JWT_PUBLIC_KEYS),
 *   }),
 * });
 * ```
 *
 * Tokens whose `iss` is not `issuer` are rejected before any keys load, so to accept several
 * authorization servers, call one validator per server from your own `validateToken`. Only EC
 * P-256 keys with a `kid` are used; other keys are ignored. Offline validation cannot see
 * revocation until the token expires.
 *
 * @experimental
 */
export function createJwtAccessTokenValidator<Env = Cloudflare.Env>(
  options: JwtAccessTokenValidatorOptions<Env> & { mapClaims?: undefined }
): (env: Env) => OAuthResourceTokenValidator<undefined>;
export function createJwtAccessTokenValidator<Env = Cloudflare.Env, Props = undefined>(
  options: JwtAccessTokenValidatorOptions<Env, Props> & {
    mapClaims: NonNullable<JwtAccessTokenValidatorOptions<Env, Props>['mapClaims']>;
  }
): (env: Env) => OAuthResourceTokenValidator<Props>;
export function createJwtAccessTokenValidator<Env, Props>(
  options: JwtAccessTokenValidatorOptions<Env, Props>
): (env: Env) => OAuthResourceTokenValidator<Props | undefined> {
  if (typeof options?.issuer !== 'string' || !options.issuer) throw new TypeError('issuer is required');
  if (typeof options.keys !== 'function') throw new TypeError('keys must be a function');
  const { issuer } = options;
  if (options.mapClaims !== undefined && typeof options.mapClaims !== 'function') {
    throw new TypeError('mapClaims must be a function');
  }

  return (env) =>
    async (resource, token): Promise<OAuthResourceTokenValidation<Props | undefined> | null> => {
      if (!looksLikeJwtAccessToken(token)) return null;
      // Another server's token is not ours: reject before loading keys. Verification below still
      // requires this exact `iss` and a valid signature.
      if (unverifiedIssuer(token) !== issuer) return null;
      const keys = await options.keys(env);
      if (!Array.isArray(keys)) throw new TypeError('keys() must return an array of JWKs');
      const usable = keys.filter(isEcP256Jwk).map(toPublicJwk);
      const claims = await verifyWith(token, createLocalJWKSet({ keys: usable }), issuer, [resource]);
      if (!claims) return null;
      let props: Props | undefined;
      if (options.mapClaims) {
        const mapped = await options.mapClaims(claims, env);
        if (mapped === null) return null;
        props = mapped;
      }
      return {
        props,
        audience: claims.aud,
        expiresAt: claims.exp,
        scope: claims.scope ? claims.scope.split(' ') : [],
        userId: claims.sub,
        clientId: claims.client_id,
      };
    };
}

function unverifiedIssuer(token: string): string | undefined {
  try {
    const { iss } = decodeJwt(token);
    return typeof iss === 'string' ? iss : undefined;
  } catch {
    return undefined;
  }
}

/** An EC P-256 JWK with a `kid`, usable for ES256. */
function isEcP256Jwk(key: unknown): key is JwtKey {
  if (!key || typeof key !== 'object') return false;
  const jwk = key as JwtKey;
  return (
    jwk.kty === 'EC' &&
    jwk.crv === 'P-256' &&
    typeof jwk.x === 'string' &&
    typeof jwk.y === 'string' &&
    typeof jwk.kid === 'string' &&
    jwk.kid.length > 0 &&
    (jwk.alg === undefined || jwk.alg === JWT_ACCESS_TOKEN_ALGORITHM)
  );
}

async function verifyWith(
  token: string,
  keys: ReturnType<typeof createLocalJWKSet>,
  issuer: string,
  audiences: string[]
): Promise<JwtAccessTokenClaims | null> {
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, keys, {
      algorithms: [JWT_ACCESS_TOKEN_ALGORITHM],
      typ: JWT_ACCESS_TOKEN_TYPE,
      issuer,
      audience: audiences,
      requiredClaims: REQUIRED_CLAIMS,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    }));
  } catch {
    // Every verification failure, including an unknown key, is a rejection: invalid_token.
    return null;
  }
  const { aud, sub, client_id, grant_id, jti, scope } = payload;
  if (typeof aud !== 'string' || typeof sub !== 'string' || !sub) return null;
  if (typeof client_id !== 'string' || typeof grant_id !== 'string' || !grant_id || typeof jti !== 'string')
    return null;
  if (scope !== undefined && typeof scope !== 'string') return null;
  return payload as JwtAccessTokenClaims;
}

function checkKey(key: JwtKey | undefined, name: string): asserts key is JwtKey {
  if (!isEcP256Jwk(key)) {
    throw new TypeError(`accessTokens.jwt.keys(): ${name} must be an EC P-256 JWK with a kid, for ES256`);
  }
}

function toPublicJwk(key: JwtKey): JwtKey {
  return { kty: 'EC', crv: 'P-256', x: key.x, y: key.y, kid: key.kid, alg: JWT_ACCESS_TOKEN_ALGORITHM, use: 'sig' };
}

function cloneClaimValue(value: JwtClaimValue, depth: number): JwtClaimValue {
  if (depth > 32) throw new TypeError('accessTokens.jwt.claims values are nested too deeply');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('accessTokens.jwt.claims numbers must be finite');
    return value;
  }
  if (Array.isArray(value)) return value.map((item) => cloneClaimValue(item, depth + 1));
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, cloneClaimValue(v, depth + 1)]));
  }
  throw new TypeError('accessTokens.jwt.claims values must be JSON');
}
