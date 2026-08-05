import { validateResourceUri } from './oauth-resource';
import { isValidOAuthScopeToken } from './oauth-capabilities';

/** Collision-resistant private claim carrying the provider's grant identifier. */
export const JWT_ACCESS_TOKEN_GRANT_ID_CLAIM = 'https://workers.cloudflare.com/oauth-provider/claims/grant-id' as const;

/**
 * Collision-resistant private claim containing only application data that the
 * deployer explicitly chose to make readable to the access-token holder.
 */
export const JWT_ACCESS_TOKEN_PUBLIC_CLAIMS = 'https://workers.cloudflare.com/oauth-provider/claims/public' as const;

const DEFAULT_MAX_TOKEN_BYTES = 16 * 1024;
const MAX_CONFIGURED_TOKEN_BYTES = 128 * 1024;
const MAX_KEY_ID_LENGTH = 128;
const MAX_PUBLIC_CLAIM_DEPTH = 64;
const MAX_PUBLIC_CLAIM_NODES = 10_000;
const verifiedSigningKeyPairs = new WeakMap<CryptoKey, Map<string, Promise<void>>>();
const JWT_TYPE = 'at+jwt';
const ACCEPTED_JWT_TYPES = new Set([JWT_TYPE, 'application/at+jwt']);
const FORBIDDEN_JOSE_HEADERS = ['jku', 'jwk', 'x5u', 'x5c', 'b64'] as const;

/** JSON value accepted in the explicitly public application claim. */
export type JwtJsonValue = null | boolean | number | string | JwtJsonValue[] | { [key: string]: JwtJsonValue };

/** Asymmetric algorithms supported by the RFC 9068 helper. */
export type JwtAccessTokenAlgorithm = 'RS256' | 'ES256';

/** Public verification key with the JOSE fields required for safe selection. */
export interface JwtAccessTokenPublicKey extends JsonWebKey {
  kid: string;
  alg: JwtAccessTokenAlgorithm;
}

/** The active signing key and its public JWK. */
export interface JwtAccessTokenSigningKey {
  /** Stable, unique identifier published as JOSE `kid`. */
  kid: string;
  /** Signing algorithm. `RS256` is required for broad RFC 9068 interoperability. */
  alg: JwtAccessTokenAlgorithm;
  /** Private WebCrypto key used to sign access tokens. Non-extractable keys are recommended. */
  privateKey: CryptoKey;
  /** Matching public JWK. Private key parameters are rejected. */
  publicJwk: JwtAccessTokenPublicKey;
}

/** Key material returned by the authorization server's functional key resolver. */
export interface JwtAccessTokenKeySet {
  /** Key used for new tokens. */
  current: JwtAccessTokenSigningKey;
  /** Additional public keys prepublished for rotation or retained while old tokens remain valid. */
  verificationKeys?: JwtAccessTokenPublicKey[];
}

/** RFC 9068 claims emitted and validated by this package. */
export interface JwtAccessTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nbf?: number;
  jti: string;
  client_id: string;
  scope?: string;
  [JWT_ACCESS_TOKEN_GRANT_ID_CLAIM]: string;
  [JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]?: JwtJsonValue;
}

/** Input to the explicit public-claim projection. */
export interface JwtAccessTokenPublicClaimsInput<Env, Props> {
  readonly props: Props;
  readonly userId: string;
  readonly grantId: string;
  readonly clientId: string;
  readonly scope: readonly string[];
  readonly audience: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly env: Env;
}

/** Input used internally by the authorization server to mint one JWT access token. */
export interface JwtAccessTokenIssueInput<Env, Props> extends JwtAccessTokenPublicClaimsInput<Env, Props> {}

/** Signed token plus its validated claims, returned to the provider's storage layer. */
export interface JwtIssuedAccessToken {
  token: string;
  claims: JwtAccessTokenClaims;
}

/** Configuration for {@link createJwtAccessTokens}. */
export interface JwtAccessTokensOptions<Env = Cloudflare.Env, Props = unknown> {
  /** Exact RFC 8414 authorization-server issuer. */
  issuer: string;
  /** Absolute HTTPS JWKS URL served by the authorization-server fetch surface. */
  jwksUri: string;
  /** Resolve the active signing key plus any staged or retiring public keys from application code. */
  keys(env: Env): JwtAccessTokenKeySet | Promise<JwtAccessTokenKeySet>;
  /**
   * Explicitly project non-secret application data into the client-readable JWT.
   *
   * Signed JWT payloads are not confidential. There is intentionally no default
   * that serializes `props`, because existing deployments commonly keep upstream
   * access and refresh tokens there.
   */
  publicClaims?(
    input: JwtAccessTokenPublicClaimsInput<Env, Props>
  ): JwtJsonValue | undefined | Promise<JwtJsonValue | undefined>;
  /** Maximum compact-token size accepted and emitted. Defaults to 16 KiB. */
  maxTokenBytes?: number;
}

/** Verified JWT context before a resource-specific props mapper runs. */
export interface VerifiedJwtAccessToken {
  claims: JwtAccessTokenClaims;
  audience: string;
  expiresAt: number;
  scope: string[];
  userId: string;
  clientId: string;
  grantId: string;
  jti: string;
  publicClaims: JwtJsonValue | undefined;
}

/** RFC 9068 issuer/verifier created for an {@link OAuthAuthorizationServer}. */
export interface JwtAccessTokens<Env = Cloudflare.Env, Props = unknown> {
  readonly issuer: string;
  readonly jwksUri: string;
  readonly maxTokenBytes: number;
  /** Mint one signed access token from provider-validated grant state. */
  issue: (input: JwtAccessTokenIssueInput<Env, Props>) => Promise<JwtIssuedAccessToken>;
  /** Verify against an explicit finite set of audiences owned by the caller. */
  verify: (token: string, allowedAudiences: readonly string[], env: Env) => Promise<VerifiedJwtAccessToken | null>;
  /** Cheaply identify a structurally valid token that claims this component's issuer and type. */
  recognizes: (token: string) => boolean;
  /** Resolve the sanitized public key set published by the authorization server. */
  getJwks: (env: Env) => Promise<{ keys: JwtAccessTokenPublicKey[] }>;
}

type InternalStateVerifier = (token: string, env: unknown) => Promise<VerifiedJwtAccessToken | null>;
const internalStateVerifiers = new WeakMap<object, InternalStateVerifier>();

/** @internal Verify only for an immediate provider-owned state-record cross-check. */
export function verifyJwtForProviderState<Env>(
  accessTokens: JwtAccessTokens<Env, any>,
  token: string,
  env: Env
): Promise<VerifiedJwtAccessToken | null> {
  const verify = internalStateVerifiers.get(accessTokens);
  if (!verify) throw new TypeError('JWT access-token component was not created by createJwtAccessTokens');
  return verify(token, env);
}

/** @internal Enforce the factory-only invariant at provider construction time. */
export function assertJwtAccessTokensComponent(value: JwtAccessTokens<any, any>): void {
  if (!internalStateVerifiers.has(value)) {
    throw new TypeError('accessTokens must be created by createJwtAccessTokens');
  }
}

/** Input passed to a stateless resource server's claim-to-props mapper. */
export interface JwtClaimsToPropsInput<Env> extends VerifiedJwtAccessToken {
  request: Request;
  env: Env;
}

/** Configuration for {@link createJwtAccessTokenValidator}. */
export interface JwtAccessTokenValidatorOptions<Env = Cloudflare.Env, Props = unknown> {
  /** Exact authorization-server issuer expected in `iss`. */
  issuer: string;
  /** One fixed canonical resource expected in `aud`. */
  audience: string;
  /** Allowed algorithms. Defaults to `['RS256']`. Never derived from the token. */
  algorithms?: JwtAccessTokenAlgorithm[];
  /** Resolve trusted public keys. Token-controlled key URLs are never followed. */
  keys(env: Env): JwtAccessTokenPublicKey[] | Promise<JwtAccessTokenPublicKey[]>;
  /** Map already verified claims to the typed context exposed as `ctx.props`. */
  mapClaimsToProps(input: JwtClaimsToPropsInput<Env>): Props | null | Promise<Props | null>;
  /** Permitted clock skew in seconds. Defaults to 30 seconds. */
  clockSkewSeconds?: number;
  /** Maximum accepted compact-token size. Defaults to 16 KiB. */
  maxTokenBytes?: number;
}

/** Structural input accepted by both combined and standalone resource-server validators. */
export interface JwtAccessTokenValidationInput<Env> {
  token: string;
  request: Request;
  env: Env;
}

/** Structural result accepted by both resource-server validation surfaces. */
export interface JwtAccessTokenValidation<Props> {
  props: Props;
  audience: string;
  expiresAt: number;
}

/**
 * Create an RFC 9068 access-token issuer for `OAuthAuthorizationServer`.
 *
 * New access tokens become signed JWTs. The provider still keeps its encrypted
 * token-context record so built-in validation, confidential `ctx.props`, token
 * exchange, and immediate revocation retain their existing behavior.
 */
export function createJwtAccessTokens<Env = Cloudflare.Env, Props = unknown>(
  options: JwtAccessTokensOptions<Env, Props>
): JwtAccessTokens<Env, Props> {
  const issuer = validateIssuer(options?.issuer);
  const jwksUri = validateAbsoluteHttpsUrl(options?.jwksUri, 'jwksUri');
  const maxTokenBytes = validateMaxTokenBytes(options?.maxTokenBytes);
  if (typeof options?.keys !== 'function') throw new TypeError('keys must be a function');
  if (options.publicClaims !== undefined && typeof options.publicClaims !== 'function') {
    throw new TypeError('publicClaims must be a function');
  }

  const verifyAgainstAudiences = async (
    parsed: ParsedJwt,
    audiences: readonly string[],
    env: Env
  ): Promise<VerifiedJwtAccessToken | null> => {
    if (!preflightParsedJwt(parsed, issuer, audiences, ['RS256', 'ES256'], true, 30)) return null;
    const keySet = validateKeySet(await options.keys(env));
    return verifyParsedJwt(parsed, {
      issuer,
      allowedAlgorithms: [
        keySet.current.alg,
        ...keySet.verificationKeys.map((key) => key.alg as JwtAccessTokenAlgorithm),
      ],
      publicKeys: keySet.publicKeys,
      allowedAudiences: audiences,
      requireSingleAudience: true,
      clockSkewSeconds: 30,
    });
  };

  const accessTokens: JwtAccessTokens<Env, Props> = {
    issuer,
    jwksUri,
    maxTokenBytes,

    async issue(input): Promise<JwtIssuedAccessToken> {
      const snapshot = snapshotIssueInput(input);
      const keySet = validateKeySet(await options.keys(snapshot.env));
      const projectedClaims = options.publicClaims ? await options.publicClaims(snapshot) : undefined;
      const publicClaims =
        projectedClaims === undefined
          ? undefined
          : cloneJsonValue(projectedClaims, 'publicClaims return value', maxTokenBytes);

      const claims: JwtAccessTokenClaims = {
        iss: issuer,
        sub: snapshot.userId,
        aud: snapshot.audience,
        exp: snapshot.expiresAt,
        iat: snapshot.issuedAt,
        jti: randomId(),
        client_id: snapshot.clientId,
        ...(snapshot.scope.length ? { scope: snapshot.scope.join(' ') } : {}),
        [JWT_ACCESS_TOKEN_GRANT_ID_CLAIM]: snapshot.grantId,
        ...(publicClaims === undefined ? {} : { [JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]: publicClaims }),
      };
      const header = { typ: JWT_TYPE, alg: keySet.current.alg, kid: keySet.current.kid };
      const encodedHeader = encodeJson(header);
      const encodedClaims = encodeJson(claims);
      const signingInputText = `${encodedHeader}.${encodedClaims}`;
      const signingInput = new TextEncoder().encode(signingInputText);
      const projectedTokenBytes =
        signingInput.byteLength + 1 + encodedBase64UrlLength(expectedSignatureBytes(keySet.current));
      if (projectedTokenBytes > maxTokenBytes) {
        throw new TypeError(`JWT access token exceeds the configured ${maxTokenBytes}-byte limit`);
      }
      const signature = await crypto.subtle.sign(
        getSigningAlgorithm(keySet.current.alg),
        keySet.current.privateKey,
        signingInput
      );
      if (
        !(await verifySignature(keySet.current.publicJwk, keySet.current.alg, new Uint8Array(signature), signingInput))
      ) {
        throw new TypeError('current JWT signing key privateKey does not match publicJwk');
      }
      const token = `${signingInputText}.${encodeBytes(new Uint8Array(signature))}`;
      if (new TextEncoder().encode(token).byteLength > maxTokenBytes) {
        throw new TypeError(`JWT access token exceeds the configured ${maxTokenBytes}-byte limit`);
      }
      return { token, claims };
    },

    async verify(token, allowedAudiences, env): Promise<VerifiedJwtAccessToken | null> {
      if (!Array.isArray(allowedAudiences) || allowedAudiences.length === 0) {
        throw new TypeError('allowedAudiences must contain at least one canonical resource URI');
      }
      const audiences = [...new Set(allowedAudiences.map(validateCanonicalResource))];
      const parsed = parseCompactJwt(token, maxTokenBytes);
      if (!parsed || !isAcceptedJwtType(parsed.header.typ)) return null;
      if (parsed.claims.iss !== issuer) return null;
      return verifyAgainstAudiences(parsed, audiences, env);
    },

    recognizes(token): boolean {
      const parsed = parseCompactJwt(token, maxTokenBytes);
      return !!parsed && isAcceptedJwtType(parsed.header.typ) && parsed.claims.iss === issuer;
    },

    async getJwks(env): Promise<{ keys: JwtAccessTokenPublicKey[] }> {
      const keySet = validateKeySet(await options.keys(env));
      await assertSigningKeyPair(keySet.current);
      return { keys: keySet.publicKeys.map(cloneJwk) };
    },
  };

  internalStateVerifiers.set(accessTokens, async (token, env) => {
    const parsed = parseCompactJwt(token, maxTokenBytes);
    if (!parsed || !isAcceptedJwtType(parsed.header.typ) || parsed.claims.iss !== issuer) return null;
    const audience = readCanonicalSingleAudience(parsed.claims.aud);
    if (!audience) return null;
    return verifyAgainstAudiences(parsed, [audience], env as Env);
  });
  return accessTokens;
}

/**
 * Create a fixed-issuer, fixed-audience validator for the JWT profile emitted
 * by {@link createJwtAccessTokens}. It is not a generic RFC 9068 verifier.
 * The result is suitable for `createOAuthResourceServer({ validateToken })`
 * or `resolveExternalToken`.
 *
 * This path validates offline and therefore cannot observe token-record or
 * grant revocation unless `keys` or `mapClaimsToProps` performs an application
 * status check. Keep access-token lifetimes short when using it without state.
 */
export function createJwtAccessTokenValidator<Env = Cloudflare.Env, Props = unknown>(
  options: JwtAccessTokenValidatorOptions<Env, Props>
): (input: JwtAccessTokenValidationInput<Env>) => Promise<JwtAccessTokenValidation<Props> | null> {
  const issuer = validateIssuer(options?.issuer);
  const audience = validateCanonicalResource(options?.audience);
  const algorithms = validateAlgorithms(options?.algorithms ?? ['RS256']);
  const clockSkewSeconds = validateClockSkew(options?.clockSkewSeconds);
  const maxTokenBytes = validateMaxTokenBytes(options?.maxTokenBytes);
  if (typeof options?.keys !== 'function') throw new TypeError('keys must be a function');
  if (typeof options?.mapClaimsToProps !== 'function') throw new TypeError('mapClaimsToProps must be a function');

  return async ({ token, request, env }) => {
    const parsed = parseCompactJwt(token, maxTokenBytes);
    if (!parsed) return null;
    if (!preflightParsedJwt(parsed, issuer, [audience], algorithms, false, clockSkewSeconds)) return null;
    const publicKeys = validatePublicKeys(await options.keys(env), algorithms);
    const verified = await verifyParsedJwt(parsed, {
      issuer,
      allowedAudiences: [audience],
      allowedAlgorithms: algorithms,
      publicKeys,
      requireSingleAudience: false,
      clockSkewSeconds,
    });
    if (!verified) return null;
    const props = await options.mapClaimsToProps({ ...verified, request, env });
    if (props == null) return null;
    return { props, audience, expiresAt: verified.expiresAt };
  };
}

interface ParsedJwt {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
}

interface VerifyParsedOptions {
  issuer: string;
  allowedAudiences: readonly string[];
  allowedAlgorithms: JwtAccessTokenAlgorithm[];
  publicKeys: JwtAccessTokenPublicKey[];
  requireSingleAudience: boolean;
  clockSkewSeconds: number;
}

async function verifyParsedJwt(
  parsed: ParsedJwt,
  options: VerifyParsedOptions
): Promise<VerifiedJwtAccessToken | null> {
  const { header, claims } = parsed;
  if (
    !preflightParsedJwt(
      parsed,
      options.issuer,
      options.allowedAudiences,
      options.allowedAlgorithms,
      options.requireSingleAudience,
      options.clockSkewSeconds
    )
  ) {
    return null;
  }

  const alg = header.alg as JwtAccessTokenAlgorithm;
  const kid = header.kid;
  if (typeof kid !== 'string') return null;
  const matchingKeys = options.publicKeys.filter((key) => key.kid === kid && key.alg === alg);
  if (matchingKeys.length !== 1) return null;

  let verified = false;
  try {
    verified = await verifySignature(matchingKeys[0], alg, parsed.signature, parsed.signingInput);
  } catch (error) {
    throw new TypeError(`Unable to use configured JWT verification key: ${errorMessage(error)}`);
  }
  if (!verified) return null;

  // Repeat every semantic check after cryptographic verification. This keeps
  // untrusted preflight checks strictly an optimization rather than an authority.
  if (
    !preflightParsedJwt(
      parsed,
      options.issuer,
      options.allowedAudiences,
      options.allowedAlgorithms,
      options.requireSingleAudience,
      options.clockSkewSeconds
    )
  ) {
    return null;
  }
  const audience = selectAudience(claims.aud, options.allowedAudiences, options.requireSingleAudience);
  const scope = parseScopeClaim(claims.scope);
  const grantId = claims[JWT_ACCESS_TOKEN_GRANT_ID_CLAIM] as string;
  if (!audience || !scope || typeof claims.exp !== 'number') return null;
  const publicClaims = claims[JWT_ACCESS_TOKEN_PUBLIC_CLAIMS];

  return {
    claims: claims as unknown as JwtAccessTokenClaims,
    audience,
    expiresAt: claims.exp,
    scope,
    userId: claims.sub as string,
    clientId: claims.client_id as string,
    grantId,
    jti: claims.jti as string,
    publicClaims: publicClaims as JwtJsonValue | undefined,
  };
}

function preflightParsedJwt(
  parsed: ParsedJwt,
  issuer: string,
  allowedAudiences: readonly string[],
  allowedAlgorithms: readonly JwtAccessTokenAlgorithm[],
  requireSingleAudience: boolean,
  clockSkewSeconds: number
): boolean {
  const { header, claims } = parsed;
  if (!isAcceptedJwtType(header.typ)) return false;
  if (FORBIDDEN_JOSE_HEADERS.some((name) => name in header) || 'crit' in header) return false;
  if (!isSupportedAlgorithm(header.alg) || !allowedAlgorithms.includes(header.alg)) return false;
  if (!isNonEmptyString(header.kid) || header.kid.length > MAX_KEY_ID_LENGTH) return false;
  if (claims.iss !== issuer || !selectAudience(claims.aud, allowedAudiences, requireSingleAudience)) return false;
  if (!isNonEmptyString(claims.sub) || !isNonEmptyString(claims.client_id) || !isNonEmptyString(claims.jti)) {
    return false;
  }
  if (!isNonEmptyString(claims[JWT_ACCESS_TOKEN_GRANT_ID_CLAIM])) return false;
  if (!isNumericDate(claims.exp) || !isNumericDate(claims.iat) || claims.iat >= claims.exp) return false;
  const now = Math.floor(Date.now() / 1000);
  if (claims.exp <= now - clockSkewSeconds || claims.iat > now + clockSkewSeconds) return false;
  if (claims.nbf !== undefined && (!isNumericDate(claims.nbf) || claims.nbf > now + clockSkewSeconds)) return false;
  if (!parseScopeClaim(claims.scope)) return false;
  const publicClaims = claims[JWT_ACCESS_TOKEN_PUBLIC_CLAIMS];
  return publicClaims === undefined || isJsonValue(publicClaims);
}

function selectAudience(
  value: unknown,
  allowedAudiences: readonly string[],
  requireSingleAudience: boolean
): string | null {
  const claimAudiences =
    typeof value === 'string'
      ? [value]
      : Array.isArray(value) && value.length > 0 && value.every(isNonEmptyString)
        ? value
        : null;
  if (!claimAudiences || new Set(claimAudiences).size !== claimAudiences.length) return null;
  if (requireSingleAudience && (typeof value !== 'string' || claimAudiences.length !== 1)) return null;
  const matchingAudiences = allowedAudiences.filter((audience) => claimAudiences.includes(audience));
  return matchingAudiences.length === 1 ? matchingAudiences[0] : null;
}

function parseScopeClaim(value: unknown): string[] | null {
  if (value === undefined) return [];
  if (typeof value !== 'string' || !value) return null;
  const scopes = value.split(' ');
  if (scopes.some((scope) => !isValidOAuthScopeToken(scope))) return null;
  return scopes;
}

function parseCompactJwt(token: string, maxTokenBytes: number): ParsedJwt | null {
  if (typeof token !== 'string' || !token || new TextEncoder().encode(token).byteLength > maxTokenBytes) return null;
  const segments = token.split('.');
  if (segments.length !== 3 || segments.some((segment) => !segment)) return null;
  try {
    const header = decodeJsonObject(segments[0]);
    const claims = decodeJsonObject(segments[1]);
    const signature = decodeBytes(segments[2]);
    if (!signature.length) return null;
    return {
      header,
      claims,
      signingInput: new TextEncoder().encode(`${segments[0]}.${segments[1]}`),
      signature,
    };
  } catch {
    return null;
  }
}

interface ValidatedKeySet {
  current: JwtAccessTokenSigningKey;
  verificationKeys: JwtAccessTokenPublicKey[];
  publicKeys: JwtAccessTokenPublicKey[];
}

function validateKeySet(value: JwtAccessTokenKeySet): ValidatedKeySet {
  if (!value || typeof value !== 'object' || !value.current) {
    throw new TypeError('keys must return a current JWT signing key');
  }
  const { current } = value;
  if (!isNonEmptyString(current.kid) || current.kid.length > MAX_KEY_ID_LENGTH) {
    throw new TypeError(`current JWT signing key kid must contain 1-${MAX_KEY_ID_LENGTH} characters`);
  }
  if (!isSupportedAlgorithm(current.alg)) throw new TypeError('current JWT signing key alg must be RS256 or ES256');
  if (!isCryptoKey(current.privateKey) || current.privateKey.type !== 'private') {
    throw new TypeError('current JWT signing key privateKey must be a private CryptoKey');
  }
  if (!current.privateKey.usages.includes('sign')) {
    throw new TypeError('current JWT signing key privateKey must allow sign');
  }
  validatePrivateKeyAlgorithm(current.privateKey, current.alg);
  const currentPublicJwk = validatePublicJwk(current.publicJwk, current.alg, current.kid);
  const verificationKeys = value.verificationKeys ?? [];
  if (!Array.isArray(verificationKeys)) {
    throw new TypeError('JWT verificationKeys must be an array');
  }
  const additionalPublicKeys = verificationKeys.map((key) => validatePublicJwk(key));
  const publicKeys = [currentPublicJwk, ...additionalPublicKeys];
  assertUniqueKeyIds(publicKeys);
  return {
    current: { ...current, publicJwk: currentPublicJwk },
    verificationKeys: additionalPublicKeys,
    publicKeys,
  };
}

function validatePublicKeys(
  value: JwtAccessTokenPublicKey[],
  algorithms: JwtAccessTokenAlgorithm[]
): JwtAccessTokenPublicKey[] {
  if (!Array.isArray(value) || value.length === 0) throw new TypeError('keys must return at least one public JWK');
  const keys = value.map((key) => validatePublicJwk(key));
  assertUniqueKeyIds(keys);
  if (!keys.some((key) => algorithms.includes(key.alg as JwtAccessTokenAlgorithm))) {
    throw new TypeError('keys did not return a public JWK for an allowed algorithm');
  }
  return keys;
}

function validatePublicJwk(
  value: JwtAccessTokenPublicKey,
  expectedAlgorithm?: JwtAccessTokenAlgorithm,
  expectedKeyId?: string
): JwtAccessTokenPublicKey {
  if (!value || typeof value !== 'object') throw new TypeError('JWT public key must be a JWK object');
  const key = cloneJwk(value);
  if (containsPrivateJwkMaterial(key)) throw new TypeError('JWT public JWK must not contain private key material');
  if (!isNonEmptyString(key.kid) || key.kid.length > MAX_KEY_ID_LENGTH) {
    throw new TypeError(`JWT public JWK kid must contain 1-${MAX_KEY_ID_LENGTH} characters`);
  }
  if (!isSupportedAlgorithm(key.alg)) throw new TypeError('JWT public JWK alg must be RS256 or ES256');
  if (expectedAlgorithm && key.alg !== expectedAlgorithm)
    throw new TypeError('JWT public JWK alg must match signing key');
  if (expectedKeyId && key.kid !== expectedKeyId) throw new TypeError('JWT public JWK kid must match signing key');
  if (key.use !== undefined && key.use !== 'sig') throw new TypeError("JWT public JWK use must be 'sig'");
  if (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || !key.key_ops.includes('verify'))) {
    throw new TypeError("JWT public JWK key_ops must include 'verify'");
  }
  if (key.alg === 'RS256' && key.kty !== 'RSA') throw new TypeError('RS256 JWT public JWK must use kty RSA');
  if (key.alg === 'RS256' && (!isNonEmptyString(key.n) || rsaModulusBits(key.n) < 2048 || !isNonEmptyString(key.e))) {
    throw new TypeError('RS256 JWT public JWK must contain an RSA modulus of at least 2048 bits and an exponent');
  }
  if (key.alg === 'ES256' && (key.kty !== 'EC' || key.crv !== 'P-256')) {
    throw new TypeError('ES256 JWT public JWK must use kty EC and crv P-256');
  }
  if (key.alg === 'ES256' && (!isNonEmptyString(key.x) || !isNonEmptyString(key.y))) {
    throw new TypeError('ES256 JWT public JWK must contain x and y coordinates');
  }
  // RFC 7517 advises against publishing both `use` and `key_ops`. `use: sig`
  // is the broadly interoperable constraint for an authorization-server JWKS.
  const { key_ops: _keyOperations, ...publicJwk } = key;
  return { ...publicJwk, use: 'sig' } as JwtAccessTokenPublicKey;
}

function assertUniqueKeyIds(keys: JwtAccessTokenPublicKey[]): void {
  const seen = new Set<string>();
  for (const key of keys) {
    if (seen.has(key.kid!)) throw new TypeError(`JWT public keys must use unique kid values: ${key.kid}`);
    seen.add(key.kid!);
  }
}

function containsPrivateJwkMaterial(key: JwtAccessTokenPublicKey): boolean {
  return ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((name) => name in key);
}

function snapshotIssueInput<Env, Props>(
  input: JwtAccessTokenIssueInput<Env, Props>
): JwtAccessTokenIssueInput<Env, Props> {
  if (!isNonEmptyString(input.userId)) throw new TypeError('JWT access token userId is required');
  if (!isNonEmptyString(input.grantId)) throw new TypeError('JWT access token grantId is required');
  if (!isNonEmptyString(input.clientId)) throw new TypeError('JWT access token clientId is required');
  validateCanonicalResource(input.audience);
  if (!Array.isArray(input.scope) || input.scope.some((scope) => !isValidOAuthScopeToken(scope))) {
    throw new TypeError('JWT access token scope must contain valid OAuth scope tokens');
  }
  if (!isNumericDate(input.issuedAt) || !isNumericDate(input.expiresAt) || input.issuedAt >= input.expiresAt) {
    throw new TypeError('JWT access token issuedAt and expiresAt must be valid increasing NumericDate values');
  }
  return Object.freeze({
    props: input.props,
    userId: input.userId,
    grantId: input.grantId,
    clientId: input.clientId,
    scope: Object.freeze([...input.scope]),
    audience: input.audience,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    env: input.env,
  });
}

function validateIssuer(value: unknown): string {
  const issuer = validateAbsoluteHttpsUrl(value, 'issuer');
  const parsed = new URL(issuer);
  if (parsed.search || parsed.hash) throw new TypeError('issuer must not contain a query or fragment');
  return issuer;
}

function validateCanonicalResource(value: unknown): string {
  if (typeof value !== 'string' || !isCanonicalHttpsUrl(value)) {
    throw new TypeError('audience must be a canonical absolute HTTPS resource URI');
  }
  return value;
}

function readCanonicalSingleAudience(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  try {
    return validateCanonicalResource(value);
  } catch {
    return null;
  }
}

function validateAbsoluteHttpsUrl(value: unknown, name: string): string {
  if (typeof value !== 'string' || !isCanonicalHttpsUrl(value)) {
    throw new TypeError(`${name} must be an absolute HTTPS URL`);
  }
  const parsed = new URL(value);
  if (parsed.hash) {
    throw new TypeError(`${name} must be an absolute HTTPS URL without userinfo or a fragment`);
  }
  return value;
}

function isCanonicalHttpsUrl(value: string): boolean {
  if (!validateResourceUri(value)) return false;
  const parsed = new URL(value);
  return (
    parsed.protocol === 'https:' &&
    !parsed.username &&
    !parsed.password &&
    parsed.protocol === parsed.protocol.toLowerCase() &&
    parsed.hostname === parsed.hostname.toLowerCase() &&
    (parsed.href === value || parsed.origin === value)
  );
}

function validateAlgorithms(value: JwtAccessTokenAlgorithm[]): JwtAccessTokenAlgorithm[] {
  if (!Array.isArray(value) || value.length === 0 || value.some((alg) => !isSupportedAlgorithm(alg))) {
    throw new TypeError('algorithms must contain RS256 and/or ES256');
  }
  return [...new Set(value)];
}

function validateClockSkew(value: number | undefined): number {
  const skew = value ?? 30;
  if (!Number.isInteger(skew) || skew < 0 || skew > 300) {
    throw new TypeError('clockSkewSeconds must be an integer between 0 and 300');
  }
  return skew;
}

function validateMaxTokenBytes(value: number | undefined): number {
  const limit = value ?? DEFAULT_MAX_TOKEN_BYTES;
  if (!Number.isInteger(limit) || limit < 1024 || limit > MAX_CONFIGURED_TOKEN_BYTES) {
    throw new TypeError(`maxTokenBytes must be an integer between 1024 and ${MAX_CONFIGURED_TOKEN_BYTES}`);
  }
  return limit;
}

function isSupportedAlgorithm(value: unknown): value is JwtAccessTokenAlgorithm {
  return value === 'RS256' || value === 'ES256';
}

function isAcceptedJwtType(value: unknown): boolean {
  return typeof value === 'string' && ACCEPTED_JWT_TYPES.has(value.toLowerCase());
}

function getImportAlgorithm(algorithm: JwtAccessTokenAlgorithm): Parameters<SubtleCrypto['importKey']>[2] {
  return algorithm === 'RS256'
    ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    : { name: 'ECDSA', namedCurve: 'P-256' };
}

function getSigningAlgorithm(algorithm: JwtAccessTokenAlgorithm): Parameters<SubtleCrypto['sign']>[0] {
  return algorithm === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };
}

function expectedSignatureBytes(key: JwtAccessTokenSigningKey): number {
  if (key.alg === 'ES256') return 64;
  return Math.ceil(((key.privateKey.algorithm as { modulusLength?: number }).modulusLength ?? 0) / 8);
}

function encodedBase64UrlLength(byteLength: number): number {
  return Math.ceil((byteLength * 4) / 3);
}

async function verifySignature(
  publicJwk: JwtAccessTokenPublicKey,
  algorithm: JwtAccessTokenAlgorithm,
  signature: Uint8Array,
  signingInput: Uint8Array
): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey('jwk', publicJwk, getImportAlgorithm(algorithm), false, ['verify']);
  return crypto.subtle.verify(getSigningAlgorithm(algorithm), publicKey, signature, signingInput);
}

async function assertSigningKeyPair(key: JwtAccessTokenSigningKey): Promise<void> {
  const fingerprint = JSON.stringify(key.publicJwk);
  let validations = verifiedSigningKeyPairs.get(key.privateKey);
  if (!validations) {
    validations = new Map<string, Promise<void>>();
    verifiedSigningKeyPairs.set(key.privateKey, validations);
  }
  let validation = validations.get(fingerprint);
  if (!validation) {
    validation = proveSigningKeyPair(key);
    validations.set(fingerprint, validation);
  }
  try {
    await validation;
  } catch (error) {
    if (validations.get(fingerprint) === validation) validations.delete(fingerprint);
    throw error;
  }
}

async function proveSigningKeyPair(key: JwtAccessTokenSigningKey): Promise<void> {
  const probe = new TextEncoder().encode('workers-oauth-provider jwt key-pair check');
  let signature: ArrayBuffer;
  try {
    signature = await crypto.subtle.sign(getSigningAlgorithm(key.alg), key.privateKey, probe);
  } catch (error) {
    throw new TypeError(`Unable to use current JWT signing key: ${errorMessage(error)}`);
  }
  if (!(await verifySignature(key.publicJwk, key.alg, new Uint8Array(signature), probe))) {
    throw new TypeError('current JWT signing key privateKey does not match publicJwk');
  }
}

function isCryptoKey(value: unknown): value is CryptoKey {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<CryptoKey>;
  return (
    (candidate.type === 'private' || candidate.type === 'public' || candidate.type === 'secret') &&
    Array.isArray(candidate.usages) &&
    !!candidate.algorithm &&
    typeof candidate.algorithm === 'object'
  );
}

function validatePrivateKeyAlgorithm(key: CryptoKey, algorithm: JwtAccessTokenAlgorithm): void {
  const details = key.algorithm as {
    name: string;
    hash?: { name: string };
    modulusLength?: number;
    namedCurve?: string;
  };
  if (
    algorithm === 'RS256' &&
    (details.name !== 'RSASSA-PKCS1-v1_5' || details.hash?.name !== 'SHA-256' || (details.modulusLength ?? 0) < 2048)
  ) {
    throw new TypeError('RS256 privateKey must be an RSA PKCS#1 SHA-256 key of at least 2048 bits');
  }
  if (algorithm === 'ES256' && (details.name !== 'ECDSA' || details.namedCurve !== 'P-256')) {
    throw new TypeError('ES256 privateKey must be an ECDSA P-256 key');
  }
}

function rsaModulusBits(encodedModulus: string): number {
  let modulus: Uint8Array;
  try {
    modulus = decodeBytes(encodedModulus);
  } catch {
    return 0;
  }
  let firstNonZero = 0;
  while (firstNonZero < modulus.length && modulus[firstNonZero] === 0) firstNonZero++;
  if (firstNonZero === modulus.length) return 0;
  const firstByteBits = 32 - Math.clz32(modulus[firstNonZero]);
  return (modulus.length - firstNonZero - 1) * 8 + firstByteBits;
}

function isNumericDate(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

interface JsonTraversalState {
  ancestors: Set<object>;
  nodes: number;
}

interface JsonCloneState extends JsonTraversalState {
  remainingTextBytes: number;
}

function isJsonValue(value: unknown): value is JwtJsonValue {
  return checkJsonValue(value, { ancestors: new Set<object>(), nodes: 0 }, 0);
}

function checkJsonValue(value: unknown, state: JsonTraversalState, depth: number): value is JwtJsonValue {
  if (depth > MAX_PUBLIC_CLAIM_DEPTH || ++state.nodes > MAX_PUBLIC_CLAIM_NODES) return false;
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'object') return false;
  if (state.ancestors.has(value)) return false;
  state.ancestors.add(value);
  if (Array.isArray(value)) {
    const valid = value.every((item) => checkJsonValue(item, state, depth + 1));
    state.ancestors.delete(value);
    return valid;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) return false;
  const valid = Object.values(value as Record<string, unknown>).every((item) => checkJsonValue(item, state, depth + 1));
  state.ancestors.delete(value);
  return valid;
}

function cloneJsonValue(value: unknown, source: string, maxTextBytes: number): JwtJsonValue {
  return cloneJsonValueAt(
    value,
    source,
    { ancestors: new Set<object>(), nodes: 0, remainingTextBytes: maxTextBytes },
    0
  );
}

function cloneJsonValueAt(value: unknown, source: string, state: JsonCloneState, depth: number): JwtJsonValue {
  if (depth > MAX_PUBLIC_CLAIM_DEPTH || ++state.nodes > MAX_PUBLIC_CLAIM_NODES) {
    throw new TypeError(`${source} exceeds the maximum JSON depth or node count`);
  }
  if (typeof value === 'string') {
    consumeCloneTextBudget(state, value, source);
    return value;
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object') throw new TypeError(`${source} must be a finite JSON value or undefined`);
  if (state.ancestors.has(value)) throw new TypeError(`${source} must be a finite JSON value or undefined`);
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) return value.map((item) => cloneJsonValueAt(item, source, state, depth + 1));
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
      throw new TypeError(`${source} must be a finite JSON value or undefined`);
    }
    // A null prototype makes JSON keys such as "__proto__" ordinary own data
    // instead of invoking Object.prototype's legacy setter during the clone.
    const result = Object.create(null) as Record<string, JwtJsonValue>;
    for (const key of Object.keys(value)) {
      consumeCloneTextBudget(state, key, source);
      result[key] = cloneJsonValueAt((value as Record<string, unknown>)[key], source, state, depth + 1);
    }
    return result;
  } finally {
    state.ancestors.delete(value);
  }
}

function consumeCloneTextBudget(state: JsonCloneState, value: string, source: string): void {
  state.remainingTextBytes -= new TextEncoder().encode(value).byteLength;
  if (state.remainingTextBytes < 0) {
    throw new TypeError(`${source} exceeds the configured JWT token-size budget`);
  }
}

function randomId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return encodeBytes(bytes);
}

function encodeJson(value: object): string {
  return encodeBytes(new TextEncoder().encode(JSON.stringify(value)));
}

function decodeJsonObject(value: string): Record<string, unknown> {
  const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(decodeBytes(value)));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('JWT part must be an object');
  return parsed;
}

function encodeBytes(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid base64url');
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBytes(bytes) !== value) throw new Error('Non-canonical base64url');
  return bytes;
}

function cloneJwk(value: JwtAccessTokenPublicKey): JwtAccessTokenPublicKey {
  return JSON.parse(JSON.stringify(value)) as JwtAccessTokenPublicKey;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
