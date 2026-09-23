import { hasAcceptedCanonicalScheme, validateResourceUri } from './oauth-resource';
import { isValidOAuthScopeToken } from './oauth-capabilities';

/** Collision-resistant private claim carrying the provider's grant identifier. */
export const JWT_ACCESS_TOKEN_GRANT_ID_CLAIM = 'https://workers.cloudflare.com/oauth-provider/claims/grant-id' as const;

/**
 * Collision-resistant private claim containing only application data that the
 * deployer explicitly chose to make readable to the access-token holder.
 */
export const JWT_ACCESS_TOKEN_PUBLIC_CLAIMS = 'https://workers.cloudflare.com/oauth-provider/claims/public' as const;

/** Compact-token size ceiling, applied to every token this module emits and reads. */
const MAX_TOKEN_BYTES = 16 * 1024;
const MAX_KEY_ID_LENGTH = 128;
/** Permitted clock skew, shared by the issuer's own verifier and the offline validator. */
const DEFAULT_CLOCK_SKEW_SECONDS = 30;
const SUPPORTED_ALGORITHMS: readonly JwtAlgorithm[] = ['RS256', 'ES256'];
const DEFAULT_JWKS_CACHE_TTL_SECONDS = 5 * 60;
/** One forced refresh per window, because `kid` is unauthenticated attacker-chosen input. */
const JWKS_REFRESH_COOLDOWN_SECONDS = 30;
const JWKS_FETCH_TIMEOUT_MS = 10_000;
const MAX_JWKS_BYTES = 64 * 1024;
const MAX_PUBLIC_CLAIM_DEPTH = 64;
const MAX_PUBLIC_CLAIM_NODES = 10_000;
const verifiedSigningKeyPairs = new WeakMap<CryptoKey, Map<string, Promise<void>>>();

const JWT_TYPE = 'at+jwt';
const ACCEPTED_JWT_TYPES = new Set([JWT_TYPE, 'application/at+jwt']);
const FORBIDDEN_JOSE_HEADERS = ['jku', 'jwk', 'x5u', 'x5c', 'b64'] as const;

/** JSON value accepted in the explicitly public application claim. */
export type JwtJsonValue = null | boolean | number | string | JwtJsonValue[] | { [key: string]: JwtJsonValue };

/** Asymmetric algorithms supported by the RFC 9068 helper. */
export type JwtAlgorithm = 'RS256' | 'ES256';

/** Public verification key with the JOSE fields required for safe selection. */
export interface JwtPublicKey extends JsonWebKey {
  kid: string;
  alg: JwtAlgorithm;
}

/** The active signing key and its public JWK. */
export interface JwtSigningKey {
  /** Stable, unique identifier published as JOSE `kid`. */
  kid: string;
  /** Signing algorithm. `RS256` is required for broad RFC 9068 interoperability. */
  alg: JwtAlgorithm;
  /** Private WebCrypto key used to sign access tokens. Non-extractable keys are recommended. */
  privateKey: CryptoKey;
  /** Matching public JWK. Private key parameters are rejected. */
  publicJwk: JwtPublicKey;
}

/** Key material returned by the authorization server's functional key resolver. */
export interface JwtKeySet {
  /** Key used to sign new tokens. */
  signingKey: JwtSigningKey;
  /** Additional public keys prepublished for rotation or retained while old tokens remain valid. */
  verificationKeys?: JwtPublicKey[];
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

/** What the authorization server knows about a token as it decides whether to issue a JWT. */
export interface JwtIssuanceInput<Env> {
  readonly env: Env;
  /** The canonical resource the token is bound to. */
  readonly resource: string;
}

/** Input to the explicit public-claim projection, and to issuance itself. */
export interface JwtPublicClaimsInput<Env, Props> {
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

/** Signed token plus its validated claims, returned to the provider's storage layer. */
interface IssuedJwtAccessToken {
  token: string;
  claims: JwtAccessTokenClaims;
}

/** Configuration for {@link createJwtAccessTokens}. */
export interface JwtAccessTokensOptions<Env = Cloudflare.Env, Props = unknown> {
  /** Exact RFC 8414 authorization-server issuer. */
  issuer: string;
  /** Absolute HTTPS JWKS URL served by the authorization-server fetch surface (http only on a loopback host). */
  jwksUri: string;
  /** Resolve the active signing key plus any staged or retiring public keys from application code. */
  keys(env: Env): JwtKeySet | Promise<JwtKeySet>;
  /**
   * Explicitly project non-secret application data into the client-readable JWT.
   *
   * Signed JWT payloads are not confidential. There is intentionally no default
   * that serializes `props`, because existing deployments commonly keep upstream
   * access and refresh tokens there.
   */
  publicClaims?(input: JwtPublicClaimsInput<Env, Props>): JwtJsonValue | undefined | Promise<JwtJsonValue | undefined>;
  /**
   * Whether a newly issued access token is a JWT. Omit it, or return `false`, and the
   * reader, signer and JWKS are installed while issuance stays opaque, which is the
   * reader-first order a rollout needs: every resource server must be able to verify a
   * JWT before the first one is written. A function decides per token, so issuance can
   * be switched on per resource or per environment. Authorization codes and refresh
   * tokens are opaque regardless.
   */
  issuance?: boolean | ((input: JwtIssuanceInput<Env>) => boolean | Promise<boolean>);
}

/** Verified JWT context before a resource-specific props mapper runs. */
interface VerifiedJwtAccessToken {
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

/**
 * The RFC 9068 issuer, reader and JWKS publisher an {@link OAuthAuthorizationServer} is
 * given as `jwtAccessTokens`. Opaque to application code: the server mints, verifies and
 * publishes through it, and nothing else should. A token minted outside the token endpoint
 * has no grant behind it, and a verification outside the server skips the revocation
 * check its own resources get.
 */
export interface JwtAccessTokens<Env = Cloudflare.Env, Props = unknown> {
  readonly issuer: string;
  readonly jwksUri: string;
  /** @internal Binds the `Props` type parameter; never set. */
  readonly __props?: Props;
}

/** Capabilities the provider needs from a component and no npm consumer may reach. */
interface JwtInternals<Env, Props> {
  /** Whether the token about to be issued for `input.resource` should be a JWT. */
  readonly shouldIssue: (input: JwtIssuanceInput<Env>) => Promise<boolean>;
  /** Mint one signed access token from provider-validated grant state. */
  readonly issue: (input: JwtPublicClaimsInput<Env, Props>) => Promise<IssuedJwtAccessToken>;
  /** Verify against an explicit finite set of audiences owned by the caller. */
  readonly verifyForAudiences: (
    token: string,
    allowedAudiences: readonly string[],
    env: Env
  ) => Promise<VerifiedJwtAccessToken | null>;
  /** Verify against the token's own audience for a provider-owned state cross-check. */
  readonly verify: (token: string, env: Env) => Promise<VerifiedJwtAccessToken | null>;
  /** Cheaply identify a structurally valid token that claims this component's issuer and type. */
  readonly isOwnJwt: (token: string) => boolean;
  /** The sanitized public key set the authorization server publishes. */
  readonly getJwks: (env: Env) => Promise<{ keys: JwtPublicKey[] }>;
}
/**
 * Brands the objects this factory returns. A WeakMap rather than a property so that a
 * spread copy of the component is not branded, which is what makes the factory-only
 * invariant detectable rather than merely documented.
 */
const internals = new WeakMap<object, JwtInternals<any, any>>();
const NOT_FROM_FACTORY = 'jwtAccessTokens must be created by createJwtAccessTokens';

/**
 * @internal The provider's only door into a branded component. Called for its throw at
 * construction time, and for the hooks on every request that carries a token.
 */
export function jwtInternals<Env, Props>(accessTokens: JwtAccessTokens<Env, Props>): JwtInternals<Env, Props> {
  const hooks = internals.get(accessTokens);
  if (!hooks) throw new TypeError(NOT_FROM_FACTORY);
  return hooks;
}

/** Verified claims handed to a resource server's `mapClaimsToProps`. */
export interface JwtClaimsToPropsInput<Env> {
  claims: JwtAccessTokenClaims;
  audience: string;
  expiresAt: number;
  scope: string[];
  userId: string;
  clientId: string;
  grantId: string;
  jti: string;
  publicClaims: JwtJsonValue | undefined;
  request: Request;
  env: Env;
}

/** The verification key a token names, passed to a validator's `keys` resolver. */
export interface JwtKeyHint {
  /** `kid` from the token header. Always present: a token without one is rejected first. */
  readonly kid: string;
  /** Algorithm from the token header, already restricted to the allowed list. */
  readonly alg: JwtAlgorithm;
}

/**
 * Where a resource server gets the authorization server's public keys: its `jwks_uri`,
 * fetched and cached by this package, optionally over a Service Binding to keep the
 * request off the public internet. Only the key set travels over that binding; the token
 * being verified never leaves the resource server.
 */
export interface JwksSource<Env = Cloudflare.Env> {
  /** The authorization server's exact `jwks_uri`. The only URL ever fetched. */
  jwksUri: string;
  /** Where to send the JWKS request. Defaults to global `fetch`. */
  fetcher?: (env: Env) => { fetch(request: Request): Promise<Response> } | undefined;
  /**
   * How long a fetched key set is reused, in seconds. The response's `Cache-Control`
   * can only shorten this. Defaults to 300 seconds, which is what this package's own
   * authorization server publishes.
   */
  cacheTtlSeconds?: number;
}

/**
 * Offline validation of the JWT access tokens an {@link OAuthAuthorizationServer} issues:
 * the signature is checked here, against the authorization server's published keys, and
 * no request is made to it per token. What that buys and costs: no per-request
 * round trip, but only the claims the authorization server chose to make public, and no
 * way to see a token or grant revoked before it expires. When either of those matters,
 * validate online over a Service Binding instead.
 */
export interface OfflineTokenValidation<Env = Cloudflare.Env, Props = unknown> {
  /** Exact authorization-server issuer expected in `iss`. */
  issuer: string;
  /**
   * Allowed algorithms. Never derived from the token, and never defaulted: an
   * authorization server signing `ES256` against a validator that assumed `RS256`
   * would reject every token as `invalid_token` with nothing to distinguish it
   * from an expired one.
   */
  algorithms: JwtAlgorithm[];
  /**
   * Trusted public keys: the authorization server's `jwks_uri`, or a resolver of your own.
   * Token-controlled key URLs are never followed.
   *
   * A resolver receives the `kid` and `alg` the token names, so a cached key set can be
   * refreshed when the authorization server has rotated to a key it lacks. That hint is
   * read from the JOSE header before any signature has been checked, so it is
   * unauthenticated attacker-chosen input: a resolver that fetches per unknown `kid` must
   * bound that work, as the built-in one does by refreshing at most once per cooldown.
   * Returning an empty array, or a set without the named key, is answered as
   * `invalid_token`.
   */
  keys: JwksSource<Env> | ((env: Env, hint: JwtKeyHint) => JwtPublicKey[] | Promise<JwtPublicKey[]>);
  /** Map already verified claims to the typed context exposed as `ctx.props`. */
  mapClaimsToProps(input: JwtClaimsToPropsInput<Env>): Props | null | Promise<Props | null>;
}

/** Input the resource-server host passes to a `validateToken` callback. */
interface JwtAccessTokenValidationInput<Env> {
  token: string;
  request: Request;
  env: Env;
}

/** What this validator returns. `expiresAt` is always populated, unlike the host's own type. */
interface JwtAccessTokenValidation<Props> {
  props: Props;
  audience: string;
  expiresAt: number;
}

/**
 * Create an RFC 9068 access-token signer and reader for `OAuthAuthorizationServer`.
 *
 * Passing the result as `jwtAccessTokens` installs the reader, the signer and the JWKS
 * endpoint; issuance stays opaque until `accessTokenFormat` returns `'jwt'`, so the
 * reader always ships before the writer. The provider still keeps its encrypted
 * token-context record so built-in validation, confidential `ctx.props`, token
 * exchange, and immediate revocation retain their behavior.
 *
 * `keys(env)` runs on every issuance and every same-Worker verification. Import the
 * private key once per isolate and return the memoised set, rather than calling
 * `crypto.subtle.importKey` inside it each time.
 */
export function createJwtAccessTokens<Env = Cloudflare.Env, Props = unknown>(
  options: JwtAccessTokensOptions<Env, Props>
): JwtAccessTokens<Env, Props> {
  const issuer = validateIssuer(options?.issuer);
  const jwksUri = validateAbsoluteHttpsUrl(options?.jwksUri, 'jwksUri');
  if (typeof options?.keys !== 'function') throw new TypeError('keys must be a function');
  if (options.publicClaims !== undefined && typeof options.publicClaims !== 'function') {
    throw new TypeError('publicClaims must be a function');
  }
  const issuance = options.issuance ?? false;
  if (typeof issuance !== 'boolean' && typeof issuance !== 'function') {
    throw new TypeError('issuance must be a boolean or a function');
  }

  const verifyAgainstAudiences = async (
    parsed: ParsedJwt,
    audiences: readonly string[],
    env: Env
  ): Promise<VerifiedJwtAccessToken | null> => {
    // Cheap reject before resolving keys, so a junk token never reaches the caller's
    // `keys()` resolver. It cannot yet narrow to the key set's algorithms, and it carries
    // no authority: verifyParsedJwt repeats every check below against the loaded key set.
    const preflight: JwtCheckOptions = {
      issuer,
      allowedAudiences: audiences,
      allowedAlgorithms: SUPPORTED_ALGORITHMS,
      requireSingleAudience: true,
      clockSkewSeconds: DEFAULT_CLOCK_SKEW_SECONDS,
    };
    if (!checkUnverifiedJwt(parsed, preflight)) return null;
    const keySet = validateKeySet(await options.keys(env));
    return verifyParsedJwt(parsed, {
      issuer,
      allowedAlgorithms: [keySet.signingKey.alg, ...keySet.verificationKeys.map((key) => key.alg as JwtAlgorithm)],
      publicKeys: keySet.publicKeys,
      allowedAudiences: audiences,
      requireSingleAudience: true,
      clockSkewSeconds: DEFAULT_CLOCK_SKEW_SECONDS,
    });
  };

  const accessTokens: JwtAccessTokens<Env, Props> = { issuer, jwksUri };

  internals.set(accessTokens, {
    async shouldIssue(input): Promise<boolean> {
      if (typeof issuance === 'boolean') return issuance;
      // The decision may be shared with application code: give it an immutable snapshot.
      const decision = await issuance(Object.freeze({ ...input }));
      if (typeof decision !== 'boolean') throw new TypeError('issuance must return a boolean');
      return decision;
    },

    async issue(input): Promise<IssuedJwtAccessToken> {
      const snapshot = snapshotIssueInput(input);
      const keySet = validateKeySet(await options.keys(snapshot.env));
      const projectedClaims = options.publicClaims ? await options.publicClaims(snapshot) : undefined;
      const publicClaims =
        projectedClaims === undefined
          ? undefined
          : cloneJsonValue(projectedClaims, 'publicClaims return value', MAX_TOKEN_BYTES);

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
      const header = { typ: JWT_TYPE, alg: keySet.signingKey.alg, kid: keySet.signingKey.kid };
      const encodedHeader = encodeJson(header);
      const encodedClaims = encodeJson(claims);
      const signingInputText = `${encodedHeader}.${encodedClaims}`;
      const signingInput = new TextEncoder().encode(signingInputText);
      const signature = new Uint8Array(
        await crypto.subtle.sign(getSigningAlgorithm(keySet.signingKey.alg), keySet.signingKey.privateKey, signingInput)
      );
      // Memoised per key pair, so only the first token issued under a key pays for this.
      // A privateKey paired with the wrong publicJwk is a routine rotation slip, and
      // without the proof its only symptom is a 401 at every resource server.
      await assertSigningKeyPair(keySet.signingKey);
      const token = `${signingInputText}.${encodeBytes(signature)}`;
      if (new TextEncoder().encode(token).byteLength > MAX_TOKEN_BYTES) {
        throw new TypeError(`JWT access token exceeds the ${MAX_TOKEN_BYTES}-byte limit`);
      }
      return { token, claims };
    },

    async verifyForAudiences(token, allowedAudiences, env): Promise<VerifiedJwtAccessToken | null> {
      if (!Array.isArray(allowedAudiences) || allowedAudiences.length === 0) {
        throw new TypeError('allowedAudiences must contain at least one canonical resource URI');
      }
      const audiences = [...new Set(allowedAudiences.map((value) => validateCanonicalResource(value)))];
      const parsed = parseCompactJwt(token);
      if (!parsed || !isAcceptedJwtType(parsed.header.typ)) return null;
      if (parsed.claims.iss !== issuer) return null;
      return verifyAgainstAudiences(parsed, audiences, env);
    },

    async getJwks(env): Promise<{ keys: JwtPublicKey[] }> {
      const keySet = validateKeySet(await options.keys(env));
      await assertSigningKeyPair(keySet.signingKey);
      return { keys: keySet.publicKeys.map(cloneJwk) };
    },

    verify: async (token, env) => {
      const parsed = parseCompactJwt(token);
      if (!parsed || !isAcceptedJwtType(parsed.header.typ) || parsed.claims.iss !== issuer) return null;
      const audience = readCanonicalSingleAudience(parsed.claims.aud);
      if (!audience) return null;
      return verifyAgainstAudiences(parsed, [audience], env);
    },
    isOwnJwt: (token) => {
      const parsed = parseCompactJwt(token);
      return !!parsed && isAcceptedJwtType(parsed.header.typ) && parsed.claims.iss === issuer;
    },
  });
  // Frozen: the branded handle is what the provider re-reads on every request.
  return Object.freeze(accessTokens);
}

/**
 * @internal The offline validator behind `createOAuthResourceServer({ validateToken: { offline } })`,
 * pinned to the one resource the host serves. It validates the JWT profile emitted by
 * {@link createJwtAccessTokens} and is not a generic RFC 9068 verifier.
 */
export function createJwtAccessTokenValidator<Env = Cloudflare.Env, Props = unknown>(
  audience: string,
  options: OfflineTokenValidation<Env, Props>
): (input: JwtAccessTokenValidationInput<Env>) => Promise<JwtAccessTokenValidation<Props> | null> {
  const issuer = validateIssuer(options?.issuer);
  validateCanonicalResource(audience);
  const algorithms = validateAlgorithms(options?.algorithms);
  if (typeof options?.mapClaimsToProps !== 'function') throw new TypeError('mapClaimsToProps must be a function');
  const keys = typeof options?.keys === 'function' ? options.keys : createJwksKeyResolver(options?.keys);

  return async ({ token, request, env }) => {
    const parsed = parseCompactJwt(token);
    if (!parsed) return null;
    const preflight: JwtCheckOptions = {
      issuer,
      allowedAudiences: [audience],
      allowedAlgorithms: algorithms,
      // RFC 9068 §4: a resource server accepts a token whose `aud` contains its own
      // identifier, so an interoperable array audience is honoured here even though the
      // package's own issuer only mints a single string.
      requireSingleAudience: false,
      clockSkewSeconds: DEFAULT_CLOCK_SKEW_SECONDS,
    };
    if (!checkUnverifiedJwt(parsed, preflight)) return null;
    // checkUnverifiedJwt has already restricted `alg` to `algorithms` and required a `kid`.
    const hint: JwtKeyHint = {
      kid: parsed.header.kid as string,
      alg: parsed.header.alg as JwtAlgorithm,
    };
    const publicKeys = selectUsableKeys(await keys(env, hint), algorithms);
    // No key for this token is an unverifiable token, not a broken validator: returning
    // null makes it a 401 invalid_token (RFC 9068 §4) instead of a 503.
    if (publicKeys.length === 0) return null;
    const verified = await verifyParsedJwt(parsed, {
      issuer,
      allowedAudiences: [audience],
      allowedAlgorithms: algorithms,
      publicKeys,
      requireSingleAudience: false,
      clockSkewSeconds: DEFAULT_CLOCK_SKEW_SECONDS,
    });
    if (!verified) return null;
    const props = await options.mapClaimsToProps({ ...verified, request, env });
    if (props == null) return null;
    return { props, audience, expiresAt: verified.expiresAt };
  };
}

/**
 * @internal The key resolver behind `OfflineTokenValidation.keys` when it names a JWKS:
 * the caching every resource server needs and the refresh limit it is easy to forget.
 *
 * A token names the `kid` it wants, and that name is attacker-chosen and unauthenticated
 * at the point this runs. So an unknown `kid` refreshes the key set at most once per
 * cooldown window; without that bound, a stream of invented `kid` values turns every
 * resource server into an amplifier pointed at the authorization server's JWKS endpoint.
 * Serving a stale set meanwhile is safe, because verification still has to succeed
 * against whatever keys come back.
 *
 * A key set is reused for `cacheTtlSeconds`, or for less when the response's
 * `Cache-Control` says so: `max-age` caps the lifetime, and `no-store` or `no-cache`
 * means every validation fetches again, with concurrent validations sharing one
 * request. A key the authorization server removes therefore stops verifying no later
 * than its own `Cache-Control` allows.
 */
export function createJwksKeyResolver<Env = Cloudflare.Env>(
  options: JwksSource<Env>
): (env: Env, hint: JwtKeyHint) => Promise<JwtPublicKey[]> {
  const jwksUri = validateAbsoluteHttpsUrl(options?.jwksUri, 'jwksUri');
  const maxCacheTtlSeconds = validateCacheTtl(options?.cacheTtlSeconds);
  if (options?.fetcher !== undefined && typeof options.fetcher !== 'function') {
    throw new TypeError('fetcher must be a function');
  }

  let cached: { keys: JwtPublicKey[]; expiresAt: number; nextForcedRefreshAt: number } | undefined;
  let inFlight: Promise<JwtPublicKey[]> | undefined;

  const load = async (env: Env, now: number): Promise<JwtPublicKey[]> => {
    inFlight ??= (async () => {
      try {
        const fetched = await fetchJwks(jwksUri, options.fetcher?.(env));
        cached = {
          keys: fetched.keys,
          expiresAt: now + Math.min(maxCacheTtlSeconds, fetched.freshnessSeconds ?? maxCacheTtlSeconds),
          nextForcedRefreshAt: now + JWKS_REFRESH_COOLDOWN_SECONDS,
        };
        return cached.keys;
      } finally {
        inFlight = undefined;
      }
    })();
    return inFlight;
  };

  return async (env, hint) => {
    const now = Math.floor(Date.now() / 1000);
    if (!cached || cached.expiresAt <= now) return load(env, now);
    if (cached.keys.some((key) => key.kid === hint.kid)) return cached.keys;
    // An unknown `kid` is the authorization server having rotated, or an attacker
    // guessing. One refresh per cooldown serves both without serving as an amplifier.
    if (cached.nextForcedRefreshAt > now) return cached.keys;
    return load(env, now);
  };
}

interface FetchedJwks {
  keys: JwtPublicKey[];
  /** How long the response permits its own reuse, when its `Cache-Control` said. */
  freshnessSeconds?: number;
}

async function fetchJwks(
  jwksUri: string,
  fetcher: { fetch(request: Request): Promise<Response> } | undefined
): Promise<FetchedJwks> {
  const abort = new AbortController();
  const timeout = setTimeout(() => abort.abort(), JWKS_FETCH_TIMEOUT_MS);
  try {
    const request = new Request(jwksUri, {
      headers: { Accept: 'application/jwk-set+json, application/json' },
      signal: abort.signal,
    });
    const response = await (fetcher ? fetcher.fetch(request) : fetch(request));
    if (!response.ok) throw new TypeError(`JWKS request failed with status ${response.status}`);
    const declaredLength = Number(response.headers.get('content-length') ?? Number.NaN);
    if (Number.isFinite(declaredLength) && declaredLength > MAX_JWKS_BYTES) {
      throw new TypeError('JWKS response exceeds the size limit');
    }
    const body = await readBodyWithLimit(response, MAX_JWKS_BYTES);
    const document: unknown = JSON.parse(body);
    if (!document || typeof document !== 'object' || !Array.isArray((document as { keys?: unknown }).keys)) {
      throw new TypeError('JWKS response has no keys array');
    }
    const freshnessSeconds = jwksFreshnessSeconds(response);
    return {
      keys: (document as { keys: JwtPublicKey[] }).keys,
      ...(freshnessSeconds !== undefined ? { freshnessSeconds } : {}),
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * How long a JWKS response permits its own reuse, in seconds, from the `Cache-Control`
 * directives that bind a private cache. `undefined` when the response says nothing
 * about freshness, so the configured TTL applies.
 *
 * The most restrictive directive wins (RFC 9111 §4.2.1): `no-store` or `no-cache` is
 * zero, a repeated `max-age` takes the smallest, and a `max-age` whose argument is not
 * delta-seconds, as a token or quoted, counts as stale. A misconfigured origin can only
 * make a resource server fetch more often, never serve a removed key for longer.
 * `s-maxage` and `private` address shared caches and are ignored.
 *
 * Splitting on commas is enough here: a quoted argument containing a comma is not a
 * shape any freshness directive takes, and a mis-split can only yield an unrecognised
 * name or an invalid argument, both of which land on the restrictive side.
 */
function jwksFreshnessSeconds(response: Response): number | undefined {
  const cacheControl = response.headers.get('Cache-Control');
  if (cacheControl === null) return undefined;
  let freshness: number | undefined;
  for (const directive of cacheControl.split(',')) {
    const separator = directive.indexOf('=');
    const name = (separator === -1 ? directive : directive.slice(0, separator)).trim().toLowerCase();
    if (name === 'no-store' || name === 'no-cache') return 0;
    if (name !== 'max-age') continue;
    const rawArgument = separator === -1 ? '' : directive.slice(separator + 1).trim();
    const argument = rawArgument.replace(/^"(.*)"$/, '$1');
    // RFC 9111 §1.2.2: a delta-seconds value beyond what can be represented is 2^31.
    const seconds = /^\d+$/.test(argument) ? Math.min(Number(argument), 2 ** 31) : 0;
    freshness = freshness === undefined ? seconds : Math.min(freshness, seconds);
  }
  return freshness;
}

/** Bound memory before parsing a response this Worker does not control the size of. */
async function readBodyWithLimit(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) throw new TypeError('JWKS response has no body');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new TypeError('JWKS response exceeds the size limit');
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

function validateCacheTtl(value: number | undefined): number {
  const ttl = value ?? DEFAULT_JWKS_CACHE_TTL_SECONDS;
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 86_400) {
    throw new TypeError('cacheTtlSeconds must be an integer between 1 and 86400');
  }
  return ttl;
}

interface ParsedJwt {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
}

interface JwtCheckOptions {
  issuer: string;
  allowedAudiences: readonly string[];
  allowedAlgorithms: readonly JwtAlgorithm[];
  /** Reject an array `aud`. The issuer's own profile is always single-audience. */
  requireSingleAudience: boolean;
  clockSkewSeconds: number;
}

interface VerifyParsedOptions extends JwtCheckOptions {
  publicKeys: JwtPublicKey[];
}

async function verifyParsedJwt(
  parsed: ParsedJwt,
  options: VerifyParsedOptions
): Promise<VerifiedJwtAccessToken | null> {
  const { header, claims } = parsed;
  const alg = header.alg as JwtAlgorithm;
  const kid = header.kid;
  if (typeof kid !== 'string') return null;
  const matchingKeys = options.publicKeys.filter((key) => key.kid === kid && key.alg === alg);
  if (matchingKeys.length !== 1) return null;

  let verified = false;
  try {
    verified = await verifySignature(matchingKeys[0], alg, parsed.signature, parsed.signingInput);
  } catch (error) {
    throw withCause(new TypeError(`Unable to use configured JWT verification key: ${errorMessage(error)}`), error);
  }
  if (!verified) return null;

  // Every semantic check runs here, after cryptographic verification, so a caller's
  // cheap pre-parse check is strictly an optimization and never an authority. Key
  // selection above cannot admit an algorithm outside the allowlist: it requires an
  // exact match against a `kid`/`alg` pair that `validatePublicJwk` already narrowed.
  if (!checkUnverifiedJwt(parsed, options)) return null;
  const audience = selectAudience(claims.aud, options.allowedAudiences, options.requireSingleAudience);
  const scope = parseScopeClaim(claims.scope);
  const grantId = claims[JWT_ACCESS_TOKEN_GRANT_ID_CLAIM] as string;
  if (!audience || !scope || typeof claims.exp !== 'number') return null;
  // Symmetric with the null-prototype clone the issuer builds: a `__proto__` member that
  // rode along inside the public claim must reach mapClaimsToProps as ordinary data.
  const publicClaims = detachPrototypes(claims[JWT_ACCESS_TOKEN_PUBLIC_CLAIMS]);

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

function checkUnverifiedJwt(parsed: ParsedJwt, options: JwtCheckOptions): boolean {
  const { issuer, allowedAudiences, allowedAlgorithms, requireSingleAudience, clockSkewSeconds } = options;
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

function parseCompactJwt(token: string): ParsedJwt | null {
  if (typeof token !== 'string' || !token || new TextEncoder().encode(token).byteLength > MAX_TOKEN_BYTES) return null;
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
  signingKey: JwtSigningKey;
  verificationKeys: JwtPublicKey[];
  publicKeys: JwtPublicKey[];
}

function validateKeySet(value: JwtKeySet): ValidatedKeySet {
  if (!value || typeof value !== 'object' || !value.signingKey) {
    throw new TypeError('keys must return a JWT signing key');
  }
  const { signingKey } = value;
  if (!isNonEmptyString(signingKey.kid) || signingKey.kid.length > MAX_KEY_ID_LENGTH) {
    throw new TypeError(`JWT signing key kid must contain 1-${MAX_KEY_ID_LENGTH} characters`);
  }
  if (!isSupportedAlgorithm(signingKey.alg)) throw new TypeError('JWT signing key alg must be RS256 or ES256');
  if (!isCryptoKey(signingKey.privateKey) || signingKey.privateKey.type !== 'private') {
    throw new TypeError('JWT signing key privateKey must be a private CryptoKey');
  }
  if (!signingKey.privateKey.usages.includes('sign')) {
    throw new TypeError('JWT signing key privateKey must allow sign');
  }
  validatePrivateKeyAlgorithm(signingKey.privateKey, signingKey.alg);
  const signingPublicJwk = validatePublicJwk(signingKey.publicJwk, signingKey.alg, signingKey.kid);
  const verificationKeys = value.verificationKeys ?? [];
  if (!Array.isArray(verificationKeys)) {
    throw new TypeError('JWT verificationKeys must be an array');
  }
  const additionalPublicKeys = verificationKeys.map((key) => validatePublicJwk(key));
  const publicKeys = [signingPublicJwk, ...additionalPublicKeys];
  assertUniqueKeyIds(publicKeys);
  return {
    signingKey: { ...signingKey, publicJwk: signingPublicJwk },
    verificationKeys: additionalPublicKeys,
    publicKeys,
  };
}

/**
 * Narrow a resolver's key set to the keys this validator can actually verify with.
 *
 * A resource server is handed someone else's JWKS, and RFC 7517 §4.4 makes `alg` optional
 * while RFC 9068 §4 expects an authorization server to publish keys for other purposes in
 * the same document. So an entry this package cannot classify is skipped rather than
 * treated as a configuration error: one foreign key must not take the resource server
 * down for tokens whose own key is sitting beside it. Returning no usable key at all is a
 * property of the token, not an outage, and the caller turns it into `invalid_token`.
 */
function selectUsableKeys(value: JwtPublicKey[], algorithms: JwtAlgorithm[]): JwtPublicKey[] {
  if (!Array.isArray(value)) throw new TypeError('keys must return an array of public JWKs');
  const keys: JwtPublicKey[] = [];
  for (const key of value) {
    let validated: JwtPublicKey;
    try {
      validated = validatePublicJwk(key);
    } catch {
      continue;
    }
    if (algorithms.includes(validated.alg as JwtAlgorithm)) keys.push(validated);
  }
  // A duplicate `kid` is ambiguous rather than foreign, and verifyParsedJwt already
  // refuses to guess between two keys carrying one `kid`.
  return keys;
}

function validatePublicJwk(
  value: JwtPublicKey,
  expectedAlgorithm?: JwtAlgorithm,
  expectedKeyId?: string
): JwtPublicKey {
  if (!value || typeof value !== 'object') throw new TypeError('JWT public key must be a JWK object');
  // Reject private material on the caller's own object: cloneJwk() copies an allowlist and
  // would quietly drop the very members this refuses to publish.
  if (containsPrivateJwkMaterial(value)) {
    throw new TypeError('JWT public JWK must not contain private key material');
  }
  const declaredKeyOps = (value as { key_ops?: unknown }).key_ops;
  if (declaredKeyOps !== undefined && (!Array.isArray(declaredKeyOps) || !declaredKeyOps.includes('verify'))) {
    throw new TypeError("JWT public JWK key_ops must include 'verify'");
  }
  const key = cloneJwk(value);
  if (!isNonEmptyString(key.kid) || key.kid.length > MAX_KEY_ID_LENGTH) {
    throw new TypeError(`JWT public JWK kid must contain 1-${MAX_KEY_ID_LENGTH} characters`);
  }
  if (!isSupportedAlgorithm(key.alg)) throw new TypeError('JWT public JWK alg must be RS256 or ES256');
  if (expectedAlgorithm && key.alg !== expectedAlgorithm)
    throw new TypeError('JWT public JWK alg must match signing key');
  if (expectedKeyId && key.kid !== expectedKeyId) throw new TypeError('JWT public JWK kid must match signing key');
  if (key.use !== undefined && key.use !== 'sig') throw new TypeError("JWT public JWK use must be 'sig'");
  if (key.alg === 'RS256' && key.kty !== 'RSA') throw new TypeError('RS256 JWT public JWK must use kty RSA');
  if (
    key.alg === 'RS256' &&
    (!isNonEmptyString(key.n) ||
      rsaModulusBits(key.n) < 2048 ||
      !isNonEmptyString(key.e) ||
      !isUsableRsaExponent(key.e))
  ) {
    throw new TypeError(
      'RS256 JWT public JWK must contain an RSA modulus of at least 2048 bits and an odd public exponent of at least 3'
    );
  }
  if (key.alg === 'ES256' && (key.kty !== 'EC' || key.crv !== 'P-256')) {
    throw new TypeError('ES256 JWT public JWK must use kty EC and crv P-256');
  }
  if (key.alg === 'ES256' && (!isP256Coordinate(key.x) || !isP256Coordinate(key.y))) {
    throw new TypeError('ES256 JWT public JWK must contain 32-byte base64url x and y coordinates');
  }
  // RFC 7517 advises against publishing both `use` and `key_ops`. `use: sig` is the
  // broadly interoperable constraint for an authorization-server JWKS, and `key_ops`
  // never survives the published-member allowlist above.
  return { ...key, use: 'sig' } as JwtPublicKey;
}

function assertUniqueKeyIds(keys: JwtPublicKey[]): void {
  const seen = new Set<string>();
  for (const key of keys) {
    if (seen.has(key.kid!)) throw new TypeError(`JWT public keys must use unique kid values: ${key.kid}`);
    seen.add(key.kid!);
  }
}

/**
 * Rebuild plain objects with a null prototype and drop any `__proto__` member.
 *
 * The issuer refuses to mint such a member, so this only matters for a token minted by
 * another build, but the consequence is not local: `mapClaimsToProps` receiving a claim
 * with a `__proto__` key would reassign the prototype of any ordinary object it copies the
 * claim onto, and a copy is the obvious thing to write.
 */
function detachPrototypes(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(detachPrototypes);
  if (!value || typeof value !== 'object') return value;
  const detached = Object.create(null) as Record<string, unknown>;
  for (const [key, member] of Object.entries(value)) {
    if (key === '__proto__') continue;
    detached[key] = detachPrototypes(member);
  }
  return detached;
}

/** A P-256 affine coordinate is exactly 32 base64url-encoded bytes (RFC 7518 §6.2.1.2). */
function isP256Coordinate(value: unknown): boolean {
  if (!isNonEmptyString(value)) return false;
  try {
    return decodeBytes(value).length === 32;
  } catch {
    return false;
  }
}

function containsPrivateJwkMaterial(key: JwtPublicKey): boolean {
  // Presence alone is not enough to judge: workerd's exportKey() materializes the optional
  // members of the JsonWebKey dictionary as own properties holding undefined, so a public
  // key legitimately has a `d` key that carries nothing. Only a real value is material.
  return ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(
    (name) => (key as unknown as Record<string, unknown>)[name] !== undefined
  );
}

function snapshotIssueInput<Env, Props>(input: JwtPublicClaimsInput<Env, Props>): JwtPublicClaimsInput<Env, Props> {
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
  if (new URL(issuer).search) throw new TypeError('issuer must not contain a query');
  return issuer;
}

function validateCanonicalResource(value: unknown): string {
  if (typeof value !== 'string' || !isCanonicalHttpsUrl(value)) {
    throw new TypeError(
      'audience must be a canonical absolute HTTPS resource URI (http is accepted only on a loopback host)'
    );
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
    throw new TypeError(`${name} must be an absolute HTTPS URL (http is accepted only on a loopback host)`);
  }
  // isCanonicalHttpsUrl already rejects userinfo and any '#', so nothing further to check.
  return value;
}

function isCanonicalHttpsUrl(value: string): boolean {
  if (!validateResourceUri(value)) return false;
  const parsed = new URL(value);
  return (
    hasAcceptedCanonicalScheme(parsed) &&
    !parsed.username &&
    !parsed.password &&
    parsed.protocol === parsed.protocol.toLowerCase() &&
    parsed.hostname === parsed.hostname.toLowerCase() &&
    (parsed.href === value || parsed.origin === value)
  );
}

function validateAlgorithms(value: unknown): JwtAlgorithm[] {
  if (!Array.isArray(value) || value.length === 0 || value.some((alg) => !isSupportedAlgorithm(alg))) {
    throw new TypeError('algorithms must contain RS256 and/or ES256');
  }
  return [...new Set(value)];
}

function isSupportedAlgorithm(value: unknown): value is JwtAlgorithm {
  return SUPPORTED_ALGORITHMS.includes(value as JwtAlgorithm);
}

function isAcceptedJwtType(value: unknown): boolean {
  return typeof value === 'string' && ACCEPTED_JWT_TYPES.has(value.toLowerCase());
}

function getImportAlgorithm(algorithm: JwtAlgorithm): Parameters<SubtleCrypto['importKey']>[2] {
  return algorithm === 'RS256'
    ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    : { name: 'ECDSA', namedCurve: 'P-256' };
}

function getSigningAlgorithm(algorithm: JwtAlgorithm): Parameters<SubtleCrypto['sign']>[0] {
  return algorithm === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };
}

async function verifySignature(
  publicJwk: JwtPublicKey,
  algorithm: JwtAlgorithm,
  signature: Uint8Array,
  signingInput: Uint8Array
): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey('jwk', publicJwk, getImportAlgorithm(algorithm), false, ['verify']);
  return crypto.subtle.verify(getSigningAlgorithm(algorithm), publicKey, signature, signingInput);
}

async function assertSigningKeyPair(key: JwtSigningKey): Promise<void> {
  const cacheKey = JSON.stringify(key.publicJwk);
  let verifications = verifiedSigningKeyPairs.get(key.privateKey);
  if (!verifications) {
    verifications = new Map<string, Promise<void>>();
    verifiedSigningKeyPairs.set(key.privateKey, verifications);
  }
  let verification = verifications.get(cacheKey);
  if (!verification) {
    verification = proveSigningKeyPair(key);
    verifications.set(cacheKey, verification);
  }
  try {
    await verification;
  } catch (error) {
    if (verifications.get(cacheKey) === verification) verifications.delete(cacheKey);
    throw error;
  }
}

async function proveSigningKeyPair(key: JwtSigningKey): Promise<void> {
  const data = new TextEncoder().encode('workers-oauth-provider jwt key-pair check');
  let signature: Uint8Array;
  try {
    signature = new Uint8Array(await crypto.subtle.sign(getSigningAlgorithm(key.alg), key.privateKey, data));
  } catch (error) {
    throw withCause(new TypeError(`Unable to use the JWT signing key: ${errorMessage(error)}`), error);
  }
  if (!(await verifySignature(key.publicJwk, key.alg, signature, data))) {
    throw new TypeError('JWT signing key privateKey does not match publicJwk');
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

function validatePrivateKeyAlgorithm(key: CryptoKey, algorithm: JwtAlgorithm): void {
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

/**
 * An RSA public exponent of 1 (or any even value) makes PKCS#1 v1.5 verification
 * trivially forgeable, and WebCrypto imports such keys without complaint.
 */
function isUsableRsaExponent(encodedExponent: string): boolean {
  let exponent: Uint8Array;
  try {
    exponent = decodeBytes(encodedExponent);
  } catch {
    return false;
  }
  let value = 0n;
  for (const byte of exponent) value = (value << 8n) | BigInt(byte);
  return value >= 3n && (value & 1n) === 1n;
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

function cloneJsonValue(value: unknown, label: string, maxTextBytes: number): JwtJsonValue {
  return cloneJsonValueAt(
    value,
    label,
    { ancestors: new Set<object>(), nodes: 0, remainingTextBytes: maxTextBytes },
    0
  );
}

function cloneJsonValueAt(value: unknown, label: string, state: JsonCloneState, depth: number): JwtJsonValue {
  if (depth > MAX_PUBLIC_CLAIM_DEPTH || ++state.nodes > MAX_PUBLIC_CLAIM_NODES) {
    throw new TypeError(`${label} exceeds the maximum JSON depth or node count`);
  }
  if (typeof value === 'string') {
    consumeCloneTextBudget(state, value, label);
    return value;
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object') throw new TypeError(`${label} must be a finite JSON value or undefined`);
  if (state.ancestors.has(value)) throw new TypeError(`${label} must be a finite JSON value or undefined`);
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) return value.map((item) => cloneJsonValueAt(item, label, state, depth + 1));
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
      throw new TypeError(`${label} must be a finite JSON value or undefined`);
    }
    // A null prototype makes JSON keys such as "__proto__" ordinary own data
    // instead of invoking Object.prototype's legacy setter during the clone.
    const result = Object.create(null) as Record<string, JwtJsonValue>;
    for (const key of Object.keys(value)) {
      // Nothing downstream can hold such a member safely: a resource server that copies
      // the claim onto an ordinary object with Object.assign or a spread would reassign
      // that object's prototype. Refuse to mint it rather than export the hazard.
      if (key === '__proto__') throw new TypeError(`${label} must not contain a __proto__ member`);
      consumeCloneTextBudget(state, key, label);
      result[key] = cloneJsonValueAt((value as Record<string, unknown>)[key], label, state, depth + 1);
    }
    return result;
  } finally {
    state.ancestors.delete(value);
  }
}

function consumeCloneTextBudget(state: JsonCloneState, value: string, label: string): void {
  state.remainingTextBytes -= new TextEncoder().encode(value).byteLength;
  if (state.remainingTextBytes < 0) {
    throw new TypeError(`${label} exceeds the JWT token-size budget`);
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

/**
 * Members that belong in a published JWK. An allowlist rather than a denylist, because the
 * caller's key record is an application object: anything it carries beside the key (an
 * internal id, a rotation timestamp) would otherwise be served on the public JWKS.
 */
const PUBLISHED_JWK_MEMBERS = ['kty', 'kid', 'alg', 'use', 'n', 'e', 'crv', 'x', 'y'] as const;

function cloneJwk(value: JwtPublicKey): JwtPublicKey {
  const published: Partial<Record<(typeof PUBLISHED_JWK_MEMBERS)[number], unknown>> = {};
  for (const name of PUBLISHED_JWK_MEMBERS) {
    const member = (value as unknown as Record<string, unknown>)[name];
    if (member !== undefined) published[name] = member;
  }
  return published as unknown as JwtPublicKey;
}

/**
 * Keep the underlying WebCrypto failure reachable for diagnostics. Assigned rather than
 * passed to the constructor because the package targets a language level without the
 * ES2022 `cause` option.
 */
function withCause(error: TypeError, cause: unknown): TypeError {
  Object.defineProperty(error, 'cause', { value: cause, enumerable: false, configurable: true, writable: true });
  return error;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
