/**
 * Constants for MCP Enterprise-Managed Authorization (EMA).
 *
 * Co-located so that anyone touching the EMA code path sees every magic
 * number in one place. Public-facing defaults can be overridden via
 * `EmaOptions`.
 */

/** JWT `typ` header value required for ID-JAG assertions (RFC 8725 §3.11). */
export const EMA_ID_JAG_JWT_TYPE = 'oauth-id-jag+jwt';

/** Maximum compact JWT assertion size accepted at the token endpoint. */
export const EMA_MAX_JWT_BYTES = 16 * 1024;

/** Maximum JWKS response size accepted from a trusted enterprise IdP. */
export const EMA_JWKS_MAX_SIZE_BYTES = 64 * 1024;

/** Request timeout for JWKS fetches. */
export const EMA_JWKS_FETCH_TIMEOUT_MS = 10_000;

/** Default JWKS cache TTL. */
export const EMA_DEFAULT_JWKS_CACHE_TTL_SECONDS = 5 * 60;

/** Default allowed clock skew for ID-JAG time claim validation. */
export const EMA_DEFAULT_CLOCK_SKEW_SECONDS = 60;

/** Default maximum accepted ID-JAG lifetime. */
export const EMA_DEFAULT_MAX_ASSERTION_LIFETIME_SECONDS = 5 * 60;

/**
 * Minimum cool-down between JWKS force-refreshes per issuer.
 * Defends against attackers that send many assertions with random `kid`
 * values to amplify load on the IdP's JWKS endpoint.
 */
export const EMA_JWKS_FORCE_REFRESH_COOLDOWN_SECONDS = 30;

/** Default JWT signing algorithm assumed for a trusted issuer. */
export const EMA_DEFAULT_JWT_ALGORITHM = 'RS256';

/** JWT signing algorithms supported by the built-in WebCrypto verifier. */
export const EMA_SUPPORTED_JWT_ALGORITHMS = new Set(['RS256', 'ES256'] as const);

export type EmaSupportedAlg = 'RS256' | 'ES256';
