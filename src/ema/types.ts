/**
 * Public and internal types for MCP Enterprise-Managed Authorization (EMA).
 */

import type { ClientInfo } from '../oauth-provider';

// ─── Public types (deployer-facing) ───────────────────────────────────────────

/**
 * Claims expected in an MCP Enterprise-Managed Authorization ID-JAG assertion.
 * Additional issuer-specific claims (e.g. `email`) are preserved verbatim
 * under the index signature.
 */
export interface EmaIdJagClaims {
  /** Identity provider issuer URL. */
  iss: string;

  /** Enterprise subject identifier for the resource owner. */
  sub: string;

  /** Authorization server issuer URL or URLs for which this assertion is intended. */
  aud: string | string[];

  /** RFC 9728 resource identifier of the MCP server. */
  resource: string;

  /** OAuth client identifier this assertion was issued to. */
  client_id: string;

  /** Unique assertion identifier used for replay protection. */
  jti: string;

  /** Assertion expiration time as a Unix timestamp in seconds. */
  exp: number;

  /** Assertion issued-at time as a Unix timestamp in seconds. */
  iat: number;

  /** Optional space-separated OAuth scope string. */
  scope?: string;

  /** Optional email claim supplied by the enterprise IdP. */
  email?: string;

  /** Additional enterprise IdP claims. */
  [claim: string]: unknown;
}

/**
 * Trusted enterprise IdP configuration for ID-JAG validation.
 */
export interface EmaTrustedIssuer {
  /** Issuer URL that must exactly match the assertion `iss` claim. */
  issuer: string;

  /** HTTPS JWKS endpoint used to validate assertion signatures. */
  jwksUri: string;

  /** Allowed JWT signing algorithms for this issuer. Defaults to `['RS256']`. */
  algorithms?: string[];

  /** Expected authorization server audience. Defaults to this provider's issuer URL. */
  audience?: string;
}

/**
 * Input passed to `enterpriseManagedAuthorization.mapClaims` after ID-JAG validation.
 */
export interface EmaClaimsMapperInput<Env = Cloudflare.Env> {
  /** Validated ID-JAG claims. */
  claims: EmaIdJagClaims;

  /** Authenticated OAuth client that presented the assertion. */
  clientInfo: ClientInfo;

  /** Validated MCP resource identifier from the assertion. */
  resource: string;

  /** Requested scopes after downscoping to the assertion's scope claim, if present. */
  requestedScope: string[];

  /** Cloudflare Worker environment variables. */
  env: Env;
}

/**
 * Result returned by `enterpriseManagedAuthorization.mapClaims`.
 */
export interface EmaClaimsMapperResult {
  /** User ID to associate with the issued grant and access token. */
  userId: string;

  /** Scopes to grant to the issued access token. */
  scope: string[];

  /** Optional grant metadata used for audit and grant listing. This is not encrypted. */
  metadata?: unknown;

  /** Application props encrypted into the issued access token and exposed to API handlers. */
  props: unknown;

  /** Optional access token TTL override in seconds. Clamped to the assertion lifetime. */
  accessTokenTTL?: number;
}

/**
 * Maps validated enterprise ID-JAG claims to this provider's local user, scopes,
 * metadata, and props. Return `null` to deny token issuance.
 */
export type EmaClaimsMapper<Env = Cloudflare.Env> = (
  input: EmaClaimsMapperInput<Env>
) => Promise<EmaClaimsMapperResult | null> | EmaClaimsMapperResult | null;

/**
 * Adapter for fetching an IdP's JWKS. Deployers can supply a custom
 * implementation (e.g. backed by the Workers Cache API or a Durable Object)
 * by passing it via `EmaOptions.jwksProvider`.
 */
export interface EmaJwksProvider {
  fetch(
    issuer: EmaTrustedIssuer,
    opts: { forceRefresh: boolean; now: number }
  ): Promise<EmaJwksFetchResult>;
}

export type EmaJwksFetchResult =
  | { readonly ok: true; readonly jwks: JsonWebKeySet }
  | { readonly ok: false; readonly reason: 'fetch_failed'; readonly status?: number }
  | { readonly ok: false; readonly reason: 'force_refresh_throttled' };

/**
 * Adapter for replay protection of ID-JAG `jti` values. The default
 * implementation is KV-backed (best-effort, not strict-once). Deployers
 * needing strict-once semantics under concurrency can supply a DO-backed
 * implementation via `EmaOptions.jtiStore`.
 */
export interface EmaJtiStore {
  markUsed(input: {
    issuer: string;
    jti: string;
    exp: number;
    now: number;
    env: any;
  }): Promise<EmaJtiMarkResult>;
}

export type EmaJtiMarkResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: 'replayed' };

/**
 * MCP Enterprise-Managed Authorization configuration.
 *
 * Presence of this option on `OAuthProviderOptions` enables the EMA grant.
 * There is intentionally no `enabled` flag — forgetting to set it would
 * silently disable the feature despite full configuration.
 */
export interface EmaOptions<Env = Cloudflare.Env> {
  /** Enterprise IdPs trusted to issue ID-JAG assertions. */
  trustedIssuers: EmaTrustedIssuer[];

  /** Maps validated enterprise claims to local token data. */
  mapClaims: EmaClaimsMapper<Env>;

  /** JWKS cache TTL in seconds. Defaults to 300 seconds. */
  jwksCacheTtlSeconds?: number;

  /** Allowed clock skew for `exp` and `iat` checks in seconds. Defaults to 60 seconds. */
  clockSkewSeconds?: number;

  /** Maximum accepted assertion lifetime in seconds. Defaults to 300 seconds. */
  maxAssertionLifetimeSeconds?: number;

  /**
   * Optional custom JWKS provider. Defaults to the built-in HTTP fetcher with
   * a per-issuer in-memory cache and force-refresh cool-down.
   */
  jwksProvider?: EmaJwksProvider;

  /**
   * Optional custom JTI replay store. Defaults to a KV-backed best-effort
   * implementation; supply a Durable Object-backed implementation if you
   * need strict-once semantics under concurrent requests.
   */
  jtiStore?: EmaJtiStore;
}

// ─── Internal types (used inside the EMA pipeline) ────────────────────────────

export interface JsonWebKeySet {
  keys?: OAuthJsonWebKey[];
}

export type OAuthJsonWebKey = JsonWebKey & {
  kid?: string;
  alg?: string;
  use?: string;
  key_ops?: string[];
  kty?: string;
};

/** Parsed but not-yet-validated ID-JAG. */
export interface ParsedIdJag {
  header: Record<string, unknown>;
  rawClaims: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
}

/** Validated JOSE header for an ID-JAG. */
export interface ValidatedIdJagHeader {
  typ: string;
  alg: string;
  kid?: string;
}

/** Fully validated ID-JAG, ready to feed into the claims mapper. */
export interface ValidatedIdJag {
  claims: EmaIdJagClaims;
  resource: string;
  assertionScopes: string[];
}

/** Output of the EMA pipeline up to (but not including) token minting. */
export interface EmaAuthorization {
  userId: string;
  scope: string[];
  props: unknown;
  metadata: unknown;
  resource: string;
  assertionExp: number;
  assertionScopes: string[];
  accessTokenTTLSeconds: number;
}
