/**
 * Public and internal types for MCP Enterprise-Managed Authorization (EMA).
 */

import type { ClientInfo } from '../oauth-provider';
import type { EmaValidationError, Result } from './result';

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

  /** The original HTTP token request, e.g. for inspecting Host header in multi-tenant routing. */
  request: Request;

  /** Cloudflare Worker environment variables. */
  env: Env;
}

/**
 * Result returned by `enterpriseManagedAuthorization.mapClaims`.
 */
export interface EmaClaimsMapperResult {
  /**
   * User ID to associate with the issued grant and access token.
   *
   * Must not contain `:` — the opaque access token format issued by this
   * provider uses `:` as an internal separator, so a `userId` containing
   * it will produce tokens that fail to parse on validation. If the IdP
   * subject may contain `:` (e.g. an email), encode or hash it first
   * (e.g. ``userId: `enterprise-${encodeURIComponent(claims.sub)}` ``).
   */
  userId: string;

  /** Scopes to grant to the issued access token. */
  scope: string[];

  /**
   * Optional grant metadata used for audit and grant listing. This is not
   * encrypted. Stored on the grant in KV alongside the user ID — visible to
   * server-side code via `OAuthHelpers` but never exposed to the MCP client.
   * Use for audit logs, admin UIs, or "list active sessions" features.
   */
  metadata?: unknown;

  /**
   * Application props encrypted into the issued access token and exposed to
   * API handlers on every authenticated request (via `getMcpAuthContext()`
   * for MCP servers, or `ctx.props` in the underlying OAuth helpers). Use
   * for per-request data the protected resource needs without hitting the
   * IdP again — e.g. `enterprise: true`, subject, email, role claims.
   */
  props: unknown;

  /**
   * Optional access token TTL override in seconds. Overrides the AS's
   * configured default. Not clamped to the assertion lifetime — the ID-JAG
   * `exp` governs how long the assertion remains a usable grant, not the
   * lifetime of the access token it mints (RFC 7523 §3).
   */
  accessTokenTTL?: number;
}

/**
 * Maps validated enterprise ID-JAG claims to this provider's local user, scopes,
 * metadata, and props. Return `null` to deny token issuance.
 *
 * Always async — mirrors `EmaTrustedIssuerResolver` so the two enterprise
 * callbacks have the same shape and downstream lookups (KV, D1, IdP federation)
 * don't require a later API change to add `Promise<…>` return support.
 */
export type EmaClaimsMapper<Env = Cloudflare.Env> = (
  input: EmaClaimsMapperInput<Env>
) => Promise<EmaClaimsMapperResult | null>;

/** Internal provider for fetching an IdP's JWKS during ID-JAG signature verification. */
export interface EmaJwksProvider {
  fetch(
    issuer: EmaTrustedIssuer,
    opts: { forceRefresh: boolean; now: number }
  ): Promise<Result<JsonWebKeySet, EmaValidationError>>;
}

/**
 * Internal store for replay protection of ID-JAG `jti` values.
 *
 * The default KV-backed implementation is best-effort — KV is eventually
 * consistent, so two near-simultaneous token requests presenting the same
 * assertion from different colos can both read "not seen" and both succeed.
 * Surrounding checks (signature, short `exp`, `nbf`, `aud`, `resource`,
 * client binding) constrain the practical attack window.
 */
export interface EmaJtiStore {
  markUsed(input: {
    issuer: string;
    jti: string;
    exp: number;
    now: number;
    env: { OAUTH_KV: KVNamespace };
  }): Promise<Result<void, EmaValidationError>>;
}

/**
 * Input passed to a dynamic `EmaTrustedIssuerResolver`.
 *
 * The `iss` value comes from the assertion's unverified payload — it is
 * used here only as a routing key to choose which IdP's JWKS to load.
 * The cryptographic trust comes from signature verification later, so
 * the resolver may safely treat `iss` as untrusted input.
 */
export interface EmaTrustedIssuerResolverInput<Env = Cloudflare.Env> {
  /** Issuer URL from the assertion's `iss` claim (unverified). */
  iss: string;
  /** Cloudflare Worker environment variables (bindings, secrets, KV, D1). */
  env: Env;
  /** The original HTTP request, e.g. for inspecting the Host header in multi-tenant routing. */
  request: Request;
  /** Authenticated OAuth client that presented the assertion. */
  clientInfo: ClientInfo;
}

/**
 * Dynamic resolver for `EmaOptions.trustedIssuers`.
 *
 * Returns the trusted issuer configuration for an incoming `iss` claim,
 * or `null` if the issuer is not trusted for this client / tenant. The
 * returned `issuer` field must equal the input `iss` — the AS enforces
 * this to prevent a resolver from being tricked into returning a config
 * for a different IdP than the one the assertion claims to be from.
 *
 * Useful for B2B platforms where new tenants onboard their own IdPs
 * dynamically and the AS cannot ship a static list at deploy time.
 *
 * **SSRF warning**: `jwksUri` is fetched outbound by the AS. If your
 * resolver reads `jwksUri` from tenant-controlled storage (self-service
 * tenant onboarding, etc.), an attacker who controls a tenant config
 * can point the AS at arbitrary HTTPS endpoints — internal services,
 * cloud metadata endpoints, victim hosts for DoS amplification. The
 * library only enforces `https:`; deployers must validate `jwksUri`
 * against their own allowlist (e.g. registered IdP vendor domains)
 * before storing or returning it.
 */
export type EmaTrustedIssuerResolver<Env = Cloudflare.Env> = (
  input: EmaTrustedIssuerResolverInput<Env>
) => Promise<EmaTrustedIssuer | null>;

/**
 * MCP Enterprise-Managed Authorization configuration.
 *
 * Presence of this option on `OAuthProviderOptions` enables the EMA grant.
 * There is intentionally no `enabled` flag — forgetting to set it would
 * silently disable the feature despite full configuration.
 */
export interface EmaOptions<Env = Cloudflare.Env> {
  /**
   * Resolver that returns the trusted issuer configuration for an
   * incoming `iss` claim, or `null` to reject the assertion.
   *
   * Always a function — for a fixed list of IdPs, write a one-line closure:
   *
   * ```ts
   * const issuers = [{ issuer: 'https://idp.example.com', jwksUri: '...' }];
   * trustedIssuers: async ({ iss }) => issuers.find((i) => i.issuer === iss) ?? null,
   * ```
   *
   * For B2B / multi-tenant deployments, the resolver can consult `env`,
   * `request`, or `clientInfo` to look up the issuer dynamically (e.g.
   * a per-tenant config in KV / D1) without redeploying.
   */
  trustedIssuers: EmaTrustedIssuerResolver<Env>;

  /** Maps validated enterprise claims to local token data. */
  mapClaims: EmaClaimsMapper<Env>;

  /** JWKS cache TTL in seconds. Defaults to 300 seconds. */
  jwksCacheTtlSeconds?: number;

  /** Allowed clock skew for `exp` and `iat` checks in seconds. Defaults to 60 seconds. */
  clockSkewSeconds?: number;

  /** Maximum accepted assertion lifetime in seconds. Defaults to 300 seconds. */
  maxAssertionLifetimeSeconds?: number;

  /**
   * Allow public clients (`token_endpoint_auth_method: 'none'`) to use the
   * enterprise-managed authorization (ID-JAG) grant.
   *
   * Defaults to `false`. By default the EMA grant requires client
   * authentication, matching the MCP enterprise-managed-authorization draft.
   *
   * Set to `true` to also accept public clients on this grant — for example
   * clients registered via a Client ID Metadata Document (CIMD), which are
   * always public (`none`) and therefore cannot present a client secret. The
   * security trade-off is documented in the README: the trust then rests on
   * the IdP-issued, signature-verified, short-lived, single-use ID-JAG
   * assertion (audience-, resource-, and client-bound) rather than on a
   * separately presented client secret.
   */
  allowPublicClients?: boolean;
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
