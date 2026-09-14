import { WorkerEntrypoint } from 'cloudflare:workers';

import {
  AuthorizationError,
  buildOAuthServerCapabilities,
  isValidOAuthScopeToken,
  normalizePkceCodeChallengeMethod,
  validateAuthorizationPkce,
  validateAuthorizationResponseType,
  validatePkceCodeChallengeMethod,
  validateAuthorizationServerScopes,
  withAuthorizationRedirect,
  type OAuthServerCapabilities,
  type PkceCodeChallengeMethod,
} from './oauth-capabilities';
import {
  fetchClientIdMetadataDocument,
  isClientIdMetadataDocumentUrl,
  requireJsonObject,
  resolveDynamicClientRegistrationMetadata,
  validateRedirectUriScheme,
  type ResolvedDynamicClientRegistrationMetadata,
} from './oauth-client-metadata';
import {
  EMA_DEFAULT_CLOCK_SKEW_SECONDS,
  EMA_DEFAULT_MAX_ASSERTION_LIFETIME_SECONDS,
  EMA_ID_JAG_GRANT_PROFILE,
  EMA_ID_JAG_JWT_TYPE,
  EMA_MAX_JWT_BYTES,
  EMA_SUPPORTED_JWT_ALGORITHMS,
  type EmaSupportedAlg,
} from './ema/constants';
import { createKvJtiStore } from './ema/jti';
import { createDefaultJwksProvider } from './ema/jwks';
import { parseIdJag } from './ema/parser';
import { emaErrorToWire, err, ok, type EmaValidationError, type Result } from './ema/result';
import { selectJwk, verifyIdJagSignature } from './ema/signature';
import type { EmaJtiStore, EmaJwksProvider, EmaOptions, EmaTrustedIssuer } from './ema/types';
import {
  computeEmaAccessTokenTTL,
  parseEmaScopeParam,
  resolveTrustedIssuer,
  validateEmaMapperResult,
  validateIdJagClaims,
  validateIdJagHeader,
} from './ema/validators';
import {
  jwtInternals,
  type JwtPublicKey,
  type JwtAccessTokens,
  type VerifiedJwtAccessToken,
} from './jwt-access-tokens';
import {
  foldResourceSchemeAndHost,
  hasAcceptedCanonicalScheme,
  isLoopbackHostname,
  requestCarriesResourceQuery,
  resourceMatches,
  validateResourceUri,
} from './oauth-resource';

export { AuthorizationError } from './oauth-capabilities';
export type { AuthorizationErrorCode, AuthorizationErrorOptions } from './oauth-capabilities';
export { JWT_ACCESS_TOKEN_GRANT_ID_CLAIM, JWT_ACCESS_TOKEN_PUBLIC_CLAIMS } from './jwt-access-tokens';
export {
  createJwtAccessTokens,
  createJwtAccessTokenValidator,
  type IssuedJwtAccessToken,
  type JwtAccessTokenClaims,
  type JwtAccessTokenIssueInput,
  type JwtAccessTokens,
  type JwtAccessTokensOptions,
  type JwtAccessTokenValidatorOptions,
  type JwtAlgorithm,
  type JwtClaimsToPropsInput,
  type JwtJsonValue,
  type JwtKeyHint,
  type JwtKeySet,
  type JwtPublicKey,
  type JwtSigningKey,
  type VerifiedJwtAccessToken,
} from './jwt-access-tokens';
export * from './oauth-resource-server';

export type {
  EmaClaimsMapper,
  EmaClaimsMapperInput,
  EmaClaimsMapperResult,
  EmaIdJagClaims,
  EmaOptions,
  EmaTrustedIssuer,
  EmaTrustedIssuerResolver,
  EmaTrustedIssuerResolverInput,
} from './ema/types';
export type { EmaValidationError } from './ema/result';
export { isValidOAuthScopeToken } from './oauth-capabilities';
export { resourceMatches, validateResourceUri } from './oauth-resource';

const PROTECTED_RESOURCE_WELL_KNOWN_PREFIX = '/.well-known/oauth-protected-resource';
const NO_CACHE_HEADERS = { 'Cache-Control': 'no-store', Pragma: 'no-cache' } as const;
const BASIC_AUTH_CHALLENGE = 'Basic realm="OAuth"';

// Log CIMD status on module load
const hasStrictlyPublicFetch =
  typeof Cloudflare !== 'undefined' && Cloudflare.compatibilityFlags?.global_fetch_strictly_public === true;

if (!hasStrictlyPublicFetch) {
  console.warn(
    `CIMD (Client ID Metadata Document) is disabled: add '"compatibility_flags": ["global_fetch_strictly_public"]' to your wrangler.jsonc to enable. ` +
      `See: https://developers.cloudflare.com/workers/configuration/compatibility-flags/#global-fetch-strictly-public`
  );
}

// Types

/**
 * The environment bindings the provider itself requires. The deployer's full
 * environment (`Env`) is threaded through alongside this shape so that
 * handlers and callbacks receive their app-specific bindings untouched.
 */
interface ProviderEnv {
  OAUTH_KV: KVNamespace;
}

/**
 * The public JWT factory type-checks its props mapper. The provider's historic
 * token callbacks expose `props: any`, so that type is deliberately erased only
 * at this internal boundary while the encrypted value moves through storage.
 */
type InternalJwtAccessTokens<Env> = JwtAccessTokens<Env, any>;

/**
 * Enum representing the type of handler (ExportedHandler or WorkerEntrypoint)
 */
enum HandlerType {
  EXPORTED_HANDLER,
  WORKER_ENTRYPOINT,
}

/**
 * Enum representing OAuth grant types
 */
export enum GrantType {
  AUTHORIZATION_CODE = 'authorization_code',
  REFRESH_TOKEN = 'refresh_token',
  TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange',
  JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer',
}

/** ExecutionContext with writable props — ctx.props is read-only in types but writable at runtime */
type MutableExecutionContext = Omit<ExecutionContext, 'props'> & { props: any };

/**
 * Aliases for either type of Handler that makes .fetch required
 */
type ExportedHandlerWithFetch<Env = Cloudflare.Env, Props = unknown> = ExportedHandler<Env, unknown, unknown, Props> &
  Pick<Required<ExportedHandler<Env, unknown, unknown, Props>>, 'fetch'>;
type WorkerEntrypointWithFetch<Env = Cloudflare.Env, Props = {}> = WorkerEntrypoint<Env, Props> & {
  fetch: NonNullable<WorkerEntrypoint['fetch']>;
};

/**
 * Discriminated union type for handlers
 */
type TypedHandler<Env = Cloudflare.Env> =
  | {
      type: HandlerType.EXPORTED_HANDLER;
      handler: ExportedHandlerWithFetch<Env, any>;
    }
  | {
      type: HandlerType.WORKER_ENTRYPOINT;
      handler: new (ctx: ExecutionContext, env: Env) => WorkerEntrypointWithFetch<Env, any>;
    };

/**
 * Configuration options for the OAuth Provider
 */
/**
 * Registered OAuth 2.0 error codes that the `/token` endpoint may return.
 *
 * Union of:
 *   - RFC 6749 §5.2 (token endpoint)
 *   - RFC 6750 §3.1 (bearer / resource server) — included so callbacks
 *     doing audience validation can use them
 *   - RFC 8693 §2.2.2 (token exchange)
 */
export type OAuthTokenErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'invalid_token'
  | 'insufficient_scope'
  | 'invalid_target'
  | 'server_error'
  | 'temporarily_unavailable';

/**
 * Result of a token exchange callback function.
 * Allows updating the props stored in both the access token and the grant.
 */
export interface TokenExchangeCallbackResult<Props = any> {
  /**
   * New props to be stored specifically with the access token.
   * If not provided but newProps is, the access token will use newProps.
   * If neither is provided, the original props will be used.
   */
  accessTokenProps?: Props;

  /**
   * New props to replace the props stored in the grant itself.
   * These props will be used for all future token refreshes.
   * If accessTokenProps is not provided, these props will also be used for the current access token.
   * If not provided, the original props will be used.
   */
  newProps?: Props;

  /**
   * Override the default access token TTL (time-to-live) for this specific token.
   * This is especially useful when the application is also an OAuth client to another service
   * and wants to match its access token TTL to the upstream access token TTL.
   * Value should be in seconds.
   */
  accessTokenTTL?: number;

  /**
   * Override the default refresh token TTL (time-to-live) for this specific grant.
   * Value should be in seconds.
   * Note: This is only honored during authorization code exchange. If returned during
   * refresh token exchange, it will be ignored.
   */
  refreshTokenTTL?: number;

  /**
   * Optional scopes for the new access token. Values outside the scope ceiling
   * for the current grant flow are ignored. If omitted, the effective requested
   * scopes are used.
   */
  accessTokenScope?: string[];

  /**
   * Permit a token exchange whose authenticated client differs from the client the
   * subject token's grant was issued to. Cross-client exchange is rejected with
   * `invalid_request` unless the callback returns `true` here, so impersonation
   * across clients is always a deliberate policy decision.
   */
  allowCrossClientExchange?: boolean;
}

/**
 * Options for token exchange callback functions
 */
export interface TokenExchangeCallbackOptions<Props = any> {
  /**
   * The type of grant being processed.
   */
  grantType: GrantType;

  /**
   * Client authenticated on this token request. For `authorization_code` and
   * `refresh_token` it is always the grant's client. For token exchange it is the
   * exchanging client, which may differ from {@link subjectClientId}.
   */
  clientId: string;

  /**
   * Client the underlying grant was issued to. Equal to `clientId` except during a
   * cross-client token exchange, which the callback must explicitly allow with
   * {@link TokenExchangeCallbackResult.allowCrossClientExchange}.
   */
  subjectClientId: string;

  /**
   * User who authorized this grant
   */
  userId: string;

  /**
   * Identifier of the grant record this callback is operating on. Stable across
   * refreshes for the lifetime of the grant. Pass this together with `userId`
   * to {@link OAuthHelpers.revokeGrant} when the callback decides the grant
   * should be torn down (for example, after an upstream refresh fails with a
   * terminal error code).
   */
  grantId: string;

  /**
   * List of scopes on the underlying authorization grant.
   */
  scope: string[];

  /**
   * Effective scopes selected for this token before applying the callback result.
   */
  requestedScope: string[];

  /** Canonical protected resource selected for this grant and token. */
  resource: string;

  /**
   * Application-specific properties currently associated with this grant
   */
  props: Props;
}

/**
 * Options for the client registration callback (RFC 7591).
 */
export interface ClientRegistrationCallbackOptions {
  /**
   * Parsed client metadata from the registration request body.
   *
   * Note: This is the raw JSON body. RFC 7591 §3.1.1 `software_statement` claims
   * are NOT currently merged in by the library — if `software_statement` is present
   * the callback is responsible for verifying the JWT and applying its claims.
   */
  clientMetadata: Record<string, unknown>;
  /**
   * A clone of the registration HTTP request. The body has not been consumed,
   * so the callback may call `request.text()` / `request.json()` if needed
   * (e.g. to validate a signature over the raw body).
   */
  request: Request;
}

/**
 * Result of the client registration callback.
 *
 * Return `undefined`/nothing to allow registration. Return an object to reject
 * registration. By default, rejection follows RFC 7591 §3.2.2:
 * `invalid_client_metadata` with HTTP 400.
 */
export interface ClientRegistrationCallbackResult {
  /**
   * OAuth error code when rejecting. Defaults to `invalid_client_metadata`.
   * For non-metadata rejections (e.g. missing initial access token, untrusted
   * origin), set this to a more specific code such as `access_denied` or
   * `invalid_token`.
   */
  code?: string;
  /** Error description when rejecting. */
  description?: string;
  /**
   * HTTP status code when rejecting. Defaults to 400. Override for auth-style
   * failures (e.g. 401 for missing IAT, 403 for policy denial).
   */
  status?: number;
}

/**
 * Input parameters for the resolveExternalToken callback function
 */
export interface ResolveExternalTokenInput<Env = Cloudflare.Env> {
  /**
   * The token string that was provided in the Authorization header
   */
  token: string;

  /**
   * The original HTTP request
   */
  request: Request;

  /**
   * Cloudflare Worker environment variables
   */
  env: Env;
}

/**
 * Result returned from the resolveExternalToken callback function
 */
export interface ResolveExternalTokenResult {
  /**
   * Application-specific properties that will be passed to the API handlers.
   * These properties are set in the execution context (`ctx.props`) after the
   * external bearer credential is validated.
   */
  props: any;

  /**
   * Protected resource audience established by the external validator.
   *
   * A JWT may carry this value as an `aud` claim. For an opaque API token or
   * PAT, the callback can supply the local resource URI as policy after
   * successful validation. This value is required and must identify the
   * configured canonical `resourceMetadata.resource`: ASCII case in the scheme
   * and host is folded and an empty path equals `/`, while port, path, query,
   * and trailing slash are compared exactly.
   */
  audience: string;
}

/** RFC 9728 metadata owned by one protected resource server. */
export interface OAuthProtectedResourceMetadata {
  /**
   * The protected resource identifier HTTPS URL (RFC 9728 `resource` field).
   * Configure an RFC 3986-safe HTTPS producer URL with lowercase scheme/host
   * and no userinfo, default port, fragment, or dot segments.
   */
  resource: string;

  /**
   * Authorization server issuers that can issue tokens for this resource.
   * In the legacy combined configuration this defaults to the token endpoint
   * origin. In the role-based configuration it defaults to the configured AS
   * issuer.
   */
  authorization_servers?: string[];

  /** Minimal scopes required for basic protected-resource functionality. */
  scopes_supported?: string[];

  /** Methods by which bearer tokens can be presented. Defaults to `["header"]`. */
  bearer_methods_supported?: string[];

  /** Human-readable name for this resource. */
  resource_name?: string;
}

/**
 * Existing combined authorization-server and protected-resource configuration.
 * This shape remains supported in 1.0 and is normalized to a one-resource
 * role-based provider internally.
 */
export interface OAuthProviderOptions<Env = Cloudflare.Env> {
  /**
   * URL(s) for API routes. Requests with URLs starting with any of these prefixes
   * will be treated as API requests and require a valid access token.
   * Can be a single route or an array of routes. Each route can be a full URL or just a path.
   *
   * Used with `apiHandler` for the single-handler configuration. This is incompatible with
   * the `apiHandlers` property. You must use either `apiRoute` + `apiHandler` OR `apiHandlers`, not both.
   */
  apiRoute?: string | string[];

  /**
   * Handler for API requests that have a valid access token.
   * This handler will receive the authenticated user properties in ctx.props.
   * Can be either an ExportedHandler object with a fetch method or a class extending WorkerEntrypoint.
   *
   * Used with `apiRoute` for the single-handler configuration. This is incompatible with
   * the `apiHandlers` property. You must use either `apiRoute` + `apiHandler` OR `apiHandlers`, not both.
   */
  apiHandler?:
    | ExportedHandlerWithFetch<Env>
    | (new (ctx: ExecutionContext, env: Env) => WorkerEntrypointWithFetch<Env>);

  /**
   * Map of API routes to their corresponding handlers for the multi-handler configuration.
   * The keys are the API routes (strings only, not arrays), and the values are the handlers.
   * Each route can be a full URL or just a path, and each handler can be either an ExportedHandler
   * object with a fetch method or a class extending WorkerEntrypoint.
   *
   * This is incompatible with the `apiRoute` and `apiHandler` properties. You must use either
   * `apiRoute` + `apiHandler` (single-handler configuration) OR `apiHandlers` (multi-handler
   * configuration), not both.
   */
  apiHandlers?: Record<
    string,
    ExportedHandlerWithFetch<Env> | (new (ctx: ExecutionContext, env: Env) => WorkerEntrypointWithFetch<Env>)
  >;

  /**
   * Handler for all non-API requests or API requests without a valid token.
   * Can be either an ExportedHandler object with a fetch method or a class extending WorkerEntrypoint.
   */
  defaultHandler: ExportedHandler<Env> | (new (ctx: ExecutionContext, env: Env) => WorkerEntrypointWithFetch<Env>);

  /**
   * URL of the OAuth authorization endpoint where users can grant permissions.
   * This URL is used in OAuth metadata and is not handled by the provider itself.
   */
  authorizeEndpoint: string;

  /**
   * URL of the token endpoint which the provider will implement.
   * This endpoint handles token issuance, refresh, and revocation.
   */
  tokenEndpoint: string;

  /**
   * Optional URL for the client registration endpoint.
   * If provided, the provider will implement dynamic client registration.
   */
  clientRegistrationEndpoint?: string;

  /**
   * Time-to-live for access tokens in seconds.
   * Defaults to 1 hour (3600 seconds) if not specified.
   */
  accessTokenTTL?: number;

  /**
   * Time-to-live for refresh tokens in seconds.
   * Defaults to 30 days (2,592,000 seconds).
   * Set to 0 to disable refresh tokens entirely.
   * Set to `undefined` explicitly for refresh tokens that never expire.
   * For example: 3600 = 1 hour, 2592000 = 30 days
   */
  refreshTokenTTL?: number;

  /**
   * Time-to-live for dynamically registered clients in seconds.
   * Defaults to 90 days (7,776,000 seconds).
   * Clients created via the DCR endpoint will automatically expire after this duration.
   * Clients created via `OAuthHelpers.createClient()` are not affected by this setting.
   * Set to `undefined` explicitly for clients that never expire.
   */
  clientRegistrationTTL?: number;

  /**
   * Scopes supported by the authorization server.
   * These are advertised only in authorization server metadata; configure
   * `resourceMetadata.scopes_supported` separately for protected resource requirements.
   */
  scopesSupported?: string[];

  /**
   * Controls whether the OAuth implicit flow is allowed.
   * This flow is discouraged in OAuth 2.1 due to security concerns.
   * Defaults to false.
   */
  allowImplicitFlow?: boolean;

  /**
   * Controls whether the legacy plain PKCE method is allowed.
   * Defaults to false so PKCE challenges use S256 exclusively.
   * Set to true only for compatibility with clients that cannot use S256.
   */
  allowPlainPKCE?: boolean;

  /**
   * Controls whether OAuth 2.0 Token Exchange (RFC 8693) is allowed.
   * When false, the token exchange grant type will not be advertised in metadata
   * and token exchange requests will be rejected.
   * Defaults to false.
   */
  allowTokenExchangeGrant?: boolean;

  /**
   * Experimental support for the MCP Enterprise-Managed Authorization extension.
   * When enabled, the token endpoint accepts ID-JAG assertions using the JWT bearer
   * grant type (`urn:ietf:params:oauth:grant-type:jwt-bearer`).
   *
   * This feature is opt-in because the MCP extension and underlying OAuth drafts are
   * still evolving. Trusted issuers and a claim mapper are required.
   */
  enterpriseManagedAuthorization?: EmaOptions<Env>;

  /**
   * Controls whether public clients (clients without a secret, like SPAs) can register via the
   * dynamic client registration endpoint. When true, only confidential clients can register.
   * Note: Creating public clients via the OAuthHelpers.createClient() method is always allowed.
   * Defaults to false.
   */
  disallowPublicClientRegistration?: boolean;

  /**
   * Called during DCR (RFC 7591) before the client is stored. Return void/undefined
   * to allow registration, or return an object to reject it.
   */
  clientRegistrationCallback?: (
    options: ClientRegistrationCallbackOptions
  ) => Promise<ClientRegistrationCallbackResult | void> | ClientRegistrationCallbackResult | void;

  /**
   * Optional callback function that is called during token exchange.
   * This allows updating the props stored in both the access token and the grant.
   * For example, if the application itself is also a client to some other OAuth API,
   * it may want to perform the equivalent upstream token exchange, and store the result in the props.
   *
   * The callback can return new props values that will be stored with the token or grant.
   * If the callback returns nothing or undefined for a props field, the original props will be used.
   */
  tokenExchangeCallback?: (
    options: TokenExchangeCallbackOptions
  ) => Promise<TokenExchangeCallbackResult | void> | TokenExchangeCallbackResult | void;

  /**
   * Optional callback called when a provided bearer credential was not found
   * in the internal KV. It can validate an external OAuth access token, opaque
   * API token, personal access token (PAT), or another bearer credential and
   * set the application props passed to the protected handler.
   *
   * Return props to authenticate the request, or `null` for a generic `invalid_token` response.
   * Throw this package's exported {@link ExternalTokenError} to return an intentional
   * structured error response for an upstream validation failure.
   * All other thrown errors, including {@link OAuthError}, remain unexpected
   * failures and are re-thrown for backwards compatibility.
   */
  resolveExternalToken?: (input: ResolveExternalTokenInput<Env>) => Promise<ResolveExternalTokenResult | null>;

  /**
   * Optional callback function that is called whenever the OAuthProvider returns an error response.
   * This allows the client to emit notifications or perform other actions when an error occurs.
   *
   * If the function returns a Response, that will be used in place of the OAuthProvider's default one.
   *
   * `internal` (when present) carries a tagged, server-side-only reason that the library
   * deliberately did NOT put on the wire — used for richer diagnostics where the public
   * response must stay generic (e.g. JWT validation failures on the EMA path). Backwards
   * compatible: existing callbacks ignoring this field continue to work unchanged.
   *
   * `request` (when present) is the HTTP request that produced the error response, so the
   * callback can correlate the error with per-request state such as request-keyed telemetry.
   * Currently populated for CIMD metadata fetch failures at the token endpoint. Backwards
   * compatible in the same way as `internal`.
   */
  onError?: (error: {
    code: string;
    description: string;
    status: number;
    headers: Record<string, string>;
    internal?: { category: string; reason: string; detail?: unknown };
    request?: Request;
  }) => Response | void;

  /**
   * Explicitly enable Client ID Metadata Document (CIMD) support.
   * When true, URL-formatted client_ids will be fetched as metadata documents.
   * Requires the 'global_fetch_strictly_public' compatibility flag.
   * Defaults to false.
   */
  clientIdMetadataDocumentEnabled?: boolean;

  /**
   * Metadata for RFC 9728 OAuth 2.0 Protected Resource Metadata.
   * Controls the response served at /.well-known/oauth-protected-resource.
   */
  resourceMetadata: OAuthProtectedResourceMetadata;
}

/** The authorization-server role when one Worker hosts several MCP resources. */
interface OAuthAuthorizationServerConfiguration<Env = Cloudflare.Env> {
  /** Canonical RFC 8414 issuer. Its origin gates authorization-server routes. */
  issuer: string;

  /** Every canonical protected resource this authorization server issues tokens for. */
  resources: readonly string[];

  /** Authorization endpoint advertised by the AS. A path is resolved against `issuer`. */
  authorizeEndpoint: string;

  /** Token and revocation endpoint implemented by the provider. */
  tokenEndpoint: string;

  /** Optional dynamic client registration endpoint. */
  clientRegistrationEndpoint?: string;

  /** Optional RFC 9068 JWT access-token issuer created by `createJwtAccessTokens()`. */
  jwtAccessTokens?: InternalJwtAccessTokens<Env>;

  /** Functional policy selecting the format of each newly issued access token. */
  accessTokenFormat?: (input: AccessTokenFormatInput<Env>) => AccessTokenFormat | Promise<AccessTokenFormat>;

  /**
   * Resource selected when a new authorization request omits `resource`.
   * Omit this in a multi-resource deployment to require clients to choose.
   * A single-resource deployment automatically uses its sole resource.
   */
  defaultResource?: string;

  /**
   * Server-controlled destination for grants created before resource binding.
   * An unbound refresh token cannot choose a resource supplied by the client.
   * A single-resource deployment automatically uses its sole resource.
   */
  legacyGrantResource?: string;
}

/** Access-token representations supported by the authorization server. */
export type AccessTokenFormat = 'opaque' | 'jwt';

/** Immutable input passed to an access-token format policy before issuance. */
export interface AccessTokenFormatInput<Env = Cloudflare.Env> {
  readonly env: Env;
  readonly resource: string;
}

/** Internal input used when `protectResource()` registers one hosted role. */
interface InternalProtectedResourceConfiguration<Env = Cloudflare.Env> {
  resourceMetadata: OAuthProtectedResourceMetadata;
  handler:
    | ExportedHandlerWithFetch<Env, any>
    | (new (ctx: ExecutionContext, env: Env) => WorkerEntrypointWithFetch<Env, any>);
  resolveExternalToken?: (input: ResolveExternalTokenInput<Env>) => Promise<ResolveExternalTokenResult | null>;
}

/** Internal AS-only constructor shape behind the functional public API. */
type InternalOAuthAuthorizationServerOptions<Env = Cloudflare.Env> = Omit<
  OAuthProviderOptions<Env>,
  | 'apiRoute'
  | 'apiHandler'
  | 'apiHandlers'
  | 'authorizeEndpoint'
  | 'tokenEndpoint'
  | 'clientRegistrationEndpoint'
  | 'resourceMetadata'
> & {
  authorizationServer: OAuthAuthorizationServerConfiguration<Env>;
};

/**
 * Functional authorization-server surface used with `protectResource()`.
 * The application owns the interactive authorization route and uses
 * `getOAuthApi()` to parse and complete it; `fetch()` serves protocol-owned AS
 * endpoints such as metadata, token, revocation, and optional registration.
 */
export type OAuthAuthorizationServerOptions<Env = Cloudflare.Env, Props = any> = Omit<
  OAuthProviderOptions<Env>,
  | 'apiRoute'
  | 'apiHandler'
  | 'apiHandlers'
  | 'defaultHandler'
  | 'resourceMetadata'
  | 'resolveExternalToken'
  | 'tokenExchangeCallback'
> & {
  /** Canonical RFC 8414 issuer. */
  issuer: string;

  /**
   * Canonical identifiers of every protected resource this authorization server issues
   * tokens for, whether hosted in this Worker through `protectResource()` or by another
   * Worker or service. At least one is required. The registry is fixed at construction,
   * so `defaultResource`, `legacyGrantResource`, and `resource()` are checked before the
   * first request.
   */
  resources: readonly string[];

  /** Resource selected for a new authorization request that omits `resource`. */
  defaultResource?: string;

  /**
   * Migration destination for pre-resource grants and access tokens. Changing it
   * re-targets every surviving unbound record, so keep it fixed for the migration window.
   */
  legacyGrantResource?: string;

  /**
   * Installs RFC 9068 access-token signing and validation and publishes
   * `jwks_uri`. When configured, the authorization server accepts both its
   * valid JWT access tokens and compatible legacy opaque access tokens.
   *
   * This installs the reader, the signer and the JWKS; it does not change what is
   * issued. Set `accessTokenFormat` to start writing JWTs once every consumer can
   * validate them. Authorization codes and refresh tokens remain opaque.
   */
  jwtAccessTokens?: JwtAccessTokens<Env, Props>;

  /**
   * Selects the representation of each newly issued access token. This controls
   * issuance only: it does not restrict accepted token formats, rewrite existing
   * tokens, or change refresh-token format.
   *
   * Requires `jwtAccessTokens`. Without it, access tokens stay opaque. A thrown
   * error or invalid result fails issuance; the provider never silently
   * downgrades to opaque.
   */
  accessTokenFormat?: (input: AccessTokenFormatInput<Env>) => AccessTokenFormat | Promise<AccessTokenFormat>;

  /** Typed props refresh/exchange hook for this authorization server. */
  tokenExchangeCallback?: (
    options: TokenExchangeCallbackOptions<Props>
  ) => Promise<TokenExchangeCallbackResult<Props> | void> | TokenExchangeCallbackResult<Props> | void;
};

/** Options passed to `OAuthAuthorizationServer.protectResource()`. */
export interface ProtectResourceOptions<Env = Cloudflare.Env, Props = unknown> {
  resourceMetadata: OAuthProtectedResourceMetadata;
  handler:
    | ExportedHandlerWithFetch<Env, Props>
    | (new (ctx: ExecutionContext, env: Env) => WorkerEntrypointWithFetch<Env, Props>);
  resolveExternalToken?: (input: ResolveExternalTokenInput<Env>) => Promise<ResolveExternalTokenResult | null>;
}

/** A protected-resource fetch surface created by an authorization server. */
export interface OAuthProtectedResource<Env = Cloudflare.Env> {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response>;
}

/** Options for {@link OAuthResourceHandle.protect}; the resource comes from the handle. */
export interface ProtectResourceHandleOptions<Env = Cloudflare.Env, Props = unknown> {
  resourceMetadata?: Omit<OAuthProtectedResourceMetadata, 'resource'>;
  handler: ProtectResourceOptions<Env, Props>['handler'];
  resolveExternalToken?: ProtectResourceOptions<Env, Props>['resolveExternalToken'];
}

/**
 * One protected resource declared in `OAuthAuthorizationServerOptions.resources`.
 * Obtained from `OAuthAuthorizationServer.resource()`, so a misspelled identifier fails
 * at module initialization instead of on a request.
 */
export interface OAuthResourceHandle<Env = Cloudflare.Env, Props = any> {
  /** Canonical spelling of the declared resource identifier. */
  readonly resource: string;
  /**
   * Validate an opaque access token for this resource only. A separate Worker can call
   * this over a private Service Binding; the audience is fixed here, so the caller
   * cannot ask about another resource's tokens.
   */
  validateToken<T = any>(token: string, env: Env): Promise<ValidatedAccessToken<T> | null>;
  /** Host this resource in the same Worker and return its independently routable fetch surface. */
  protect<P = Props>(options: ProtectResourceHandleOptions<Env, P>): OAuthProtectedResource<Env>;
}

/** Audience-checked token context suitable for a private Service Binding. */
export interface ValidatedAccessToken<T = any> {
  props: T;
  audience: string;
  expiresAt: number;
  scope: string[];
  userId: string;
  clientId: string;
}

// Using ExportedHandler from Cloudflare Workers Types for both API and default handlers
// This is Cloudflare's built-in type for Workers handlers with a fetch method
// For ApiHandler, ctx will include ctx.props with user properties

/**
 * Helper methods for OAuth operations provided to handler functions
 */
export interface OAuthHelpers<Props = any> {
  /**
   * Parses an OAuth authorization request from the HTTP request
   * @param request - The HTTP request containing OAuth parameters
   * @returns The parsed authorization request parameters
   * @throws Error when the response type is missing, unsupported, or not registered for the client
   * @throws {@link CimdFetchError} when the client ID is a CIMD URL whose document cannot be resolved
   */
  parseAuthRequest(request: Request): Promise<AuthRequest>;

  /**
   * Looks up a client by its client ID
   * @param clientId - The client ID to look up
   * @returns A Promise resolving to the client info, or null if the client does not exist
   * @throws {@link CimdFetchError} when the client ID is a CIMD URL whose document cannot be resolved
   */
  lookupClient(clientId: string): Promise<ClientInfo | null>;

  /**
   * Completes an authorization request by creating a grant and authorization code
   * @param options - Options specifying the grant details
   * @returns A Promise resolving to an object containing the redirect URL
   * @throws Error when the request's response type is not permitted
   * @throws {@link CimdFetchError} when the client ID is a CIMD URL whose document cannot be resolved
   */
  completeAuthorization(options: CompleteAuthorizationOptions<Props>): Promise<{ redirectTo: string }>;

  /**
   * Creates a new OAuth client
   * @param clientInfo - Partial client information to create the client with
   * @returns A Promise resolving to the created client info
   */
  createClient(clientInfo: Partial<ClientInfo>): Promise<ClientInfo>;

  /**
   * Lists all registered OAuth clients with pagination support
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with items and optional cursor
   */
  listClients(options?: ListOptions): Promise<ListResult<ClientInfo>>;

  /**
   * Updates an existing OAuth client
   * @param clientId - The ID of the client to update
   * @param updates - Partial client information with fields to update
   * @returns A Promise resolving to the updated client info, or null if not found
   */
  updateClient(clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null>;

  /**
   * Deletes an OAuth client
   * @param clientId - The ID of the client to delete
   * @returns A Promise resolving when the deletion is confirmed.
   */
  deleteClient(clientId: string): Promise<void>;

  /**
   * Lists all authorization grants for a specific user with pagination support
   * Returns a summary of each grant without sensitive information
   * @param userId - The ID of the user whose grants to list
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with grant summaries and optional cursor
   */
  listUserGrants(userId: string, options?: ListOptions): Promise<ListResult<GrantSummary>>;

  /**
   * Revokes an authorization grant
   * @param grantId - The ID of the grant to revoke
   * @param userId - The ID of the user who owns the grant
   * @returns A Promise resolving when the revocation is confirmed.
   */
  revokeGrant(grantId: string, userId: string): Promise<void>;

  /**
   * Decodes a token and returns token data with decrypted props
   * @param token - The token
   * @returns Promise resolving to token data with decrypted props, or null if token is invalid
   */
  unwrapToken<T = any>(token: string): Promise<TokenSummary<T> | null>;

  /**
   * Exchanges an existing access token for a new one with modified characteristics
   * Implements OAuth 2.0 Token Exchange (RFC 8693)
   * @param options - Options for token exchange including subject token and optional modifications
   * @returns Promise resolving to token response with new access token
   * @throws {@link CimdFetchError} when the grant's client ID is a CIMD URL whose document cannot be resolved
   */
  exchangeToken(options: ExchangeTokenOptions): Promise<TokenResponse>;

  /**
   * Purges expired and orphaned data from the KV namespace.
   * Designed to be called from a scheduled handler (Cron Trigger) for periodic cleanup.
   * Processes records in configurable batches to stay within Cloudflare's subrequest limits.
   *
   * Performs two sweep phases:
   * 1. Grant sweep: removes orphaned grants (client deleted) and expired grants (defense-in-depth for KV TTL)
   * 2. Token sweep: removes orphaned tokens (grant deleted) as defense-in-depth
   *
   * Safe to call repeatedly — deleted records disappear from KV, so subsequent invocations
   * naturally process fresh records without needing a persisted cursor.
   *
   * @param options - Optional configuration for batch size and which purge types to enable
   * @returns Statistics about what was checked and purged, and whether the full scan completed
   */
  purgeExpiredData(options?: PurgeOptions): Promise<PurgeResult>;
}

/**
 * Options for token exchange operations (RFC 8693)
 */
export interface ExchangeTokenOptions {
  /**
   * The subject token to exchange (existing access token)
   */
  subjectToken: string;

  /**
   * Optional requested scopes for the new token. Issued scopes are limited to the subject token's scopes.
   */
  scope?: string[];

  /**
   * Optional canonical target audience/resource for the new token (maps to the
   * resource parameter per RFC 8707). When present, it must match the
   * provider's configured resource.
   */
  aud?: string;

  /**
   * Optional TTL override for the new token in seconds (must not exceed subject token's remaining lifetime)
   */
  expiresIn?: number;
}

/**
 * Parsed OAuth authorization request parameters
 */
export interface AuthRequest {
  /**
   * OAuth response type (e.g., "code" for authorization code flow)
   */
  responseType: string;

  /**
   * Client identifier for the OAuth client
   */
  clientId: string;

  /**
   * URL to redirect to after authorization
   */
  redirectUri: string;

  /**
   * Array of requested permission scopes
   */
  scope: string[];

  /**
   * Client state value to be returned in the redirect
   */
  state: string;

  /**
   * PKCE code challenge (RFC 7636)
   */
  codeChallenge?: string;

  /**
   * PKCE code challenge method (plain or S256)
   */
  codeChallengeMethod?: string;

  /**
   * Canonical target resource (RFC 8707). Parsed authorization requests
   * always contain the provider's configured resource.
   */
  resource?: string;

  /**
   * Authorization server issuer recorded while parsing this request.
   * Include it as `iss` in successful and error authorization responses.
   */
  issuer?: string;
}

/**
 * OAuth client registration information
 */
export interface ClientInfo {
  /**
   * Unique identifier for the client
   */
  clientId: string;

  /**
   * Secret used to authenticate the client (stored as a hash)
   * Only present for confidential clients; undefined for public clients.
   */
  clientSecret?: string;

  /**
   * List of allowed redirect URIs for the client
   */
  redirectUris: string[];

  /**
   * Human-readable name of the client application
   */
  clientName?: string;

  /**
   * URL to the client's logo
   */
  logoUri?: string;

  /**
   * URL to the client's homepage
   */
  clientUri?: string;

  /**
   * URL to the client's privacy policy
   */
  policyUri?: string;

  /**
   * URL to the client's terms of service
   */
  tosUri?: string;

  /**
   * URL to the client's JSON Web Key Set for validating signatures
   */
  jwksUri?: string;

  /**
   * RFC 7591 §2.2 internationalized variants of the human-readable client
   * metadata fields, keyed by the raw member name including its BCP 47 language
   * tag (e.g. `"client_name#ja"`, `"tos_uri#fr"`).
   *
   * Only the human-readable fields the RFC names are captured here:
   * `client_name`, `client_uri`, `logo_uri`, `tos_uri`, and `policy_uri`.
   * The canonical (un-tagged) values continue to live in their own typed
   * fields above; this map holds only the locale-specific variants so that
   * consumers can perform their own locale selection.
   */
  i18n?: Record<string, string>;

  /**
   * List of email addresses for contacting the client developers
   */
  contacts?: string[];

  /**
   * List of grant types the client supports
   */
  grantTypes?: string[];

  /**
   * List of response types the client supports
   */
  responseTypes?: string[];

  /**
   * Unix timestamp when the client was registered
   */
  registrationDate?: number;

  /**
   * The authentication method used by the client at the token endpoint.
   * Values include:
   * - 'client_secret_basic': Uses HTTP Basic Auth with client ID and secret (default for confidential clients)
   * - 'client_secret_post': Uses POST parameters for client authentication
   * - 'none': Used for public clients that can't securely store secrets (SPAs, mobile apps, etc.)
   *
   * Public clients use 'none', while confidential clients use either 'client_secret_basic' or 'client_secret_post'.
   */
  tokenEndpointAuthMethod: string;
}

interface StoredClientInfo extends ClientInfo {
  /** Present only when tokenEndpointAuthMethod was explicitly selected. */
  authMethodExplicit?: true;
}

function toPublicClientInfo(client: StoredClientInfo): ClientInfo {
  const { authMethodExplicit: _explicit, ...publicClient } = client;
  return publicClient;
}

function isClientAuthMethodAllowed(
  client: StoredClientInfo,
  presentedMethod: string,
  isClientMetadataDocument: boolean
): boolean {
  if (presentedMethod === client.tokenEndpointAuthMethod) return true;

  const isSecretMethod = (method: string): boolean =>
    method === 'client_secret_basic' || method === 'client_secret_post';
  return (
    !isClientMetadataDocument &&
    client.authMethodExplicit === undefined &&
    isSecretMethod(client.tokenEndpointAuthMethod) &&
    isSecretMethod(presentedMethod)
  );
}

/**
 * Options for completing an authorization request
 */
export interface CompleteAuthorizationOptions<Props = any> {
  /**
   * The original parsed authorization request
   */
  request: AuthRequest;

  /**
   * Identifier for the user granting the authorization
   */
  userId: string;

  /**
   * Application-specific metadata to associate with this grant
   */
  metadata: any;

  /**
   * List of scopes that were actually granted (may differ from requested scopes)
   */
  scope: string[];

  /**
   * Application-specific properties to include with API requests
   * authorized by this grant
   */
  props: Props;

  /**
   * Revokes all existing grants for this user+client combination
   * after storing the new grant. Defaults to true. This prevents stale
   * tokens from causing infinite re-auth loops when props change.
   * Set to false to allow multiple concurrent grants per user+client.
   */
  revokeExistingGrants?: boolean;

  /**
   * Maximum number of grants to fetch per page when revoking existing
   * grants. Only used when revokeExistingGrants is not false.
   * Must be a positive integer. Values above Cloudflare KV's 1000-key page
   * limit are clamped to 1000. Defaults to 50.
   */
  revokeExistingGrantsBatchSize?: number;
}

/**
 * Authorization grant record
 */
export interface Grant {
  /**
   * Unique identifier for the grant
   */
  id: string;

  /**
   * Client that received this grant
   */
  clientId: string;

  /**
   * User who authorized this grant
   */
  userId: string;

  /**
   * List of scopes that were granted
   */
  scope: string[];

  /**
   * Application-specific metadata associated with this grant
   */
  metadata: any;

  /**
   * Encrypted application-specific properties
   */
  encryptedProps: string;

  /**
   * Unix timestamp when the grant was created
   */
  createdAt: number;

  /**
   * Unix timestamp when the grant expires (if TTL is configured)
   */
  expiresAt?: number;

  /**
   * The hash of the current refresh token associated with this grant
   */
  refreshTokenId?: string;

  /**
   * Wrapped encryption key for the current refresh token
   */
  refreshTokenWrappedKey?: string;

  /**
   * The hash of the previous refresh token associated with this grant
   * This token is still valid until the new token is first used
   */
  previousRefreshTokenId?: string;

  /**
   * Wrapped encryption key for the previous refresh token
   */
  previousRefreshTokenWrappedKey?: string;

  /**
   * The hash of the authorization code associated with this grant
   * Retained after exchange so that a replay of the same code can be
   * verified before any action is taken on the grant. The code is
   * considered already exchanged once authCodeWrappedKey is removed.
   */
  authCodeId?: string;

  /**
   * Wrapped encryption key for the authorization code
   * Present only until the authorization code is exchanged; its absence
   * (with authCodeId still set) marks the code as already used.
   */
  authCodeWrappedKey?: string;

  /**
   * PKCE code challenge for this authorization
   * Only present during the authorization code exchange process
   */
  codeChallenge?: string;

  /**
   * PKCE code challenge method (plain or S256)
   * Only present during the authorization code exchange process
   */
  codeChallengeMethod?: string;

  /**
   * Resource parameter from authorization request (RFC 8707 Section 2.1)
   * Indicates the protected resource(s) for which access is requested
   */
  resource?: string | string[];

  /**
   * The exact redirect URI used in the authorization request that created this grant
   * Recorded so that default grant revocation can be scoped to a single installation
   * of a CIMD client (whose client_id is shared across all installations). Absent on
   * grants created before this field was introduced.
   */
  redirectUri?: string;
}

/**
 * OAuth 2.0 Token Response
 * The response returned when exchanging authorization codes or refresh tokens
 */
interface TokenResponse {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
  refresh_token?: string;
  scope: string;
  /**
   * Resource indicator(s) for the issued access token (RFC 8707 Section 2.2)
   * SHOULD be included to indicate the resource server(s) for which the token is valid
   */
  resource: string;
}

/**
 * Shared fields for Token and TokenSummary
 */
export interface TokenBase {
  /**
   * Unique identifier for the token (hash of the actual token)
   */
  id: string;

  /**
   * Identifier of the grant this token is associated with
   */
  grantId: string;

  /**
   * User ID associated with this token
   */
  userId: string;

  /**
   * Unix timestamp when the token was created
   */
  createdAt: number;

  /**
   * Unix timestamp when the token expires
   */
  expiresAt: number;

  /**
   * Intended audience for this token (RFC 7519 Section 4.1.3)
   * Can be a single string or array of strings
   */
  audience?: string | string[];

  /**
   * List of scopes on this token
   */
  scope: string[];

  /**
   * Access-token representation. Absence means the opaque representation.
   */
  format?: 'jwt';

  /**
   * JWT ID for RFC 9068 access tokens. Absent on opaque tokens.
   */
  jti?: string;
}

/**
 * Token record stored in KV.
 * Opaque access tokens use "{userId}:{grantId}:{random-secret}". An
 * authorization server can return a signed JWT instead according to its
 * access-token format policy.
 * Both representations store only the hash of the complete token string.
 * This contains only access tokens; refresh tokens are stored within the grant records.
 */
export interface Token extends TokenBase {
  /**
   * The encryption key for props, wrapped with this token
   */
  wrappedEncryptionKey: string;

  /**
   * Denormalized token authorization information for faster access
   */
  grant: {
    /**
     * Client that received this token
     */
    clientId: string;

    /**
     * List of scopes that were granted
     */
    scope: string[];

    /**
     * Encrypted application-specific properties
     */
    encryptedProps: string;
  };
}

/**
 * Token record with decrypted properties
 * Derived from Token but with wrappedEncryptionKey removed and encryptedProps replaced with props
 */
export interface TokenSummary<T = any> extends TokenBase {
  /**
   * Denormalized token authorization information for faster access
   */
  grant: {
    /**
     * Client that received this token
     */
    clientId: string;

    /**
     * List of scopes that were granted
     */
    scope: string[];

    /**
     * Decrypted application-specific properties
     */
    props: T;
  };
}

/**
 * Options for listing operations that support pagination
 */
export interface ListOptions {
  /**
   * Maximum number of items to return (max 1000)
   */
  limit?: number;

  /**
   * Cursor for pagination (from a previous listing operation)
   */
  cursor?: string;
}

/**
 * Result of a listing operation with pagination support
 */
export interface ListResult<T> {
  /**
   * The list of items
   */
  items: T[];

  /**
   * Cursor to get the next page of results, if there are more results
   */
  cursor?: string;
}

/**
 * Options for the purgeExpiredData garbage collection method
 */
export interface PurgeOptions {
  /**
   * Maximum number of KV keys to check per phase (grants and tokens) per invocation.
   * Each phase (grant sweep, token sweep) gets its own budget of this size.
   * Keep this conservative to stay within Cloudflare's 1000 subrequest limit per invocation,
   * since each checked key requires at least one KV read, and orphaned grants trigger
   * additional KV operations via revokeGrant().
   * Defaults to 50.
   */
  batchSize?: number;

  /**
   * Whether to purge orphaned grants whose client no longer exists in KV.
   * Grants for CIMD (Client ID Metadata Document) clients are always skipped
   * since those clients are not stored in KV.
   * Defaults to true.
   */
  purgeOrphanedGrants?: boolean;

  /**
   * Whether to purge expired grants as defense-in-depth for KV TTL.
   * Normally KV auto-deletes expired entries, but this catches any stragglers.
   * Defaults to true.
   */
  purgeExpiredGrants?: boolean;

  /**
   * Whether to purge orphaned tokens whose grant no longer exists.
   * Tokens already auto-expire via KV TTL (default 1 hour), so this is
   * defense-in-depth for partial revokeGrant() failures.
   * Defaults to true.
   */
  purgeOrphanedTokens?: boolean;
}

/**
 * Result of a purgeExpiredData garbage collection invocation
 */
export interface PurgeResult {
  /** Number of grant records checked in this invocation */
  grantsChecked: number;

  /** Number of grant records purged (orphaned or expired) */
  grantsPurged: number;

  /** Number of token records checked in this invocation */
  tokensChecked: number;

  /** Number of token records purged (orphaned) */
  tokensPurged: number;

  /** True if the full key space was scanned in this invocation (both grants and tokens) */
  done: boolean;
}

/**
 * Public representation of a grant, with sensitive data removed
 * Used for list operations where the complete grant data isn't needed
 */
export interface GrantSummary {
  /**
   * Unique identifier for the grant
   */
  id: string;

  /**
   * Client that received this grant
   */
  clientId: string;

  /**
   * User who authorized this grant
   */
  userId: string;

  /**
   * List of scopes that were granted
   */
  scope: string[];

  /**
   * Application-specific metadata associated with this grant
   */
  metadata: any;

  /**
   * Unix timestamp when the grant was created
   */
  createdAt: number;

  /**
   * Unix timestamp when the grant expires (if TTL is configured)
   */
  expiresAt?: number;

  /**
   * The exact redirect URI used in the authorization request that created this grant
   * Recorded so that default grant revocation can be scoped to a single installation
   * of a CIMD client (whose client_id is shared across all installations). Absent on
   * grants created before this field was introduced.
   */
  redirectUri?: string;
  /** Canonical protected resource, absent only on a pre-resource legacy grant. */
  resource?: string | string[];
}

/**
 * Options for creating an access token
 */
/** An access token built by `prepareAccessToken()` but not yet written to KV. */
interface PreparedAccessToken {
  accessToken: string;
  tokenKey: string;
  tokenData: Token;
  expiresIn: number;
}

interface CreateAccessTokenOptions<Env = Cloudflare.Env> {
  /** Prevalidated access-token representation selected before grant mutation. */
  format: AccessTokenFormat;

  /**
   * User ID
   */
  userId: string;

  /**
   * Grant ID
   */
  grantId: string;

  /**
   * Client ID
   */
  clientId: string;

  /**
   * Token scopes
   */
  scope: string[];

  /**
   * Scope of the underlying authorization grant, denormalized onto the token record and
   * surfaced as `TokenSummary.grant.scope` and `TokenExchangeCallbackOptions.scope`.
   * Defaults to `scope`, which is only correct when this token carries the whole grant.
   */
  grantScope?: string[];

  /**
   * Clock read to stamp the record with. Callers that already clamped `expiresIn` against
   * a grant's remaining lifetime pass the same read they clamped with, so the token cannot
   * be recorded as outliving that grant. Defaults to a fresh read.
   */
  issuedAt?: number;

  /**
   * Encrypted props for the token
   */
  encryptedProps: string;

  /**
   * Encryption key for the props
   */
  encryptionKey: CryptoKey;

  /**
   * TTL for the access token in seconds
   */
  expiresIn: number;

  /**
   * Canonical audience/resource
   */
  audience: string;

  /**
   * Cloudflare Worker environment variables
   */
  env: Env & ProviderEnv;
}

interface AccessTokenResolution {
  /** Stored record after all representation-specific checks have passed. */
  tokenData: Token | null;

  /**
   * Whether this credential identifies itself as one of this issuer's JWTs.
   * Invalid issuer-owned JWTs fail closed instead of reaching an external resolver.
   */
  isOwnJwt: boolean;
}

type JwtAudienceSource = 'registered-resource' | 'token-audience';

type InternalOAuthProviderOptions<Env> = Omit<OAuthProviderOptions<Env>, 'resourceMetadata'> & {
  resourceMetadata?: OAuthProtectedResourceMetadata;
};

interface NormalizedResourceServer<Env> {
  resourceMetadata: OAuthProtectedResourceMetadata;
  apiHandler?: TypedHandler<Env>;
  resolveExternalToken?: (input: ResolveExternalTokenInput<Env>) => Promise<ResolveExternalTokenResult | null>;
}

interface NormalizedApiRoute<Env> {
  route: string;
  handler: TypedHandler<Env>;
  resourceServer: NormalizedResourceServer<Env>;
}

/**
 * OAuth 2.0 Provider implementation for Cloudflare Workers
 * Implements authorization code flow with support for refresh tokens
 * and dynamic client registration.
 */
export class OAuthProvider<Env = Cloudflare.Env> {
  #impl: OAuthProviderImpl<Env>;

  /**
   * Creates a new OAuth provider instance
   * @param options - Configuration options for the provider
   */
  constructor(options: OAuthProviderOptions<Env>) {
    this.#impl = new OAuthProviderImpl<Env>(options);
  }

  /**
   * Main fetch handler for the Worker
   * Routes requests to the appropriate handler based on the URL
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @param ctx - Cloudflare Worker execution context
   * @returns A Promise resolving to an HTTP Response
   */
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return this.#impl.fetch(request, env as Env & ProviderEnv, ctx);
  }

  /**
   * Purges expired and orphaned data from the KV namespace.
   * Can be called directly from a scheduled handler without needing a request context.
   *
   * @param env - Cloudflare Worker environment variables (must include OAUTH_KV binding)
   * @param options - Optional configuration for batch size and which purge types to enable
   * @returns Statistics about what was checked and purged
   */
  purgeExpiredData(env: Env, options?: PurgeOptions): Promise<PurgeResult> {
    return this.#impl.createOAuthHelpers(env as Env & ProviderEnv).purgeExpiredData(options);
  }
}

/**
 * Authorization-server role that can functionally compose multiple protected
 * MCP resources in the same Worker. The application keeps control of routing
 * by dispatching requests to this object or to the handles returned by
 * `protectResource()`.
 */
export class OAuthAuthorizationServer<Env = Cloudflare.Env, Props = any> {
  #impl: OAuthProviderImpl<Env>;

  constructor(options: OAuthAuthorizationServerOptions<Env, Props>) {
    const {
      issuer,
      resources,
      defaultResource,
      legacyGrantResource,
      authorizeEndpoint,
      tokenEndpoint,
      clientRegistrationEndpoint,
      jwtAccessTokens,
      accessTokenFormat,
      ...commonOptions
    } = options;
    this.#impl = new OAuthProviderImpl<Env>({
      ...commonOptions,
      defaultHandler: {
        fetch: () => new Response(null, { status: 404 }),
      },
      authorizationServer: {
        issuer,
        resources,
        authorizeEndpoint,
        tokenEndpoint,
        clientRegistrationEndpoint,
        jwtAccessTokens,
        accessTokenFormat,
        defaultResource,
        legacyGrantResource,
      },
    });
  }

  /**
   * A handle for one resource declared in `resources`. Throws at module initialization
   * when the identifier was not declared.
   */
  resource(resource: string): OAuthResourceHandle<Env, Props> {
    const canonical = this.#impl.requireDeclaredResource(resource);
    return {
      resource: canonical,
      validateToken: <T = any>(token: string, env: Env) =>
        this.#impl.validateAccessToken<T>(token, canonical, env as Env & ProviderEnv),
      protect: <P = Props>(options: ProtectResourceHandleOptions<Env, P>) =>
        this.protectResource<P>({
          resourceMetadata: { ...(options.resourceMetadata ?? {}), resource: canonical },
          handler: options.handler,
          resolveExternalToken: options.resolveExternalToken,
        }),
    };
  }

  /** Host one declared resource in this Worker and return its independently routable RS surface. */
  protectResource<P = Props>(options: ProtectResourceOptions<Env, P>): OAuthProtectedResource<Env> {
    const resource = this.#impl.registerResourceServer({
      resourceMetadata: options.resourceMetadata,
      handler: options.handler,
      resolveExternalToken: options.resolveExternalToken,
    });
    return {
      fetch: (request, env, ctx) => this.#impl.fetchResourceServer(request, env as Env & ProviderEnv, ctx, resource),
    };
  }

  /** Serve protocol-owned authorization-server endpoints, excluding the application authorization UI. */
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return this.#impl.fetchAuthorizationServer(request, env as Env & ProviderEnv, ctx);
  }

  /** Obtain helpers for scheduled jobs or custom code outside a fetch dispatch. */
  getOAuthApi(env: Env): OAuthHelpers<Props> {
    return this.#impl.createOAuthHelpers<Props>(env as Env & ProviderEnv);
  }

  purgeExpiredData(env: Env, options?: PurgeOptions): Promise<PurgeResult> {
    return this.#impl.createOAuthHelpers(env as Env & ProviderEnv).purgeExpiredData(options);
  }
}

/**
 * Gets OAuthHelpers for the given environment
 * @param options - Configuration options for the OAuth provider
 * @param env - Cloudflare Worker environment variables
 * @returns An instance of OAuthHelpers
 */
export function getOAuthApi<Env = Cloudflare.Env>(options: OAuthProviderOptions<Env>, env: Env): OAuthHelpers {
  const impl = new OAuthProviderImpl<Env>(options);
  return impl.createOAuthHelpers(env as Env & ProviderEnv);
}

/**
 * Implementation class backing OAuthProvider.
 *
 * We use a PImpl pattern in `OAuthProvider` to make sure we don't inadvertently export any private
 * methods over RPC. Unfortunately, declaring a method "private" in TypeScript is merely a type
 * annotation, and does not actually prevent the method from being called from outside the class,
 * including over RPC.
 */
class OAuthProviderImpl<Env = Cloudflare.Env> {
  /**
   * Configuration options for the provider
   */
  options: InternalOAuthProviderOptions<Env>;

  /** Explicit issuer used by the role-based multi-resource configuration. */
  private readonly explicitIssuer: string | undefined;

  /** Optional RFC 9068 access-token component for the role-based AS. */
  private readonly jwtAccessTokens: InternalJwtAccessTokens<Env> | undefined;

  /** Optional reader-first rollout policy for newly issued access tokens. */
  private readonly accessTokenFormatPolicy:
    | ((input: AccessTokenFormatInput<Env>) => AccessTokenFormat | Promise<AccessTokenFormat>)
    | undefined;

  /** Every protected-resource role hosted by this provider. */
  private readonly resourceServers: NormalizedResourceServer<Env>[];

  /** Resource chosen when a new authorization request omits RFC 8707 `resource`. */
  private readonly configuredDefaultAuthorizationResource: string | undefined;

  /** Server-controlled migration destination for pre-resource grants. */
  private readonly configuredLegacyGrantResource: string | undefined;

  /**
   * Represents the validated type of a handler (ExportedHandler or WorkerEntrypoint)
   */
  private typedDefaultHandler: TypedHandler<Env>;

  /**
   * Array of tuples of API routes and their validated handlers
   * In the simple case, this will be a single entry with the route and handler from options.apiRoute/apiHandler
   * In the advanced case, this will contain entries from options.apiHandlers
   */
  private typedApiHandlers: NormalizedApiRoute<Env>[];

  /** Capabilities shared by discovery and client metadata validation. */
  readonly serverCapabilities: OAuthServerCapabilities;

  /** In-memory cached IdP JWKS fetcher; only constructed when EMA is configured. */
  private readonly jwksProvider: EmaJwksProvider | undefined;

  /** KV-backed best-effort `jti` replay store; only constructed when EMA is configured. */
  private readonly jtiStore: EmaJtiStore | undefined;

  /**
   * Creates a new OAuth provider instance
   * @param options - Configuration options for the provider
   */
  constructor(options: OAuthProviderOptions<Env> | InternalOAuthAuthorizationServerOptions<Env>) {
    this.typedApiHandlers = [];
    this.typedDefaultHandler = this.validateHandler(options.defaultHandler, 'defaultHandler');

    const roleBased = 'authorizationServer' in options;
    if (!roleBased && 'resourceMatchOriginOnly' in (options as unknown as Record<string, unknown>)) {
      throw new TypeError(
        'resourceMatchOriginOnly was removed in 1.0. Configure resourceMetadata.resource; audiences are compared exactly against that canonical resource. See the migration guide.'
      );
    }
    let normalizedOptions: InternalOAuthProviderOptions<Env>;
    let configuredResourceServers: Array<{
      resourceMetadata: OAuthProtectedResourceMetadata;
      resolveExternalToken?: InternalProtectedResourceConfiguration<Env>['resolveExternalToken'];
    }>;

    if (roleBased) {
      const { authorizationServer, ...commonOptions } = options;
      this.validateAuthorizationServerIssuer(authorizationServer.issuer);
      this.explicitIssuer = authorizationServer.issuer;
      this.jwtAccessTokens = authorizationServer.jwtAccessTokens;
      this.accessTokenFormatPolicy = authorizationServer.accessTokenFormat;
      if (this.accessTokenFormatPolicy !== undefined && typeof this.accessTokenFormatPolicy !== 'function') {
        throw new TypeError('accessTokenFormat must be a function');
      }
      if (this.accessTokenFormatPolicy && !this.jwtAccessTokens) {
        throw new TypeError('accessTokenFormat requires jwtAccessTokens');
      }
      if (this.jwtAccessTokens && this.jwtAccessTokens.issuer !== authorizationServer.issuer) {
        throw new TypeError('jwtAccessTokens issuer must exactly match authorizationServer.issuer');
      }
      if (this.jwtAccessTokens) jwtInternals(this.jwtAccessTokens);
      normalizedOptions = {
        ...(commonOptions as Omit<InternalOAuthProviderOptions<Env>, 'authorizeEndpoint' | 'tokenEndpoint'>),
        authorizeEndpoint: authorizationServer.authorizeEndpoint,
        tokenEndpoint: authorizationServer.tokenEndpoint,
        clientRegistrationEndpoint: authorizationServer.clientRegistrationEndpoint,
      };
      const declared = authorizationServer.resources;
      if (!Array.isArray(declared) || declared.length === 0 || declared.some((value) => typeof value !== 'string')) {
        throw new TypeError('resources must list at least one canonical protected resource identifier');
      }
      configuredResourceServers = declared.map((resource) => ({ resourceMetadata: { resource } }));
    } else {
      this.explicitIssuer = undefined;
      this.jwtAccessTokens = undefined;
      this.accessTokenFormatPolicy = undefined;
      normalizedOptions = options;
      configuredResourceServers = [
        {
          resourceMetadata: options.resourceMetadata,
          resolveExternalToken: options.resolveExternalToken,
        },
      ];
    }

    this.options = {
      accessTokenTTL: DEFAULT_ACCESS_TOKEN_TTL,
      refreshTokenTTL: DEFAULT_REFRESH_TOKEN_TTL,
      clientRegistrationTTL: DEFAULT_CLIENT_REGISTRATION_TTL,
      onError: ({ status, code, description }) =>
        console.warn(`OAuth error response: ${status} ${code} - ${description}`),
      ...normalizedOptions,
    };

    this.validateEndpoint(this.options.authorizeEndpoint, 'authorizeEndpoint');
    this.validateEndpoint(this.options.tokenEndpoint, 'tokenEndpoint');
    if (this.options.clientRegistrationEndpoint) {
      this.validateEndpoint(this.options.clientRegistrationEndpoint, 'clientRegistrationEndpoint');
    }
    if (this.jwtAccessTokens) {
      this.validateEndpoint(this.jwtAccessTokens.jwksUri, 'jwtAccessTokens.jwksUri');
    }
    if (roleBased) {
      this.validateAuthorizationServerRouteIsolation();
    }

    this.resourceServers = configuredResourceServers.map(({ resourceMetadata, resolveExternalToken }) => {
      const metadata = this.snapshotResourceMetadata(resourceMetadata);
      this.validateResourceMetadataOptions(metadata);
      return {
        resourceMetadata: metadata,
        resolveExternalToken,
      };
    });
    for (const [index, server] of this.resourceServers.entries()) {
      const duplicate = this.resourceServers
        .slice(0, index)
        .some((other) => isExactResource(other.resourceMetadata.resource, server.resourceMetadata.resource));
      if (duplicate) {
        throw new TypeError(`resources must be unique; duplicate ${server.resourceMetadata.resource}`);
      }
    }

    if (!roleBased) {
      const legacyOptions = options as OAuthProviderOptions<Env>;
      const hasSingleHandlerConfig = !!(legacyOptions.apiRoute && legacyOptions.apiHandler);
      const hasMultiHandlerConfig = !!legacyOptions.apiHandlers;

      if (hasSingleHandlerConfig && hasMultiHandlerConfig) {
        throw new TypeError(
          'Cannot use both apiRoute/apiHandler and apiHandlers. ' +
            'Use either apiRoute + apiHandler OR apiHandlers, not both.'
        );
      }
      if (!hasSingleHandlerConfig && !hasMultiHandlerConfig) {
        throw new TypeError(
          'Must provide either apiRoute + apiHandler OR apiHandlers. No API route configuration provided.'
        );
      }

      const resourceServer = this.resourceServers[0];
      if (hasSingleHandlerConfig) {
        const handler = this.validateHandler(legacyOptions.apiHandler!, 'apiHandler');
        resourceServer.apiHandler = handler;
        const routes = Array.isArray(legacyOptions.apiRoute) ? legacyOptions.apiRoute : [legacyOptions.apiRoute!];
        routes.forEach((route, index) => {
          this.validateEndpoint(route, Array.isArray(legacyOptions.apiRoute) ? `apiRoute[${index}]` : 'apiRoute');
          this.typedApiHandlers.push({ route, handler, resourceServer });
        });
      } else {
        for (const [route, rawHandler] of Object.entries(legacyOptions.apiHandlers!)) {
          this.validateEndpoint(route, `apiHandlers key: ${route}`);
          const handler = this.validateHandler(rawHandler, `apiHandlers[${route}]`);
          this.typedApiHandlers.push({ route, handler, resourceServer });
        }
      }
      for (const { route } of this.typedApiHandlers) {
        this.assertRouteCoveredByResource(route, resourceServer.resourceMetadata.resource);
      }
    }

    const resources = this.resourceServers.map((server) => server.resourceMetadata.resource);
    const soleResource = resources.length === 1 ? resources[0] : undefined;
    const authorizationServer = roleBased ? options.authorizationServer : undefined;
    this.configuredDefaultAuthorizationResource = authorizationServer?.defaultResource ?? soleResource;
    this.configuredLegacyGrantResource = authorizationServer?.legacyGrantResource ?? soleResource;
    if (roleBased) {
      // The registry is complete, so a misspelled policy value fails here rather than
      // on the first authorization or refresh request.
      this.getDefaultAuthorizationResource();
      this.getLegacyGrantResource();
    }

    // Cloudflare KV rejects token writes whose expiration is less than 60 seconds in the
    // future, so an access token TTL below that would make every token issuance fail with
    // an opaque KV 400 at runtime. Reject it at construction with a clear, actionable error.
    if (!isValidAccessTokenTTL(this.options.accessTokenTTL!)) {
      throw new TypeError(
        `accessTokenTTL must be an integer of at least ${KV_MIN_EXPIRATION_TTL_SECONDS} seconds (Cloudflare KV's minimum expiration window).`
      );
    }

    this.serverCapabilities = buildOAuthServerCapabilities({
      allowImplicitFlow: !!this.options.allowImplicitFlow,
      allowPlainPKCE: this.options.allowPlainPKCE === true,
      allowTokenExchangeGrant: !!this.options.allowTokenExchangeGrant,
      enterpriseManagedAuthorization: !!this.options.enterpriseManagedAuthorization,
    });
    validateAuthorizationServerScopes(this.options.scopesSupported);
    this.validateEmaOptions(this.options.enterpriseManagedAuthorization);

    if (this.options.enterpriseManagedAuthorization) {
      this.jwksProvider = createDefaultJwksProvider({
        cacheTtlSeconds: this.options.enterpriseManagedAuthorization.jwksCacheTtlSeconds,
      });
      this.jtiStore = createKvJtiStore();
    }
  }

  /**
   * Validates that an endpoint is either an absolute path or a full URL
   * @param endpoint - The endpoint to validate
   * @param name - The name of the endpoint property for error messages
   * @throws TypeError if the endpoint is invalid
   */
  private validateEndpoint(endpoint: string, name: string): void {
    if (this.isPath(endpoint)) {
      // It should be an absolute path starting with /
      if (!endpoint.startsWith('/')) {
        throw new TypeError(`${name} path must be an absolute path starting with /`);
      }
      if (this.explicitIssuer && new URL(endpoint, new URL(this.explicitIssuer).origin).hash) {
        throw new TypeError(`${name} must not contain a fragment`);
      }
    } else {
      // It should be a valid URL
      let parsed: URL;
      try {
        parsed = new URL(endpoint);
      } catch (e) {
        throw new TypeError(`${name} must be either an absolute path starting with / or a valid URL`);
      }
      if (
        this.explicitIssuer &&
        (!hasAcceptedCanonicalScheme(parsed) || parsed.username || parsed.password || parsed.hash)
      ) {
        throw new TypeError(
          `${name} must be an absolute HTTPS URL without userinfo or a fragment (http is accepted only on a loopback host)`
        );
      }
    }
  }

  /** Validate the explicit issuer used to host-gate the role-based AS. */
  private validateAuthorizationServerIssuer(issuer: string): void {
    let parsed: URL;
    try {
      parsed = new URL(issuer);
    } catch {
      throw new TypeError('authorizationServer.issuer must be a canonical absolute HTTPS URL');
    }
    if (
      !validateResourceUri(issuer) ||
      !hasAcceptedCanonicalScheme(parsed) ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash ||
      foldResourceSchemeAndHost(issuer) !== issuer ||
      (parsed.href !== issuer && parsed.origin !== issuer)
    ) {
      throw new TypeError(
        'authorizationServer.issuer must be a canonical absolute HTTPS URL (http is accepted only on a loopback host)'
      );
    }
  }

  /** Reject exact collisions between protocol endpoints owned by the AS fetch surface. */
  private validateAuthorizationServerRouteIsolation(): void {
    const issuerUrl = new URL(this.explicitIssuer!);
    const discoveryEndpoint = this.getAuthorizationServerMetadataUrl(issuerUrl);
    const tokenUrl = new URL(this.getFullEndpointUrl(this.options.tokenEndpoint, issuerUrl));

    if (this.matchEndpoint(tokenUrl, discoveryEndpoint)) {
      throw new TypeError('tokenEndpoint must not collide with the authorization server metadata endpoint');
    }

    if (this.options.clientRegistrationEndpoint) {
      const registrationUrl = new URL(this.getFullEndpointUrl(this.options.clientRegistrationEndpoint, issuerUrl));
      if (this.matchEndpoint(registrationUrl, this.options.tokenEndpoint)) {
        throw new TypeError('clientRegistrationEndpoint must not collide with tokenEndpoint');
      }
      if (this.matchEndpoint(registrationUrl, discoveryEndpoint)) {
        throw new TypeError(
          'clientRegistrationEndpoint must not collide with the authorization server metadata endpoint'
        );
      }
    }

    if (this.jwtAccessTokens) {
      const jwksUrl = new URL(this.jwtAccessTokens.jwksUri);
      const collisions: Array<[string, string]> = [
        [this.options.tokenEndpoint, 'tokenEndpoint'],
        [this.options.authorizeEndpoint, 'authorizeEndpoint'],
        [discoveryEndpoint, 'the authorization server metadata endpoint'],
      ];
      if (this.options.clientRegistrationEndpoint) {
        collisions.push([this.options.clientRegistrationEndpoint, 'clientRegistrationEndpoint']);
      }
      for (const [endpoint, name] of collisions) {
        const endpointUrl = new URL(this.getFullEndpointUrl(endpoint, issuerUrl));
        if (jwksUrl.origin === endpointUrl.origin && jwksUrl.pathname === endpointUrl.pathname) {
          throw new TypeError(`jwtAccessTokens.jwksUri must not collide with ${name}`);
        }
      }
    }
  }

  /** Reject resource and route layouts where dispatch could choose the wrong audience. */
  private validateResourceRouteIsolation(): void {
    for (let left = 0; left < this.resourceServers.length; left++) {
      for (let right = left + 1; right < this.resourceServers.length; right++) {
        const leftResource = this.resourceServers[left].resourceMetadata.resource;
        const rightResource = this.resourceServers[right].resourceMetadata.resource;
        if (isExactResource(leftResource, rightResource)) {
          throw new TypeError(`resourceServers must use unique resources; duplicate ${leftResource}`);
        }
      }
    }

    for (let left = 0; left < this.typedApiHandlers.length; left++) {
      for (let right = left + 1; right < this.typedApiHandlers.length; right++) {
        const a = this.typedApiHandlers[left];
        const b = this.typedApiHandlers[right];
        if (a.resourceServer === b.resourceServer) continue;
        const aUrl = new URL(a.route);
        const bUrl = new URL(b.route);
        if (aUrl.origin !== bUrl.origin) continue;
        // Two resources on one path with disjoint queries are told apart by the query a
        // request carries. A query-less route would match any query, and a query that is a
        // subset of the other's would match that resource's requests too.
        if (
          aUrl.search &&
          bUrl.search &&
          !requestCarriesResourceQuery(aUrl, bUrl) &&
          !requestCarriesResourceQuery(bUrl, aUrl)
        ) {
          continue;
        }
        if (pathsOverlapOnBoundary(aUrl.pathname, bUrl.pathname)) {
          throw new TypeError(`API routes for different resources must not overlap: ${a.route} and ${b.route}`);
        }
      }
    }
  }

  /**
   * A protected route must be the canonical resource path or a path-boundary descendant of
   * it. Anything else can never validate a token, because every token is bound to the
   * canonical resource, so it would be a permanently 401 zone.
   */
  private assertRouteCoveredByResource(route: string, resource: string): void {
    const resourceUrl = new URL(resource);
    let routePath: string;
    if (this.isPath(route)) {
      routePath = route.split('?')[0];
    } else {
      const routeUrl = new URL(route);
      if (routeUrl.origin !== resourceUrl.origin) {
        throw new TypeError(
          `API route ${route} is not covered by resourceMetadata.resource ${resource}. An absolute protected route must be on the resource's origin.`
        );
      }
      // A route whose static query names another value for one of the resource's own
      // parameters can only ever receive requests for a different resource.
      for (const [name, value] of resourceUrl.searchParams) {
        const routeValues = routeUrl.searchParams.getAll(name);
        if (routeValues.length > 0 && !routeValues.includes(value)) {
          throw new TypeError(
            `API route ${route} is not covered by resourceMetadata.resource ${resource}. An absolute protected route must carry the resource's query parameters.`
          );
        }
      }
      routePath = routeUrl.pathname;
    }
    if (isPathDescendant(routePath, resourceUrl.pathname)) return;
    throw new TypeError(
      `API route ${route} is not covered by resourceMetadata.resource ${resource}. Protected routes must be the canonical resource path or a descendant of it; use ${resourceUrl.origin} as the resource to cover every path on that origin.`
    );
  }

  /** Resolve a configured policy value to the registry's canonical spelling. */
  private resolveConfiguredResourceDefault(resource: string | undefined, name: string): string | undefined {
    if (resource === undefined) return undefined;
    const configured = this.findConfiguredResource(resource);
    if (!configured) {
      throw new TypeError(`${name} must name one of the configured protected resources`);
    }
    return configured;
  }

  private getDefaultAuthorizationResource(): string | undefined {
    const sole = this.resourceServers.length === 1 ? this.resourceServers[0].resourceMetadata.resource : undefined;
    return this.resolveConfiguredResourceDefault(
      this.configuredDefaultAuthorizationResource ?? sole,
      'defaultResource'
    );
  }

  private getLegacyGrantResource(): string | undefined {
    const sole = this.resourceServers.length === 1 ? this.resourceServers[0].resourceMetadata.resource : undefined;
    return this.resolveConfiguredResourceDefault(this.configuredLegacyGrantResource ?? sole, 'legacyGrantResource');
  }

  /**
   * The audience a stored access token is treated as bound to.
   *
   * A token issued before resource binding has no stored audience. It keeps
   * working at the server-selected migration resource (the sole resource, or
   * `legacyGrantResource` in a multi-resource deployment) until it expires;
   * refresh binds its grant and returns a bound replacement. The client never
   * chooses this destination. Without a migration resource the token is
   * treated as unbound and rejected.
   *
   * The destination is deployment policy, not an issuance-time claim: changing
   * `legacyGrantResource` re-targets every surviving unbound token and grant.
   * Keep it fixed for the length of the migration window.
   */
  private resolveStoredTokenAudience(audience: string | string[] | undefined): string | string[] | undefined {
    return audience === undefined ? this.getLegacyGrantResource() : audience;
  }

  /**
   * Validates that a handler is either an ExportedHandler or a class extending WorkerEntrypoint
   * @param handler - The handler to validate
   * @param name - The name of the handler property for error messages
   * @returns The type of the handler (EXPORTED_HANDLER or WORKER_ENTRYPOINT)
   * @throws TypeError if the handler is invalid
   */
  private validateHandler(handler: any, name: string): TypedHandler<Env> {
    if (typeof handler === 'object' && handler !== null && typeof handler.fetch === 'function') {
      // It's an ExportedHandler object
      return { type: HandlerType.EXPORTED_HANDLER, handler };
    }

    // Check if it's a class constructor extending WorkerEntrypoint
    if (typeof handler === 'function' && handler.prototype instanceof WorkerEntrypoint) {
      return { type: HandlerType.WORKER_ENTRYPOINT, handler };
    }

    throw new TypeError(
      `${name} must be either an ExportedHandler object with a fetch method or a class extending WorkerEntrypoint`
    );
  }

  /** Snapshot caller-owned metadata so later mutation cannot change routing or policy. */
  private snapshotResourceMetadata(metadata: OAuthProtectedResourceMetadata): OAuthProtectedResourceMetadata {
    return {
      ...metadata,
      ...(metadata?.authorization_servers ? { authorization_servers: [...metadata.authorization_servers] } : {}),
      ...(metadata?.scopes_supported ? { scopes_supported: [...metadata.scopes_supported] } : {}),
      ...(metadata?.bearer_methods_supported
        ? { bearer_methods_supported: [...metadata.bearer_methods_supported] }
        : {}),
    };
  }

  /** Validate configured RFC 9728 protected resource metadata. */
  private validateResourceMetadataOptions(options: OAuthProtectedResourceMetadata): void {
    if (!options || !validateResourceUri(options.resource) || !hasAcceptedCanonicalScheme(new URL(options.resource))) {
      throw new TypeError(
        'resourceMetadata.resource is required and must be an absolute HTTPS URI without a fragment (http is accepted only on a loopback host)'
      );
    }
    if (foldResourceSchemeAndHost(options.resource) !== options.resource) {
      throw new TypeError('resourceMetadata.resource must use a lowercase scheme and lowercase host');
    }
    const parsedResource = new URL(options.resource);
    if (
      parsedResource.username ||
      parsedResource.password ||
      (parsedResource.href !== options.resource && parsedResource.origin !== options.resource)
    ) {
      throw new TypeError(
        'resourceMetadata.resource must use canonical URL serialization without userinfo, a default port, or dot segments'
      );
    }
    // The metadata namespace is dispatched to discovery before any protected route, so a
    // resource inside it could never receive a request.
    if (
      parsedResource.pathname === PROTECTED_RESOURCE_WELL_KNOWN_PREFIX ||
      parsedResource.pathname.startsWith(`${PROTECTED_RESOURCE_WELL_KNOWN_PREFIX}/`)
    ) {
      throw new TypeError(
        `resourceMetadata.resource must not be inside the ${PROTECTED_RESOURCE_WELL_KNOWN_PREFIX} namespace`
      );
    }

    if (options.authorization_servers !== undefined) {
      if (options.authorization_servers.length === 0) {
        throw new TypeError('resourceMetadata.authorization_servers must contain at least one issuer');
      }
      for (const issuer of options.authorization_servers) {
        let parsed: URL;
        try {
          parsed = new URL(issuer);
        } catch {
          throw new TypeError('resourceMetadata.authorization_servers must contain valid HTTPS issuer URLs');
        }
        if (
          !validateResourceUri(issuer) ||
          !hasAcceptedCanonicalScheme(parsed) ||
          parsed.username ||
          parsed.password ||
          foldResourceSchemeAndHost(issuer) !== issuer ||
          (parsed.href !== issuer && parsed.origin !== issuer) ||
          issuer.includes('?') ||
          issuer.includes('#')
        ) {
          throw new TypeError(
            'resourceMetadata.authorization_servers must contain valid HTTPS issuer URLs (http is accepted only on a loopback host)'
          );
        }
      }
    }

    if (options.scopes_supported?.some((scope) => !isValidOAuthScopeToken(scope))) {
      throw new TypeError('resourceMetadata.scopes_supported must contain valid OAuth scope tokens');
    }

    if (options.bearer_methods_supported?.some((method) => method !== 'header')) {
      throw new TypeError("resourceMetadata.bearer_methods_supported only supports 'header'");
    }
  }

  /**
   * Validates MCP Enterprise-Managed Authorization configuration at construction time.
   *
   * Presence of `enterpriseManagedAuthorization` on options enables the feature —
   * there is no separate `enabled` flag (which would silently disable EMA when
   * forgotten). Configuration is checked structurally; runtime concerns
   * (JWKS reachability etc.) are checked when assertions arrive.
   */
  private validateEmaOptions(options: EmaOptions<Env> | undefined): void {
    if (!options) {
      return;
    }

    if (typeof options.trustedIssuers !== 'function') {
      throw new TypeError(
        'enterpriseManagedAuthorization.trustedIssuers must be a resolver function: (input) => EmaTrustedIssuer | null'
      );
    }

    if (typeof options.mapClaims !== 'function') {
      throw new TypeError('enterpriseManagedAuthorization.mapClaims must be a function');
    }

    if (options.jwksCacheTtlSeconds !== undefined && options.jwksCacheTtlSeconds <= 0) {
      throw new TypeError('enterpriseManagedAuthorization.jwksCacheTtlSeconds must be greater than 0');
    }
    if (options.clockSkewSeconds !== undefined && options.clockSkewSeconds < 0) {
      throw new TypeError('enterpriseManagedAuthorization.clockSkewSeconds must be non-negative');
    }
    if (options.maxAssertionLifetimeSeconds !== undefined && options.maxAssertionLifetimeSeconds <= 0) {
      throw new TypeError('enterpriseManagedAuthorization.maxAssertionLifetimeSeconds must be greater than 0');
    }
  }

  /**
   * Main fetch handler for the Worker
   * Routes requests to the appropriate handler based on the URL
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @param ctx - Cloudflare Worker execution context
   * @returns A Promise resolving to an HTTP Response
   */
  async fetch(request: Request, env: Env & ProviderEnv, ctx: ExecutionContext): Promise<Response> {
    return this.fetchForRoles(request, env, ctx, 'combined');
  }

  async fetchAuthorizationServer(request: Request, env: Env & ProviderEnv, ctx: ExecutionContext): Promise<Response> {
    return this.fetchForRoles(request, env, ctx, 'authorization-server');
  }

  async fetchResourceServer(
    request: Request,
    env: Env & ProviderEnv,
    ctx: ExecutionContext,
    resource: string
  ): Promise<Response> {
    const resourceServer = this.resourceServers.find((server) => server.resourceMetadata.resource === resource);
    if (!resourceServer) throw new TypeError(`No protected resource is registered for ${resource}`);
    return this.fetchForRoles(request, env, ctx, resourceServer);
  }

  private async fetchForRoles(
    request: Request,
    env: Env & ProviderEnv,
    ctx: ExecutionContext,
    role: 'combined' | 'authorization-server' | NormalizedResourceServer<Env>
  ): Promise<Response> {
    const url = new URL(request.url);

    const servesAuthorizationServer = role === 'combined' || role === 'authorization-server';
    const servesProtectedResources = role !== 'authorization-server';
    const metadataResourceServer = servesProtectedResources
      ? this.findResourceServerForMetadataUrl(url, typeof role === 'object' ? role : undefined)
      : undefined;
    const matchedApiRoute = servesProtectedResources ? this.findApiRouteForUrl(url) : undefined;
    const apiRoute =
      matchedApiRoute && (typeof role !== 'object' || matchedApiRoute.resourceServer === role)
        ? matchedApiRoute
        : undefined;

    // Special handling for OPTIONS requests (CORS preflight)
    if (request.method === 'OPTIONS') {
      // For API routes and OAuth endpoints, respond with CORS headers
      if (
        apiRoute !== undefined ||
        (servesAuthorizationServer && this.isAuthorizationServerMetadataRequest(url)) ||
        (servesProtectedResources && this.isProtectedResourceMetadataPath(url)) ||
        (servesAuthorizationServer && this.jwtAccessTokens && this.isJwksEndpoint(url)) ||
        (servesAuthorizationServer && this.isTokenEndpoint(url)) ||
        (servesAuthorizationServer && this.options.clientRegistrationEndpoint && this.isClientRegistrationEndpoint(url))
      ) {
        // Create an empty 204 No Content response with CORS headers
        return this.addCorsHeaders(
          new Response(null, {
            status: 204,
            headers: { 'Content-Length': '0' },
          }),
          request
        );
      }

      // For other routes, pass through to the default handler
    }

    // Handle .well-known/oauth-authorization-server
    if (servesAuthorizationServer && this.isAuthorizationServerMetadataRequest(url)) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return this.addCorsHeaders(
          new Response(null, {
            status: 405,
            headers: { Allow: 'GET, HEAD, OPTIONS' },
          }),
          request
        );
      }
      const response = await this.handleMetadataDiscovery(url);
      return this.addCorsHeaders(withoutBodyForHead(request, response), request);
    }

    // Publish the public signing keys used by RFC 9068 JWT access tokens.
    if (servesAuthorizationServer && this.jwtAccessTokens && this.isJwksEndpoint(url)) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return this.addCorsHeaders(
          new Response(null, {
            status: 405,
            headers: { Allow: 'GET, HEAD, OPTIONS' },
          }),
          request
        );
      }
      let jwks: { keys: JwtPublicKey[] };
      try {
        jwks = await this.jwtAccessTokens.getJwks(env);
      } catch (error) {
        // The deployer's key store is the only thing that can fail here, and every
        // resource server polls this endpoint, so the failure has to reach `onError`
        // instead of escaping as an opaque unhandled rejection.
        return this.addCorsHeaders(
          this.createErrorResponse(
            'server_error',
            { description: 'JWKS is temporarily unavailable', statusCode: 503 },
            {
              category: 'jwks',
              reason: 'key_resolution_failed',
              detail: { message: error instanceof Error ? error.message : String(error) },
            },
            request
          ),
          request
        );
      }
      return this.addCorsHeaders(
        withoutBodyForHead(
          request,
          Response.json(jwks, {
            headers: {
              'Cache-Control': 'public, max-age=300',
              // The response is cacheable and its CORS headers depend on Origin, so a
              // shared cache must key the no-Origin variant separately too.
              Vary: 'Origin',
            },
          })
        ),
        request
      );
    }

    // Handle .well-known/oauth-protected-resource (RFC 9728). A document at
    // any alias would identify a different resource than the URL used to fetch
    // it, so reserve the namespace and return 404 for noncanonical variants.
    if (servesProtectedResources && this.isProtectedResourceMetadataPath(url)) {
      if (!metadataResourceServer) {
        return this.addCorsHeaders(new Response(null, { status: 404 }), request);
      }
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return this.addCorsHeaders(
          new Response(null, {
            status: 405,
            headers: { Allow: 'GET, HEAD, OPTIONS' },
          }),
          request
        );
      }
      const response = this.handleProtectedResourceMetadata(url, metadataResourceServer);
      return this.addCorsHeaders(withoutBodyForHead(request, response), request);
    }

    // Handle token endpoint (including revocation)
    if (servesAuthorizationServer && this.isTokenEndpoint(url)) {
      const parsed = await this.parseTokenEndpointRequest(request, env);

      // If parsing failed, return the error response
      if (parsed instanceof Response) {
        return this.addCorsHeaders(parsed, request);
      }

      let response: Response;
      if (parsed.isRevocationRequest) {
        response = await this.handleRevocationRequest(parsed.body, parsed.clientInfo, env);
      } else {
        response = await this.handleTokenRequest(parsed.body, parsed.clientInfo, env, url, request);
      }

      return this.addCorsHeaders(response, request);
    }

    // Handle client registration endpoint
    if (
      servesAuthorizationServer &&
      this.options.clientRegistrationEndpoint &&
      this.isClientRegistrationEndpoint(url)
    ) {
      const response = await this.handleClientRegistration(request, env);
      return this.addCorsHeaders(response, request);
    }

    // Check if it's an API request
    if (apiRoute) {
      const response = await this.handleApiRequest(request, env, ctx, apiRoute);
      return this.addCorsHeaders(response, request);
    }

    if (typeof role === 'object') {
      return new Response(null, { status: 404 });
    }

    // Inject OAuth helpers into env if not already present
    if (!(env as Record<string, unknown>).OAUTH_PROVIDER) {
      (env as Record<string, unknown>).OAUTH_PROVIDER = this.createOAuthHelpers(env);
    }

    // Call the default handler based on its type
    // Note: We don't add CORS headers to default handler responses
    if (this.typedDefaultHandler.type === HandlerType.EXPORTED_HANDLER) {
      return this.typedDefaultHandler.handler.fetch(
        request as Parameters<ExportedHandlerWithFetch<Env>['fetch']>[0],
        env,
        ctx
      );
    }

    const handler = new this.typedDefaultHandler.handler(ctx, env);
    return handler.fetch(request);
  }

  /** Resolve either a legacy opaque token or this issuer's verified JWT token record. */
  private async resolveInternalAccessToken(
    token: string,
    env: Env & ProviderEnv,
    audienceSource: JwtAudienceSource = 'registered-resource'
  ): Promise<AccessTokenResolution> {
    if (this.jwtAccessTokens && jwtInternals(this.jwtAccessTokens).isOwnJwt(token)) {
      const registeredResources = this.resourceServers.map((server) => server.resourceMetadata.resource);
      const verified =
        audienceSource === 'token-audience'
          ? await jwtInternals(this.jwtAccessTokens).verify(token, env)
          : registeredResources.length > 0
            ? await this.jwtAccessTokens.verify(token, registeredResources, env)
            : null;
      if (!verified) return { tokenData: null, isOwnJwt: true };

      const id = await generateTokenId(token);
      const tokenData: Token | null = await env.OAUTH_KV.get(`token:${verified.userId}:${verified.grantId}:${id}`, {
        type: 'json',
      });
      if (!tokenData || !this.jwtClaimsMatchStoredToken(id, verified, tokenData)) {
        return { tokenData: null, isOwnJwt: true };
      }
      return { tokenData, isOwnJwt: true };
    }

    const parts = token.split(':');
    if (parts.length !== 3) return { tokenData: null, isOwnJwt: false };

    const [userId, grantId] = parts;
    const id = await generateTokenId(token);
    const tokenData: Token | null = await env.OAUTH_KV.get(`token:${userId}:${grantId}:${id}`, { type: 'json' });
    return { tokenData, isOwnJwt: false };
  }

  /** The signed JWT and encrypted state record must describe exactly the same token. */
  private jwtClaimsMatchStoredToken(id: string, verified: VerifiedJwtAccessToken, tokenData: Token): boolean {
    return (
      tokenData.format === 'jwt' &&
      tokenData.id === id &&
      tokenData.jti === verified.jti &&
      tokenData.userId === verified.userId &&
      tokenData.grantId === verified.grantId &&
      tokenData.grant.clientId === verified.clientId &&
      tokenData.audience === verified.audience &&
      tokenData.createdAt === verified.claims.iat &&
      tokenData.expiresAt === verified.expiresAt &&
      tokenData.scope.length === verified.scope.length &&
      tokenData.scope.every((scope, index) => scope === verified.scope[index])
    );
  }

  /**
   * Decodes a token and returns token data with decrypted props
   * @param token - The granted token
   * @param env - Cloudflare Worker environment variables
   * @returns Promise resolving to token data with decrypted props, or null if token is invalid
   */
  async unwrapToken<T = any>(token: string, env: Env & ProviderEnv): Promise<TokenSummary<T> | null> {
    const { tokenData } = await this.resolveInternalAccessToken(token, env);

    // Return null if missing or expired
    if (!tokenData) return null;
    const now = Math.floor(Date.now() / 1e3);
    if (tokenData.expiresAt < now) {
      return null;
    }

    // Decrypt the props
    const encryptionKey = await unwrapKeyWithToken(token, tokenData.wrappedEncryptionKey);
    const decryptedProps = await decryptProps(encryptionKey, tokenData.grant.encryptedProps);

    // Return the token data with decrypted instead of encrypted props
    const { grant } = tokenData;
    return {
      id: tokenData.id,
      grantId: tokenData.grantId,
      userId: tokenData.userId,
      createdAt: tokenData.createdAt,
      expiresAt: tokenData.expiresAt,
      audience: tokenData.audience,
      scope: tokenData.scope || grant.scope, // Use token scope if available, fallback to grant scope for backward compatibility
      format: tokenData.format,
      jti: tokenData.jti,
      grant: {
        clientId: grant.clientId,
        scope: grant.scope,
        props: decryptedProps as T,
      },
    };
  }

  async validateAccessToken<T = any>(
    token: string,
    resource: string,
    env: Env & ProviderEnv
  ): Promise<ValidatedAccessToken<T> | null> {
    const configuredResource = this.findConfiguredResource(resource);
    if (!configuredResource) {
      throw new TypeError('resource must name one registered protected resource');
    }
    const summary = await this.unwrapToken<T>(token, env);
    if (!summary || !isExactResource(this.resolveStoredTokenAudience(summary.audience), configuredResource))
      return null;
    return {
      props: summary.grant.props,
      audience: configuredResource,
      expiresAt: summary.expiresAt,
      scope: summary.scope,
      userId: summary.userId,
      clientId: summary.grant.clientId,
    };
  }

  /**
   * Determines if an endpoint configuration is a path or a full URL
   * @param endpoint - The endpoint configuration
   * @returns True if the endpoint is a path (starts with /), false if it's a full URL
   */
  private isPath(endpoint: string): boolean {
    return endpoint.startsWith('/');
  }

  /**
   * Matches a URL against an endpoint pattern that can be a full URL or just a path
   * @param url - The URL to check
   * @param endpoint - The endpoint pattern (full URL or path)
   * @returns True if the URL matches the endpoint pattern
   */
  private matchEndpoint(url: URL, endpoint: string, allowAdditionalQuery = false): boolean {
    if (!this.explicitIssuer) {
      // The combined OAuthProvider keeps its 0.x matching: a path matches on pathname
      // only, a full URL on hostname and pathname, and the query is ignored either way.
      // The role-based shape resolves paths against its explicit issuer and host-gates them.
      if (this.isPath(endpoint)) return url.pathname === endpoint;
      const legacyEndpoint = new URL(endpoint);
      return url.hostname === legacyEndpoint.hostname && url.pathname === legacyEndpoint.pathname;
    }
    const endpointUrl = new URL(this.getFullEndpointUrl(endpoint, url));
    if (url.origin !== endpointUrl.origin || url.pathname !== endpointUrl.pathname) return false;

    const unmatchedActualQuery = [...url.searchParams.entries()];
    const configuredQueryNames = new Set<string>();
    for (const [name, value] of endpointUrl.searchParams) {
      configuredQueryNames.add(name);
      const match = unmatchedActualQuery.findIndex(([actualName, actualValue]) => {
        return actualName === name && actualValue === value;
      });
      if (match === -1) return false;
      unmatchedActualQuery.splice(match, 1);
    }
    if (!allowAdditionalQuery) return unmatchedActualQuery.length === 0;

    // OAuth parameters may be appended to an authorization endpoint's static
    // query, but a second value for a configured key could change what
    // application code sees through URLSearchParams.get().
    return unmatchedActualQuery.every(([name]) => !configuredQueryNames.has(name));
  }

  /**
   * Checks if a URL matches the configured token endpoint
   * @param url - The URL to check
   * @returns True if the URL matches the token endpoint
   */
  private isTokenEndpoint(url: URL): boolean {
    // RFC 6749 §3.2 lets the endpoint URI carry a static query; a client may add its own.
    return this.matchEndpoint(url, this.options.tokenEndpoint, true);
  }

  isAuthorizationEndpointRequest(url: URL): boolean {
    // The endpoint's configured query is retained while OAuth request
    // parameters are added by the client.
    return this.matchEndpoint(url, this.options.authorizeEndpoint, true);
  }

  /**
   * Checks if a URL matches the configured client registration endpoint
   * @param url - The URL to check
   * @returns True if the URL matches the client registration endpoint
   */
  private isClientRegistrationEndpoint(url: URL): boolean {
    if (!this.options.clientRegistrationEndpoint) return false;
    return this.matchEndpoint(url, this.options.clientRegistrationEndpoint, true);
  }

  private isJwksEndpoint(url: URL): boolean {
    return !!this.jwtAccessTokens && this.matchEndpoint(url, this.jwtAccessTokens.jwksUri);
  }

  /**
   * Checks if a URL is a request for OAuth Protected Resource Metadata (RFC 9728).
   * Only the well-known URL constructed from the configured canonical resource
   * may return its document; aliases would violate RFC 9728 §3.3.
   */
  private findResourceServerForMetadataUrl(
    url: URL,
    onlyResourceServer?: NormalizedResourceServer<Env>
  ): NormalizedResourceServer<Env> | undefined {
    const candidates = onlyResourceServer ? [onlyResourceServer] : this.resourceServers;
    return candidates.find((server) => {
      // RFC 9728 §3 fixes the origin and path; a cache-busting query must not hide the
      // document, while a resource's own query parameters must still be present.
      const expected = new URL(this.getConfiguredResourceMetadataUrl(server.resourceMetadata.resource));
      return (
        url.origin === expected.origin &&
        url.pathname === expected.pathname &&
        requestCarriesResourceQuery(url, expected)
      );
    });
  }

  /** Exact RFC 8414 discovery location for the configured issuer. */
  private getAuthorizationServerMetadataUrl(requestUrl: URL): string {
    if (!this.explicitIssuer) return `${requestUrl.origin}/.well-known/oauth-authorization-server`;
    const issuer = new URL(this.explicitIssuer);
    // RFC 8414 inserts the well-known suffix before a non-root issuer path,
    // after removing its terminating slashes.
    const issuerPath = issuer.pathname === '/' ? '' : issuer.pathname.replace(/\/+$/, '');
    return `${issuer.origin}/.well-known/oauth-authorization-server${issuerPath}`;
  }

  private isAuthorizationServerMetadataRequest(url: URL): boolean {
    // RFC 8414 §3 fixes the origin and path; a cache-busting query must not hide the document.
    const expected = new URL(this.getAuthorizationServerMetadataUrl(url));
    return url.origin === expected.origin && url.pathname === expected.pathname;
  }

  /** Whether this instance is the role-based authorization server with a fixed issuer. */
  get hasExplicitIssuer(): boolean {
    return this.explicitIssuer !== undefined;
  }

  /** Whether a URL is in the RFC 9728 protected-resource metadata namespace. */
  private isProtectedResourceMetadataPath(url: URL): boolean {
    return (
      url.pathname === PROTECTED_RESOURCE_WELL_KNOWN_PREFIX ||
      url.pathname.startsWith(PROTECTED_RESOURCE_WELL_KNOWN_PREFIX + '/')
    );
  }

  private createInvalidClientResponse(
    description: string,
    basicAuthenticationAttempted: boolean,
    internal?: { category: string; reason: string; detail?: unknown },
    request?: Request
  ): Response {
    return this.createErrorResponse(
      'invalid_client',
      {
        description,
        statusCode: 401,
        ...(basicAuthenticationAttempted ? { headers: { 'WWW-Authenticate': BASIC_AUTH_CHALLENGE } } : {}),
      },
      internal,
      request
    );
  }

  /**
   * Parses and validates a token endpoint request (used for both token exchange and revocation)
   * @param request - The HTTP request to parse
   * @returns Promise with parsed body and client info, or error response
   */
  private async parseTokenEndpointRequest(
    request: Request,
    env: Env & ProviderEnv
  ): Promise<
    | {
        body: any;
        clientInfo: ClientInfo;
        isRevocationRequest: boolean;
      }
    | Response
  > {
    // Only accept POST requests
    if (request.method !== 'POST') {
      return this.createErrorResponse('invalid_request', {
        description: 'Method not allowed',
        statusCode: 405,
        headers: { Allow: 'POST, OPTIONS' },
      });
    }

    const contentType = request.headers.get('Content-Type') || '';
    let body: any = {};

    // According to OAuth 2.0 RFC 6749/7009, requests MUST use application/x-www-form-urlencoded.
    // Parse the media type strictly: strip any parameters (e.g. "; charset=utf-8") and
    // compare the exact media type. A `includes()` check is too loose and would accept
    // malformed headers such as "application/json, application/x-www-form-urlencoded",
    // which then cause request.formData() to throw and crash the worker.
    const mediaType = contentType.split(';')[0].trim().toLowerCase();
    if (mediaType !== 'application/x-www-form-urlencoded') {
      return this.createErrorResponse('invalid_request', {
        description: 'Content-Type must be application/x-www-form-urlencoded',
        statusCode: 400,
      });
    }

    // Process application/x-www-form-urlencoded. Parsing can still throw if the body is
    // not actually valid form data, so guard it and return a 400 instead of crashing.
    let formData: FormData;
    try {
      formData = await request.formData();
    } catch {
      return this.createErrorResponse('invalid_request', {
        description: 'Request body must be valid application/x-www-form-urlencoded data',
        statusCode: 400,
      });
    }
    const processedKeys = new Set<string>();
    for (const [key, value] of formData.entries()) {
      if (processedKeys.has(key)) {
        continue;
      }
      processedKeys.add(key);

      // RFC 8707: resource parameter can appear multiple times
      const allValues = formData.getAll(key);
      if (key !== 'resource' && allValues.length > 1) {
        return this.createErrorResponse('invalid_request', {
          description: `Request parameter "${key}" must not be repeated`,
          statusCode: 400,
        });
      }

      body[key] = allValues.length > 1 ? allValues : value;
    }

    // Get client credentials from HTTP Basic auth or form parameters.
    const basicAuthorization = parseBasicAuthorizationHeader(request.headers.get('Authorization'));
    const basicAuthenticationAttempted = basicAuthorization.kind !== 'not-basic';
    let clientId = '';
    let clientSecret = '';

    if (basicAuthenticationAttempted) {
      if (formData.has('client_id') || formData.has('client_secret')) {
        return this.createErrorResponse('invalid_request', {
          description: 'Client must not use multiple authentication methods',
          statusCode: 400,
        });
      }

      if (basicAuthorization.kind === 'malformed') {
        return this.createInvalidClientResponse(
          'Client authentication failed: invalid Basic credentials',
          basicAuthenticationAttempted
        );
      }

      clientId = basicAuthorization.clientId;
      clientSecret = basicAuthorization.clientSecret;
    } else {
      clientId = body.client_id;
      clientSecret = body.client_secret || '';
    }

    if (!clientId) {
      return this.createInvalidClientResponse('Client ID is required', basicAuthenticationAttempted);
    }

    // Verify client exists
    let clientInfo: StoredClientInfo | null;
    try {
      clientInfo = await this.getClient(env, clientId);
    } catch (error) {
      if (error instanceof CimdFetchError) {
        // Same wire response as an unknown client — the CIMD spec prescribes no
        // error body for metadata fetch failures — but the deployer's onError
        // hook receives a stable reason and diagnostic details, so an upstream
        // outage blocking the metadata URL is observable instead of masquerading
        // as an unregistered client.
        return this.createInvalidClientResponse(
          'Client not found',
          basicAuthenticationAttempted,
          {
            category: 'client-id-metadata-document',
            reason: error.reason,
            detail: { metadataUrl: error.metadataUrl, message: error.detail },
          },
          request
        );
      }
      throw error;
    }
    if (!clientInfo) {
      return this.createInvalidClientResponse('Client not found', basicAuthenticationAttempted);
    }

    // RFC 7591 methods identify the credential transport. Check form-parameter
    // presence rather than truthiness so an empty secret still counts as a POST attempt.
    const presentedAuthMethod = basicAuthenticationAttempted
      ? 'client_secret_basic'
      : formData.has('client_secret')
        ? 'client_secret_post'
        : 'none';
    const registeredAuthMethod = clientInfo.tokenEndpointAuthMethod;
    if (
      !isClientAuthMethodAllowed(
        clientInfo,
        presentedAuthMethod,
        !!this.options.clientIdMetadataDocumentEnabled && this.isClientMetadataUrl(clientInfo.clientId)
      )
    ) {
      return this.createInvalidClientResponse('Client authentication failed', basicAuthenticationAttempted, {
        category: 'client-authentication',
        reason: 'token_endpoint_auth_method_mismatch',
        detail: {
          clientId: clientInfo.clientId,
          registeredMethod: registeredAuthMethod,
          presentedMethod: presentedAuthMethod,
        },
      });
    }

    // For confidential clients, validate the secret
    if (presentedAuthMethod !== 'none') {
      if (!clientSecret) {
        return this.createInvalidClientResponse(
          'Client authentication failed: missing client_secret',
          basicAuthenticationAttempted
        );
      }

      // Verify the client secret matches
      if (!clientInfo.clientSecret) {
        return this.createInvalidClientResponse(
          'Client authentication failed: client has no registered secret',
          basicAuthenticationAttempted
        );
      }

      const providedSecretHash = await hashSecret(clientSecret);
      if (providedSecretHash !== clientInfo.clientSecret) {
        return this.createInvalidClientResponse(
          'Client authentication failed: invalid client_secret',
          basicAuthenticationAttempted
        );
      }
    }

    // Determine if this is a revocation request
    // RFC 7009: Revocation requests have 'token' parameter but no 'grant_type'
    const isRevocationRequest = !body.grant_type && !!body.token;

    return {
      body,
      clientInfo,
      isRevocationRequest,
    };
  }

  /**
   * Checks if a URL matches a specific API route
   * @param url - The URL to check
   * @param route - The API route to check against
   * @returns True if the URL matches the API route
   */
  private matchApiRoute(url: URL, route: string): boolean {
    const pathMatches = (configuredPath: string, rootMatchesDescendants: boolean): boolean => {
      if (configuredPath === '/') return rootMatchesDescendants || url.pathname === '/';
      const normalized = configuredPath.endsWith('/') ? configuredPath.slice(0, -1) : configuredPath;
      return url.pathname === normalized || url.pathname.startsWith(normalized + '/');
    };

    if (this.isPath(route)) {
      return pathMatches(route, false);
    } else {
      const apiUrl = new URL(route);
      return (
        url.origin === apiUrl.origin && pathMatches(apiUrl.pathname, true) && requestCarriesResourceQuery(url, apiUrl)
      );
    }
  }

  /**
   * Checks if a URL is an API request based on the configured API route(s)
   * @param url - The URL to check
   * @returns True if the URL matches any of the API routes
   */
  private isApiRequest(url: URL): boolean {
    return this.findApiRouteForUrl(url) !== undefined;
  }

  /**
   * Finds the appropriate API handler for a URL
   * @param url - The URL to find a handler for
   * @returns The TypedHandler for the URL, or undefined if no handler matches
   */
  private findApiRouteForUrl(url: URL): NormalizedApiRoute<Env> | undefined {
    return this.typedApiHandlers
      .filter(({ route }) => this.matchApiRoute(url, route))
      .sort(
        (left, right) =>
          new URL(right.route, url.origin).pathname.length - new URL(left.route, url.origin).pathname.length
      )[0];
  }

  /**
   * Gets the full URL for an endpoint, using the provided request URL's
   * origin for endpoints specified as just paths
   * @param endpoint - The endpoint configuration (path or full URL)
   * @param requestUrl - The URL of the incoming request
   * @returns The full URL for the endpoint
   */
  private getFullEndpointUrl(endpoint: string, requestUrl: URL): string {
    if (this.isPath(endpoint)) {
      // Role-based endpoints are always scoped to the explicit AS origin.
      const origin = this.explicitIssuer ? new URL(this.explicitIssuer).origin : requestUrl.origin;
      return `${origin}${endpoint}`;
    } else {
      // It's already a full URL
      return endpoint;
    }
  }

  /**
   * Gets the authorization server issuer using the same derivation as RFC 8414 metadata.
   */
  getAuthorizationServerIssuer(requestUrl: URL): string {
    if (this.explicitIssuer) return this.explicitIssuer;
    const tokenEndpoint = this.getFullEndpointUrl(this.options.tokenEndpoint, requestUrl);
    return new URL(tokenEndpoint).origin;
  }

  /**
   * Adds CORS headers to a response
   * @param response - The response to add CORS headers to
   * @param request - The original request
   * @returns A new Response with CORS headers added
   */
  private addCorsHeaders(response: Response, request: Request): Response {
    // Get the Origin header from the request
    const origin = request.headers.get('Origin');

    // If there's no Origin header, return the original response
    if (!origin) {
      return response;
    }

    // Create a new response that copies all properties from the original response
    // This makes the response mutable so we can modify its headers
    const newResponse = new Response(response.body, response);

    // Add CORS headers
    newResponse.headers.set('Access-Control-Allow-Origin', origin);
    newResponse.headers.set('Access-Control-Allow-Methods', '*');
    // Include Authorization explicitly since it's not included in * for security reasons
    newResponse.headers.set('Access-Control-Allow-Headers', 'Authorization, *');
    appendHeaderValue(newResponse.headers, 'Vary', 'Origin');

    // Browser-based OAuth/MCP clients need these non-safelisted response
    // headers for authorization discovery, step-up challenges, and backoff.
    // Preserve any headers the API handler already chose to expose.
    const exposedHeaders = (newResponse.headers.get('Access-Control-Expose-Headers') ?? '')
      .split(',')
      .map((name) => name.trim())
      .filter(Boolean);
    for (const requiredHeader of ['WWW-Authenticate', 'Retry-After']) {
      if (!exposedHeaders.some((name) => name.toLowerCase() === requiredHeader.toLowerCase())) {
        exposedHeaders.push(requiredHeader);
      }
    }
    newResponse.headers.set('Access-Control-Expose-Headers', exposedHeaders.join(', '));
    newResponse.headers.set('Access-Control-Max-Age', '86400'); // 24 hours

    return newResponse;
  }

  /**
   * Handles the OAuth metadata discovery endpoint
   * Implements RFC 8414 for OAuth Server Metadata
   * @param requestUrl - The URL of the incoming request
   * @returns Response with OAuth server metadata
   */
  private async handleMetadataDiscovery(requestUrl: URL): Promise<Response> {
    // For endpoints specified as paths, use the request URL's origin
    const tokenEndpoint = this.getFullEndpointUrl(this.options.tokenEndpoint, requestUrl);
    const authorizeEndpoint = this.getFullEndpointUrl(this.options.authorizeEndpoint, requestUrl);

    let registrationEndpoint: string | undefined = undefined;
    if (this.options.clientRegistrationEndpoint) {
      registrationEndpoint = this.getFullEndpointUrl(this.options.clientRegistrationEndpoint, requestUrl);
    }

    const responseTypesSupported = this.serverCapabilities.responseTypes;
    const grantTypesSupported = this.serverCapabilities.grantTypes;
    const authorizationGrantProfilesSupported = this.options.enterpriseManagedAuthorization
      ? [EMA_ID_JAG_GRANT_PROFILE]
      : [];

    const metadata = {
      issuer: this.getAuthorizationServerIssuer(requestUrl),
      authorization_endpoint: authorizeEndpoint,
      token_endpoint: tokenEndpoint,
      // RFC 9728 §4. The provider's resource registry is finite and enumerable.
      // Each individual grant/token still receives exactly one of these audiences.
      // RFC 8414 §3.2: claims with zero elements are omitted from the response.
      ...(this.resourceServers.length > 0
        ? { protected_resources: this.resourceServers.map((server) => server.resourceMetadata.resource) }
        : {}),
      jwks_uri: this.jwtAccessTokens?.jwksUri,
      registration_endpoint: registrationEndpoint,
      scopes_supported: this.options.scopesSupported,
      response_types_supported: responseTypesSupported,
      response_modes_supported: this.options.allowImplicitFlow ? ['query', 'fragment'] : ['query'],
      grant_types_supported: grantTypesSupported,
      // MCP Enterprise-Managed Authorization grant profile (only when EMA is configured).
      ...(authorizationGrantProfilesSupported.length > 0
        ? { authorization_grant_profiles_supported: authorizationGrantProfilesSupported }
        : {}),
      token_endpoint_auth_methods_supported: this.serverCapabilities.tokenEndpointAuthMethods,
      // not implemented: token_endpoint_auth_signing_alg_values_supported
      // not implemented: service_documentation
      // not implemented: ui_locales_supported
      // not implemented: op_policy_uri
      // not implemented: op_tos_uri
      revocation_endpoint: tokenEndpoint, // Reusing token endpoint for revocation
      // not implemented: revocation_endpoint_auth_methods_supported
      // not implemented: revocation_endpoint_auth_signing_alg_values_supported
      // not implemented: introspection_endpoint
      // not implemented: introspection_endpoint_auth_methods_supported
      // not implemented: introspection_endpoint_auth_signing_alg_values_supported
      code_challenge_methods_supported: this.serverCapabilities.codeChallengeMethods,
      authorization_response_iss_parameter_supported: true,
      // MCP Client ID Metadata Document support (CIMD)
      // Only enabled when global_fetch_strictly_public compat flag is set (for SSRF protection)
      client_id_metadata_document_supported:
        !!this.options.clientIdMetadataDocumentEnabled && this.hasGlobalFetchStrictlyPublic(),
    };

    return new Response(JSON.stringify(metadata), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /** Scopes that are baseline requirements of the protected resource itself. */
  private getProtectedResourceScopes(resourceServer: NormalizedResourceServer<Env>): string[] {
    return this.normalizeProtectedResourceScopes(resourceServer.resourceMetadata.scopes_supported ?? []);
  }

  /** Deduplicate resource-facing scopes and remove authorization-server-only capabilities. */
  private normalizeProtectedResourceScopes(scopes: string[]): string[] {
    return [...new Set(scopes)].filter((scope) => scope !== 'offline_access');
  }

  /**
   * Handles the OAuth Protected Resource Metadata endpoint
   * Implements RFC 9728 for OAuth Protected Resource Metadata
   * @param requestUrl - The URL of the incoming request
   * @returns Response with protected resource metadata
   */
  private handleProtectedResourceMetadata(requestUrl: URL, resourceServer: NormalizedResourceServer<Env>): Response {
    const rm = resourceServer.resourceMetadata;
    const authorizationServer = this.getAuthorizationServerIssuer(requestUrl);
    const resourceScopes = this.getProtectedResourceScopes(resourceServer);
    const metadata: Record<string, unknown> = {
      resource: rm.resource,
      authorization_servers: rm.authorization_servers ?? [authorizationServer],
      ...(resourceScopes.length > 0 ? { scopes_supported: resourceScopes } : {}),
      bearer_methods_supported: rm.bearer_methods_supported ?? ['header'],
    };

    if (rm.resource_name) {
      metadata.resource_name = rm.resource_name;
    }

    return new Response(JSON.stringify(metadata), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Handles client authentication and token issuance via the token endpoint
   * Supports authorization_code and refresh_token grant types
   * @param body - The parsed request body
   * @param clientInfo - The authenticated client information
   * @param env - Cloudflare Worker environment variables
   * @returns Response with token data or error
   */
  private async handleTokenRequest(
    body: any,
    clientInfo: ClientInfo,
    env: Env & ProviderEnv,
    requestUrl: URL,
    request: Request
  ): Promise<Response> {
    // Handle different grant types. Any `OAuthError` thrown from below
    // (typically from `tokenExchangeCallback` or any code it calls) is
    // converted into a structured OAuth 2.0 `/token` error response.
    // Non-`OAuthError` exceptions are re-thrown so unexpected failures
    // surface as `500 Internal Server Error` and stay visible.
    try {
      const grantType = body.grant_type;
      const supportedGrant =
        grantType === GrantType.AUTHORIZATION_CODE ||
        grantType === GrantType.REFRESH_TOKEN ||
        (grantType === GrantType.TOKEN_EXCHANGE && !!this.options.allowTokenExchangeGrant) ||
        (grantType === GrantType.JWT_BEARER && !!this.options.enterpriseManagedAuthorization);

      if (!supportedGrant) {
        return this.createErrorResponse('unsupported_grant_type', { description: 'Grant type not supported' });
      }

      // RFC 7591 §2 and RFC 6749 §10.6: a client may use only the grant types it registered.
      // refresh_token is implied by authorization_code, because this server issues a refresh
      // token with every authorization-code grant and RFC 7591 clients commonly register only
      // the latter. jwt-bearer stays gated by the enterprise-managed-authorization configuration.
      if (grantType !== GrantType.JWT_BEARER && Array.isArray(clientInfo.grantTypes)) {
        const registered = clientInfo.grantTypes;
        const permitted =
          registered.includes(grantType) ||
          (grantType === GrantType.REFRESH_TOKEN && registered.includes(GrantType.AUTHORIZATION_CODE));
        if (!permitted) {
          return this.createErrorResponse('unauthorized_client', {
            description: 'The client is not registered for this grant type',
          });
        }
      }

      // Validate an explicit resource before any grant-specific callbacks or
      // mutations. Tolerate legacy omission and inherit the configured resource.
      this.validateTokenRequestResourceIndicator(body.resource);

      if (grantType === GrantType.AUTHORIZATION_CODE) {
        return await this.handleAuthorizationCodeGrant(body, clientInfo, env);
      } else if (grantType === GrantType.REFRESH_TOKEN) {
        return await this.handleRefreshTokenGrant(body, clientInfo, env);
      } else if (grantType === GrantType.TOKEN_EXCHANGE && this.options.allowTokenExchangeGrant) {
        return await this.handleTokenExchangeGrant(body, clientInfo, env);
      } else if (grantType === GrantType.JWT_BEARER) {
        return await this.handleJwtBearerGrant(body, clientInfo, env, requestUrl, request);
      }

      // Exhaustive at runtime because unsupported grants returned above.
      throw new Error('Unreachable supported grant type');
    } catch (error) {
      const response = this.createOAuthErrorResponse(error);
      if (response) return response;
      throw error;
    }
  }

  /**
   * Build a structured OAuth token-endpoint response from an OAuth error.
   *
   * The supported form is throwing this package's exported `OAuthError` from
   * token issuance or `tokenExchangeCallback`. Anything else is re-thrown so
   * unexpected failures still surface as 500s.
   */
  private createOAuthErrorResponse(error: unknown): Response | undefined {
    if (!(error instanceof OAuthError)) return undefined;
    return this.createErrorResponse(error.code, error.options);
  }

  /**
   * Build a structured protected-resource response from an external-token error.
   *
   * Only this package's exported `ExternalTokenError` is converted. Standard
   * bearer failures receive an RFC 6750 / RFC 9728 challenge unless the caller
   * supplied one. Other errors retain the pre-existing behavior and are re-thrown.
   */
  private createExternalTokenErrorResponse(
    error: unknown,
    resourceMetadataUrl: string | undefined,
    resourceServer: NormalizedResourceServer<Env>
  ): Response | undefined {
    if (!(error instanceof ExternalTokenError)) return undefined;

    const headers = error.headers ?? {};
    const hasChallenge = Object.keys(headers).some((name) => name.toLowerCase() === 'www-authenticate');
    const isBearerError =
      (error.code === 'invalid_token' && error.statusCode === 401) ||
      (error.code === 'insufficient_scope' && error.statusCode === 403);

    let challengeHeaders: Record<string, string> | undefined;
    if (isBearerError && !hasChallenge) {
      const requiredScopes = [...new Set(error.requiredScopes ?? [])];
      if (requiredScopes.some((scope) => !isValidOAuthScopeToken(scope))) {
        throw new TypeError('ExternalTokenError requiredScopes must contain valid OAuth scope tokens');
      }
      challengeHeaders = {
        ...headers,
        'WWW-Authenticate': this.buildWwwAuthenticateHeader(
          resourceMetadataUrl,
          error.code,
          undefined,
          requiredScopes,
          resourceServer
        ),
      };
    }

    return this.createErrorResponse(error.code, {
      description: error.description,
      statusCode: error.statusCode,
      headers: challengeHeaders ?? headers,
    });
  }

  /**
   * Handles the authorization code grant type
   * Exchanges an authorization code for access and refresh tokens
   * @param body - The parsed request body
   * @param clientInfo - The authenticated client information
   * @param env - Cloudflare Worker environment variables
   * @returns Response with token data or error
   */
  private async handleAuthorizationCodeGrant(
    body: any,
    clientInfo: ClientInfo,
    env: Env & ProviderEnv
  ): Promise<Response> {
    const code = body.code;
    const redirectUri = body.redirect_uri;
    const codeVerifier = body.code_verifier;

    if (!code) {
      return this.createErrorResponse('invalid_request', { description: 'Authorization code is required' });
    }

    // Parse the authorization code to extract user ID and grant ID
    const codeParts = code.split(':');
    if (codeParts.length !== 3) {
      return this.createErrorResponse('invalid_grant', { description: 'Invalid authorization code format' });
    }

    const [userId, grantId, _] = codeParts;

    // Get the grant
    const grantKey = `grant:${userId}:${grantId}`;
    const grantData: Grant | null = await env.OAUTH_KV.get(grantKey, { type: 'json' });

    if (!grantData) {
      return this.createErrorResponse('invalid_grant', {
        description: 'Grant not found or authorization code expired',
      });
    }

    // Verify the authorization code by comparing its hash to the one in the grant.
    // This is checked before any other action so that a submitted code that does
    // not match the one issued for this grant has no effect on the grant.
    const codeHash = await hashSecret(code);
    if (!grantData.authCodeId || codeHash !== grantData.authCodeId) {
      return this.createErrorResponse('invalid_grant', { description: 'Invalid authorization code' });
    }

    // Verify client ID matches before taking any action on the grant
    if (grantData.clientId !== clientInfo.clientId) {
      return this.createErrorResponse('invalid_grant', { description: 'Client ID mismatch' });
    }

    // If the authorization code has already been exchanged (the wrapped key has
    // been removed), this is a replay of a valid code by the legitimate client.
    // Per RFC 6749 Section 10.5, revoke all tokens issued from the first exchange
    // as a precaution against replay attacks.
    if (!grantData.authCodeWrappedKey) {
      try {
        await this.createOAuthHelpers(env).revokeGrant(grantId, userId);
      } catch {
        // Best-effort revocation — always return invalid_grant per RFC 6749 §10.5
      }
      return this.createErrorResponse('invalid_grant', { description: 'Authorization code already used' });
    }

    // Validate the stored method before deciding whether PKCE is active. Older
    // versions could persist unknown methods; those grants must not fall back
    // to the non-PKCE path or be interpreted as plain.
    let codeChallengeMethod: PkceCodeChallengeMethod;
    try {
      codeChallengeMethod = grantData.codeChallenge
        ? validatePkceCodeChallengeMethod(this.serverCapabilities, grantData.codeChallengeMethod)
        : normalizePkceCodeChallengeMethod(grantData.codeChallengeMethod);
    } catch (error) {
      return this.createErrorResponse('invalid_grant', {
        description: error instanceof Error ? error.message : 'Invalid PKCE code_challenge_method',
      });
    }

    // Check if PKCE is being used
    const isPkceEnabled = !!grantData.codeChallenge;

    // OAuth 2.1 requires redirect_uri parameter unless PKCE is used
    if (!redirectUri && !isPkceEnabled) {
      return this.createErrorResponse('invalid_request', {
        description: 'redirect_uri is required when not using PKCE',
      });
    }

    // Verify redirect URI if provided
    if (redirectUri && !isValidRedirectUri(redirectUri, clientInfo.redirectUris)) {
      return this.createErrorResponse('invalid_grant', { description: 'Invalid redirect URI' });
    }

    // OAuth 2.1 §4.1.3: a redirect_uri on the token request must be identical to the one
    // the authorization request used. Grants written before the redirect URI was recorded
    // keep only the registered-list check above.
    if (redirectUri && grantData.redirectUri !== undefined && redirectUri !== grantData.redirectUri) {
      return this.createErrorResponse('invalid_grant', {
        description: 'redirect_uri does not match the authorization request',
      });
    }

    // Reject if code_verifier is provided but PKCE wasn't used in authorization
    if (!isPkceEnabled && codeVerifier) {
      return this.createErrorResponse('invalid_request', {
        description: 'code_verifier provided for a flow that did not use PKCE',
      });
    }

    // Verify PKCE code_verifier if code_challenge was provided during authorization
    if (isPkceEnabled) {
      if (!codeVerifier) {
        return this.createErrorResponse('invalid_request', { description: 'code_verifier is required for PKCE' });
      }

      // Verify the code verifier against the stored code challenge.
      let calculatedChallenge: string;
      if (codeChallengeMethod === 'S256') {
        // SHA-256 transformation for S256 method
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        calculatedChallenge = base64UrlEncode(String.fromCharCode(...hashArray));
      } else {
        // Plain method, direct comparison
        calculatedChallenge = codeVerifier;
      }

      if (calculatedChallenge !== grantData.codeChallenge) {
        return this.createErrorResponse('invalid_grant', { description: 'Invalid PKCE code_verifier' });
      }
    }

    // Resolve the token audience before consuming the authorization code.
    const resourceResolution = this.resolveTokenResource(body.resource, grantData);
    const audience = resourceResolution.audience;

    // Define the access token TTL, may be updated by callback if provided
    let accessTokenTTL = this.options.accessTokenTTL!;
    // Define the refresh token TTL, may be updated by callback if provided
    let refreshTokenTTL = this.options.refreshTokenTTL;

    // Get the encryption key for props by unwrapping it using the auth code
    const encryptionKey = await unwrapKeyWithToken(code, grantData.authCodeWrappedKey!);

    // Default to using the same encryption key and props for both grant and access token
    let grantEncryptionKey = encryptionKey;
    let accessTokenEncryptionKey = encryptionKey;
    let encryptedAccessTokenProps = grantData.encryptedProps;

    // Parse and validate scope parameter for downscoping (RFC 6749 Section 3.3)
    // The token request can include a scope parameter to request a subset of the granted scopes
    let tokenScopes: string[] = this.downscope(body.scope, grantData.scope);

    // Process token exchange callback if provided
    if (this.options.tokenExchangeCallback) {
      // Decrypt the existing props to provide them to the callback
      const decryptedProps = await decryptProps(encryptionKey, grantData.encryptedProps);

      // Default to using the original props for both grant and token
      let grantProps = decryptedProps;
      let accessTokenProps = decryptedProps;

      const callbackOptions: TokenExchangeCallbackOptions = {
        grantType: GrantType.AUTHORIZATION_CODE,
        clientId: clientInfo.clientId,
        subjectClientId: grantData.clientId,
        userId: userId,
        grantId: grantId,
        scope: grantData.scope,
        requestedScope: tokenScopes,
        resource: audience,
        props: decryptedProps,
      };

      const callbackResult = await Promise.resolve(this.options.tokenExchangeCallback(callbackOptions));

      if (callbackResult) {
        // Use the returned props if provided, otherwise keep the original props
        if (callbackResult.newProps) {
          grantProps = callbackResult.newProps;

          // If accessTokenProps wasn't explicitly specified, use the updated newProps for the token too
          // This ensures token props are updated when only newProps are specified
          if (!callbackResult.accessTokenProps) {
            accessTokenProps = callbackResult.newProps;
          }
        }

        // If accessTokenProps was explicitly specified, use those
        if (callbackResult.accessTokenProps) {
          accessTokenProps = callbackResult.accessTokenProps;
        }

        // If accessTokenTTL was specified, use that for this token
        if (callbackResult.accessTokenTTL !== undefined) {
          accessTokenTTL = callbackResult.accessTokenTTL;
        }

        // If refreshTokenTTL was specified, use that for this grant
        if ('refreshTokenTTL' in callbackResult) {
          refreshTokenTTL = callbackResult.refreshTokenTTL;
        }

        // If accessTokenScope was specified, use it for this token
        if (callbackResult.accessTokenScope) {
          tokenScopes = this.downscope(callbackResult.accessTokenScope, grantData.scope);
        }
      }

      // Re-encrypt the potentially updated grant props
      const grantResult = await encryptProps(grantProps);
      grantData.encryptedProps = grantResult.encryptedData;
      grantEncryptionKey = grantResult.key;

      // Re-encrypt the access token props if they're different from grant props
      if (accessTokenProps !== grantProps) {
        const tokenResult = await encryptProps(accessTokenProps);
        encryptedAccessTokenProps = tokenResult.encryptedData;
        accessTokenEncryptionKey = tokenResult.key;
      } else {
        // If they're the same, use the grant's encrypted data and key
        encryptedAccessTokenProps = grantData.encryptedProps;
        accessTokenEncryptionKey = grantEncryptionKey;
      }
    }

    // Reject callback-provided TTLs before consuming the authorization code,
    // backfilling its grant resource, or writing any grant/token state.
    if (!isValidAccessTokenTTL(accessTokenTTL)) {
      return this.createErrorResponse('invalid_request', {
        description: 'Requested token lifetime must be at least 60 seconds',
      });
    }

    // Resolve rollout policy before consuming the authorization code or writing
    // grant/token state. A policy outage must leave this code retryable.
    const accessTokenFormat = await this.selectAccessTokenFormat({
      env,
      resource: audience,
    });

    // Calculate the access token expiration time (after callback might have updated TTL)
    const now = Math.floor(Date.now() / 1000);

    // Determine if we should issue a refresh token
    const useRefreshToken = refreshTokenTTL !== 0;

    // Update the grant:
    // - Retain the auth code hash so a replayed code can be verified before acting
    // - Remove PKCE-related fields (one-time use)
    // - Remove auth code wrapped key (no longer needed); its absence marks the
    //   code as used so a subsequent replay can be detected
    delete grantData.codeChallenge;
    delete grantData.codeChallengeMethod;
    delete grantData.authCodeWrappedKey;

    // Only generate refresh token if issuing one
    let refreshToken: string | undefined;

    if (useRefreshToken) {
      const refreshTokenSecret = generateRandomString(TOKEN_LENGTH);
      refreshToken = `${userId}:${grantId}:${refreshTokenSecret}`;
      const refreshTokenId = await generateTokenId(refreshToken);
      const refreshTokenWrappedKey = await wrapKeyWithToken(refreshToken, grantEncryptionKey);

      // Calculate expiration if TTL is defined
      const expiresAt = refreshTokenTTL !== undefined ? now + refreshTokenTTL : undefined;

      // Add refresh token data to grant
      grantData.refreshTokenId = refreshTokenId;
      grantData.refreshTokenWrappedKey = refreshTokenWrappedKey;
      grantData.previousRefreshTokenId = undefined; // No previous token for first use
      grantData.previousRefreshTokenWrappedKey = undefined; // No previous token for first use
      grantData.expiresAt = expiresAt;
    }

    if (resourceResolution.grantResourceBackfill) {
      grantData.resource = resourceResolution.grantResourceBackfill;
    }

    // Mint (and for JWTs, sign) the access token before the grant write consumes the
    // authorization code, so a signing or key-resolution failure leaves the code
    // retryable instead of forcing the user to authorize again.
    const prepared = await this.prepareAccessToken({
      format: accessTokenFormat,
      userId,
      grantId,
      clientId: grantData.clientId,
      scope: tokenScopes,
      encryptedProps: encryptedAccessTokenProps,
      encryptionKey: accessTokenEncryptionKey,
      expiresIn: accessTokenTTL,
      audience,
      env,
    });

    // Save the updated grant with TTL matching refresh token expiration (if any).
    // This is the write that consumes the authorization code.
    await this.saveGrantWithTTL(env, grantKey, grantData, now);

    // Store the access token record with potentially narrowed scopes
    await this.persistAccessToken(env, prepared);
    const accessToken = prepared.accessToken;

    // Build the response
    const tokenResponse: TokenResponse = {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: accessTokenTTL,
      scope: tokenScopes.join(' '),
      resource: audience,
    };

    if (refreshToken) {
      tokenResponse.refresh_token = refreshToken;
    }

    // RFC 6749 §5.1 — responses containing tokens must not be cached.
    return new Response(JSON.stringify(tokenResponse), {
      headers: { 'Content-Type': 'application/json', ...NO_CACHE_HEADERS },
    });
  }

  /**
   * Handles the refresh token grant type
   * Issues a new access token using a refresh token
   * @param body - The parsed request body
   * @param clientInfo - The authenticated client information
   * @param env - Cloudflare Worker environment variables
   * @returns Response with token data or error
   */
  private async handleRefreshTokenGrant(body: any, clientInfo: ClientInfo, env: Env & ProviderEnv): Promise<Response> {
    const refreshToken = body.refresh_token;

    if (!refreshToken) {
      return this.createErrorResponse('invalid_request', { description: 'Refresh token is required' });
    }

    // Parse the token to extract user ID and grant ID
    const tokenParts = refreshToken.split(':');
    if (tokenParts.length !== 3) {
      return this.createErrorResponse('invalid_grant', { description: 'Invalid token format' });
    }

    const [userId, grantId, _] = tokenParts;

    // Calculate the token hash
    const providedTokenHash = await generateTokenId(refreshToken);

    // Get the associated grant using userId in the key
    const grantKey = `grant:${userId}:${grantId}`;
    const grantData: Grant | null = await env.OAUTH_KV.get(grantKey, { type: 'json' });

    if (!grantData) {
      return this.createErrorResponse('invalid_grant', { description: 'Grant not found' });
    }

    // Check if the provided token matches either the current or previous refresh token
    const isCurrentToken = grantData.refreshTokenId === providedTokenHash;
    const isPreviousToken = grantData.previousRefreshTokenId === providedTokenHash;

    if (!isCurrentToken && !isPreviousToken) {
      return this.createErrorResponse('invalid_grant', { description: 'Invalid refresh token' });
    }

    // Verify client ID matches
    if (grantData.clientId !== clientInfo.clientId) {
      return this.createErrorResponse('invalid_grant', { description: 'Client ID mismatch' });
    }

    // Check if the refresh token has expired.
    // Cloudflare KV requires absolute expirations to be at least 60 seconds in the
    // future. Rotating the grant re-saves it with `{ expiration: grantData.expiresAt }`,
    // so a grant with less than 60 seconds of life remaining cannot be written back to
    // KV and would otherwise surface as an uncaught "KV PUT failed: 400 Invalid
    // expiration" error. Treat such near-expiry grants as already expired instead.
    if (grantData.expiresAt !== undefined) {
      const now = Math.floor(Date.now() / 1000);
      if (grantData.expiresAt - now < KV_MIN_EXPIRATION_TTL_SECONDS) {
        return this.createErrorResponse('invalid_grant', { description: 'Refresh token has expired' });
      }
    }

    // Resolve the token audience before callbacks, rotation, or storage writes.
    const resourceResolution = this.resolveTokenResource(body.resource, grantData);
    const audience = resourceResolution.audience;

    // Define the access token TTL, may be updated by callback if provided
    let accessTokenTTL = this.options.accessTokenTTL!;

    // Determine which wrapped key to use for unwrapping
    let wrappedKeyToUse: string;
    if (isCurrentToken) {
      wrappedKeyToUse = grantData.refreshTokenWrappedKey!;
    } else {
      wrappedKeyToUse = grantData.previousRefreshTokenWrappedKey!;
    }

    // Unwrap the encryption key using the refresh token
    const encryptionKey = await unwrapKeyWithToken(refreshToken, wrappedKeyToUse);

    // Default to using the same encryption key and props for both grant and access token
    let grantEncryptionKey = encryptionKey;
    let accessTokenEncryptionKey = encryptionKey;
    let encryptedAccessTokenProps = grantData.encryptedProps;

    // Parse and validate scope parameter for downscoping (RFC 6749 Section 3.3)
    // The token request can include a scope parameter to request a subset of the granted scopes
    let tokenScopes = this.downscope(body.scope, grantData.scope);

    // Track whether grant props changed
    let grantPropsChanged = false;

    // Process token exchange callback if provided
    if (this.options.tokenExchangeCallback) {
      // Decrypt the existing props to provide them to the callback
      const decryptedProps = await decryptProps(encryptionKey, grantData.encryptedProps);

      // Default to using the original props for both grant and token
      let grantProps = decryptedProps;
      let accessTokenProps = decryptedProps;

      const callbackOptions: TokenExchangeCallbackOptions = {
        grantType: GrantType.REFRESH_TOKEN,
        clientId: clientInfo.clientId,
        subjectClientId: grantData.clientId,
        userId: userId,
        grantId: grantId,
        scope: grantData.scope,
        requestedScope: tokenScopes,
        resource: audience,
        props: decryptedProps,
      };

      const callbackResult = await Promise.resolve(this.options.tokenExchangeCallback(callbackOptions));

      if (callbackResult) {
        // Use the returned props if provided, otherwise keep the original props
        if (callbackResult.newProps) {
          grantProps = callbackResult.newProps;
          grantPropsChanged = true;

          // If accessTokenProps wasn't explicitly specified, use the updated newProps for the token too
          // This ensures token props are updated when only newProps are specified
          if (!callbackResult.accessTokenProps) {
            accessTokenProps = callbackResult.newProps;
          }
        }

        // If accessTokenProps was explicitly specified, use those
        if (callbackResult.accessTokenProps) {
          accessTokenProps = callbackResult.accessTokenProps;
        }

        // If accessTokenTTL was specified, use that for this token
        if (callbackResult.accessTokenTTL !== undefined) {
          accessTokenTTL = callbackResult.accessTokenTTL;
        }

        // refreshTokenTTL changes are not supported during refresh token exchange
        if ('refreshTokenTTL' in callbackResult) {
          return this.createErrorResponse('invalid_request', {
            description: 'refreshTokenTTL cannot be changed during refresh token exchange',
          });
        }

        // If accessTokenScope was specified, use it for this token
        if (callbackResult.accessTokenScope) {
          tokenScopes = this.downscope(callbackResult.accessTokenScope, grantData.scope);
        }
      }

      // Only re-encrypt the grant props if they've changed
      if (grantPropsChanged) {
        // Re-encrypt the updated grant props
        const grantResult = await encryptProps(grantProps);
        grantData.encryptedProps = grantResult.encryptedData;

        // If the encryption key changed, we need to re-wrap the previous token key
        if (grantResult.key !== encryptionKey) {
          grantEncryptionKey = grantResult.key;
          wrappedKeyToUse = await wrapKeyWithToken(refreshToken, grantEncryptionKey);
        } else {
          grantEncryptionKey = grantResult.key;
        }
      }

      // Re-encrypt the access token props if they're different from grant props
      if (accessTokenProps !== grantProps) {
        const tokenResult = await encryptProps(accessTokenProps);
        encryptedAccessTokenProps = tokenResult.encryptedData;
        accessTokenEncryptionKey = tokenResult.key;
      } else {
        // If they're the same, use the grant's encrypted data and key
        encryptedAccessTokenProps = grantData.encryptedProps;
        accessTokenEncryptionKey = grantEncryptionKey;
      }
    }

    // Calculate the access token expiration time (after callback might have updated TTL)
    const now = Math.floor(Date.now() / 1000);

    // Re-check expiry against the post-callback clock. The expiry check above runs before
    // the tokenExchangeCallback, which may take long enough (e.g. an upstream network
    // refresh) that the grant now has less than KV's 60-second minimum remaining. Both the
    // grant write below and the access token write (whose TTL is clamped to the grant's
    // remaining lifetime) would then be rejected by KV with a 400. Treat the grant as
    // expired here so we return a clean invalid_grant rather than an uncaught 500. No grant
    // mutation or token write has happened yet, so returning now leaves no partial state.
    if (grantData.expiresAt !== undefined && grantData.expiresAt - now < KV_MIN_EXPIRATION_TTL_SECONDS) {
      return this.createErrorResponse('invalid_grant', { description: 'Refresh token has expired' });
    }

    // Clamp access token TTL to not exceed refresh token's remaining lifetime
    if (grantData.expiresAt !== undefined) {
      const remainingRefreshTokenLifetime = grantData.expiresAt - now;
      if (remainingRefreshTokenLifetime > 0) {
        accessTokenTTL = Math.min(accessTokenTTL, remainingRefreshTokenLifetime);
      }
    }

    // The access token below is written with a relative `expirationTtl`, which KV rejects
    // when under 60 seconds. With the re-check above the grant has >=60s remaining, so the
    // only way to land here is a tokenExchangeCallback returning an `accessTokenTTL` below
    // the minimum. Reject before rotating/saving the grant rather than crashing on the write.
    if (!isValidAccessTokenTTL(accessTokenTTL)) {
      return this.createErrorResponse('invalid_request', {
        description: 'Requested token lifetime must be at least 60 seconds',
      });
    }

    // Resolve rollout policy before rotating the refresh token or persisting a
    // legacy-resource backfill, so a failed decision leaves the grant retryable.
    const accessTokenFormat = await this.selectAccessTokenFormat({
      env,
      resource: audience,
    });

    // Generate new refresh token for rotation
    const refreshTokenSecret = generateRandomString(TOKEN_LENGTH);
    const newRefreshToken = `${userId}:${grantId}:${refreshTokenSecret}`;
    const newRefreshTokenId = await generateTokenId(newRefreshToken);
    const newRefreshTokenWrappedKey = await wrapKeyWithToken(newRefreshToken, grantEncryptionKey);

    // Update the grant with the token rotation information
    // The token which the client used this time becomes the "previous" token, so that the client
    // can always use the same token again next time. This might technically violate OAuth 2.1's
    // requirement that refresh tokens be single-use. However, this requirement violates the laws
    // of distributed systems. It's important that the client can always retry when a transient
    // failure occurs. Under the strict requirement, if the failure occurred after the server
    // rotated the token but before the client managed to store the updated token, then the client
    // no longer has any valid refresh token and has effectively lost its grant. That's bad! So
    // instead, we don't invalidate the old token until the client successfully uses a newer token.
    // This provides most of the security benefits (tokens still rotate naturally) but without
    // being inherently unreliable.
    grantData.previousRefreshTokenId = providedTokenHash;
    grantData.previousRefreshTokenWrappedKey = wrappedKeyToUse;

    // The newly-generated token becomes the new "current" token.
    grantData.refreshTokenId = newRefreshTokenId;
    grantData.refreshTokenWrappedKey = newRefreshTokenWrappedKey;

    if (resourceResolution.grantResourceBackfill) {
      grantData.resource = resourceResolution.grantResourceBackfill;
    }

    // Save the updated grant with TTL if applicable
    await this.saveGrantWithTTL(env, grantKey, grantData, now);

    // Centralized issuance preserves old opaque-token validation while allowing
    // this AS to switch new and refreshed access tokens to RFC 9068 JWTs.
    const newAccessToken = await this.createAccessToken({
      format: accessTokenFormat,
      userId,
      grantId,
      clientId: grantData.clientId,
      scope: tokenScopes,
      // A refresh may narrow the token below the grant; the record denormalizes the grant.
      grantScope: grantData.scope,
      // The same read the TTL was clamped against, so `token.expiresAt <= grant.expiresAt`.
      issuedAt: now,
      encryptedProps: encryptedAccessTokenProps,
      encryptionKey: accessTokenEncryptionKey,
      expiresIn: accessTokenTTL,
      audience,
      env,
    });

    // Build the response
    const tokenResponse: TokenResponse = {
      access_token: newAccessToken,
      token_type: 'bearer',
      expires_in: accessTokenTTL,
      refresh_token: newRefreshToken,
      scope: tokenScopes.join(' '),
      resource: audience,
    };

    // RFC 6749 §5.1 — responses containing tokens must not be cached.
    return new Response(JSON.stringify(tokenResponse), {
      headers: { 'Content-Type': 'application/json', ...NO_CACHE_HEADERS },
    });
  }

  /**
   * Core token exchange logic (RFC 8693)
   * Performs the actual token exchange operation
   * This method is not private because `OAuthHelpers` needs to call it. Note that since
   * `OAuthProviderImpl` is not exposed outside this module, this is still effectively
   * module-private.
   * @param subjectToken - The subject token to exchange
   * @param requestedScopes - Optional requested scopes, limited to the subject token's scopes
   * @param requestedResource - Optional resource/audience; when present, it must match the configured canonical resource
   * @param expiresIn - Optional TTL override in seconds
   * @param clientInfo - The client making the exchange request
   * @param env - Cloudflare Worker environment variables
   * @returns Promise resolving to token response
   * @throws OAuthError with OAuth error code and description
   */
  async exchangeToken(
    subjectToken: string,
    requestedScopes: string[] | undefined,
    requestedResource: string | string[] | undefined,
    expiresIn: number | undefined,
    clientInfo: ClientInfo,
    env: Env & ProviderEnv
  ): Promise<TokenResponse & { issued_token_type?: string }> {
    // Unwrap and validate the subject token
    // RFC 8693 §2.2.2: an invalid or unacceptable subject token is `invalid_request`.
    const tokenSummary = await this.unwrapToken(subjectToken, env);
    if (!tokenSummary) {
      throw new OAuthError('invalid_request', { description: 'Invalid or expired subject token' });
    }

    // Get the grant to access resource information
    const grantKey = `grant:${tokenSummary.userId}:${tokenSummary.grantId}`;
    const grantData: Grant | null = await env.OAUTH_KV.get(grantKey, { type: 'json' });
    if (!grantData) {
      throw new OAuthError('invalid_request', { description: 'Grant not found' });
    }

    // A token is exchanged by the client it was issued to unless the deployment's
    // tokenExchangeCallback explicitly allows the cross-client case (RFC 8693 §1.1
    // impersonation is policy, never the default).
    const crossClientExchange = grantData.clientId !== clientInfo.clientId;
    const crossClientRejection = () =>
      new OAuthError('invalid_request', { description: 'The subject token was issued to a different client' });
    if (crossClientExchange && !this.options.tokenExchangeCallback) {
      throw crossClientRejection();
    }

    // An exchanged token inherits the subject token's scopes unless a narrower subset is requested.
    let tokenScopes: string[] = this.downscope(requestedScopes, tokenSummary.scope);

    const newAudience = this.resolveTokenExchangeResource(requestedResource, tokenSummary.audience);

    // Determine TTL for new token
    const now = Math.floor(Date.now() / 1000);
    const subjectTokenRemainingLifetime = tokenSummary.expiresAt - now;

    // The issued token's TTL is clamped to the subject token's remaining lifetime below.
    // Cloudflare KV rejects writes whose expiration is less than 60 seconds away, so a
    // subject token in its final <60s would produce an unstorable access token and an
    // uncaught 500. Treat such a near-expiry subject token as not exchangeable instead.
    if (subjectTokenRemainingLifetime < KV_MIN_EXPIRATION_TTL_SECONDS) {
      throw new OAuthError('invalid_request', {
        description: 'Subject token is too close to expiry to exchange',
      });
    }

    let accessTokenTTL = this.options.accessTokenTTL ?? DEFAULT_ACCESS_TOKEN_TTL;

    // If expiresIn is provided, use it but clamp to subject token's remaining lifetime
    if (expiresIn !== undefined) {
      if (expiresIn <= 0) {
        throw new OAuthError('invalid_request', { description: 'Invalid expires_in parameter' });
      }
      accessTokenTTL = Math.min(expiresIn, subjectTokenRemainingLifetime);
    } else {
      // Default to subject token's remaining lifetime or configured TTL, whichever is smaller
      accessTokenTTL = Math.min(accessTokenTTL, subjectTokenRemainingLifetime);
    }

    // Get the subject token data to access encryption key
    const subjectTokenData: Token | null = await env.OAUTH_KV.get(
      `token:${tokenSummary.userId}:${tokenSummary.grantId}:${tokenSummary.id}`,
      { type: 'json' }
    );

    if (!subjectTokenData) {
      throw new OAuthError('invalid_request', { description: 'Subject token data not found' });
    }

    // Unwrap the encryption key from the subject token
    const encryptionKey = await unwrapKeyWithToken(subjectToken, subjectTokenData.wrappedEncryptionKey);

    // Use the same props as the subject token
    let accessTokenEncryptionKey = encryptionKey;
    let encryptedAccessTokenProps = subjectTokenData.grant.encryptedProps;

    // Process token exchange callback if provided
    if (this.options.tokenExchangeCallback) {
      const decryptedProps = await decryptProps(encryptionKey, subjectTokenData.grant.encryptedProps);

      const callbackOptions: TokenExchangeCallbackOptions = {
        grantType: GrantType.TOKEN_EXCHANGE,
        clientId: clientInfo.clientId,
        subjectClientId: grantData.clientId,
        userId: tokenSummary.userId,
        grantId: tokenSummary.grantId,
        scope: tokenSummary.grant.scope,
        requestedScope: tokenScopes,
        resource: newAudience,
        props: decryptedProps,
      };

      const callbackResult = await Promise.resolve(this.options.tokenExchangeCallback(callbackOptions));
      if (crossClientExchange && callbackResult?.allowCrossClientExchange !== true) {
        throw crossClientRejection();
      }

      if (callbackResult) {
        let accessTokenProps = decryptedProps;

        if (callbackResult.newProps) {
          // If accessTokenProps wasn't explicitly specified, use the updated newProps
          if (!callbackResult.accessTokenProps) {
            accessTokenProps = callbackResult.newProps;
          }
        }

        if (callbackResult.accessTokenProps) {
          accessTokenProps = callbackResult.accessTokenProps;
        }

        if (callbackResult.accessTokenTTL !== undefined) {
          // Clamp to subject token's remaining lifetime
          accessTokenTTL = Math.min(callbackResult.accessTokenTTL, subjectTokenRemainingLifetime);
        }

        // Re-encrypt the access token props if they changed
        if (accessTokenProps !== decryptedProps) {
          const tokenResult = await encryptProps(accessTokenProps);
          encryptedAccessTokenProps = tokenResult.encryptedData;
          accessTokenEncryptionKey = tokenResult.key;
        }

        // If accessTokenScope was specified, use it for this token while preserving
        // the subject token as the upper bound.
        if (callbackResult.accessTokenScope) {
          tokenScopes = this.downscope(callbackResult.accessTokenScope, tokenSummary.scope);
        }
      }
    }

    // A client-requested `expires_in` (or a callback-supplied `accessTokenTTL`) may be
    // below KV's 60-second minimum even when the subject token has ample life remaining.
    // Reject rather than attempting an unstorable write that KV would reject with a 400.
    if (!isValidAccessTokenTTL(accessTokenTTL)) {
      throw new OAuthError('invalid_request', {
        description: 'Requested token lifetime must be at least 60 seconds',
      });
    }

    const accessTokenFormat = await this.selectAccessTokenFormat({
      env,
      resource: newAudience,
    });

    // Create and store access token
    const newAccessToken = await this.createAccessToken({
      format: accessTokenFormat,
      userId: tokenSummary.userId,
      grantId: tokenSummary.grantId,
      // The new token belongs to the authenticated exchanging client, which
      // may differ from the client that originally received the subject token.
      clientId: clientInfo.clientId,
      scope: tokenScopes,
      encryptedProps: encryptedAccessTokenProps,
      encryptionKey: accessTokenEncryptionKey,
      expiresIn: accessTokenTTL,
      audience: newAudience,
      env,
    });

    // Build the response per RFC 8693
    const tokenResponse: TokenResponse & { issued_token_type?: string } = {
      access_token: newAccessToken,
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      token_type: 'bearer',
      expires_in: accessTokenTTL,
      scope: tokenScopes.join(' '),
      resource: newAudience,
    };

    return tokenResponse;
  }

  /**
   * Handles OAuth 2.0 token exchange requests (RFC 8693)
   * Exchanges an existing access token for a new one with modified characteristics
   * @param body - The parsed request body
   * @param clientInfo - The authenticated client information
   * @param env - Cloudflare Worker environment variables
   * @returns Response with new token data or error
   */
  private async handleTokenExchangeGrant(body: any, clientInfo: ClientInfo, env: Env & ProviderEnv): Promise<Response> {
    const subjectToken = body.subject_token;
    const subjectTokenType = body.subject_token_type;
    const requestedTokenType = body.requested_token_type || 'urn:ietf:params:oauth:token-type:access_token';
    const requestedScope = body.scope;
    const requestedResource = body.resource;

    // Validate required parameters
    if (!subjectToken) {
      return this.createErrorResponse('invalid_request', { description: 'subject_token is required' });
    }

    if (!subjectTokenType) {
      return this.createErrorResponse('invalid_request', { description: 'subject_token_type is required' });
    }

    // Only support access token as subject token type
    if (subjectTokenType !== 'urn:ietf:params:oauth:token-type:access_token') {
      return this.createErrorResponse('invalid_request', {
        description: 'Only access_token subject_token_type is supported',
      });
    }

    // Only support access token as requested token type
    if (requestedTokenType !== 'urn:ietf:params:oauth:token-type:access_token') {
      return this.createErrorResponse('invalid_request', {
        description: 'Only access_token requested_token_type is supported',
      });
    }

    // Parse requested scopes
    let requestedScopes: string[] | undefined;
    if (requestedScope) {
      if (typeof requestedScope === 'string') {
        requestedScopes = requestedScope.split(' ').filter(Boolean);
      } else if (Array.isArray(requestedScope)) {
        requestedScopes = requestedScope;
      } else {
        return this.createErrorResponse('invalid_request', { description: 'Invalid scope parameter format' });
      }
    }

    // Parse expires_in
    let expiresIn: number | undefined;
    if (body.expires_in !== undefined) {
      const requestedTTL = parseInt(body.expires_in, 10);
      if (isNaN(requestedTTL) || requestedTTL <= 0) {
        return this.createErrorResponse('invalid_request', { description: 'Invalid expires_in parameter' });
      }
      expiresIn = requestedTTL;
    }

    // Perform the token exchange
    try {
      const tokenResponse = await this.exchangeToken(
        subjectToken,
        requestedScopes,
        requestedResource,
        expiresIn,
        clientInfo,
        env
      );

      // RFC 6749 §5.1 — responses containing tokens must not be cached.
      return new Response(JSON.stringify(tokenResponse), {
        headers: { 'Content-Type': 'application/json', ...NO_CACHE_HEADERS },
      });
    } catch (error) {
      // Convert OAuth errors into structured `/token` error responses,
      // preserving status, description, and headers. Anything else (e.g.
      // an unexpected runtime error from a callback) is re-thrown so it
      // surfaces as `500 Internal Server Error` and stays visible.
      const response = this.createOAuthErrorResponse(error);
      if (response) return response;
      throw error;
    }
  }

  /**
   * Handles the MCP Enterprise-Managed Authorization JWT-bearer grant.
   *
   * Acts as a thin shell around `runEmaPipeline`: gate non-EMA traffic, run
   * the pipeline, translate the typed `EmaValidationError` Result back to a
   * standard OAuth wire response. All validation logic lives in pure
   * functions in `src/ema/`.
   */
  private async handleJwtBearerGrant(
    body: any,
    clientInfo: ClientInfo,
    env: Env & ProviderEnv,
    requestUrl: URL,
    request: Request
  ): Promise<Response> {
    const enterpriseOptions = this.options.enterpriseManagedAuthorization;
    if (!enterpriseOptions) {
      return this.createErrorResponse('unsupported_grant_type', { description: 'Grant type not supported' });
    }

    // By default the EMA grant requires client authentication (per the MCP
    // enterprise-managed-authorization draft). Deployers can opt in to also
    // accepting public clients (e.g. CIMD clients, which are always
    // `token_endpoint_auth_method: 'none'`) via `allowPublicClients`. In that
    // case trust rests on the signature-verified, short-lived, single-use
    // ID-JAG assertion rather than on a separately presented client secret.
    if (clientInfo.tokenEndpointAuthMethod === 'none' && !enterpriseOptions.allowPublicClients) {
      return this.createErrorResponse('invalid_client', {
        description: 'Enterprise-managed authorization requires client authentication',
        statusCode: 401,
      });
    }

    const result = await this.runEmaPipeline({ body, clientInfo, env, requestUrl, request, enterpriseOptions });

    if (!result.ok) {
      const wire = emaErrorToWire(result.error);
      return this.createErrorResponse(
        wire.code,
        { description: wire.message },
        { category: 'enterprise-managed-authorization', reason: result.error.reason, detail: result.error }
      );
    }

    // RFC 6749 §5.1 — responses containing tokens must not be cached.
    return new Response(JSON.stringify(result.value), {
      headers: { 'Content-Type': 'application/json', ...NO_CACHE_HEADERS },
    });
  }

  /**
   * Runs the full EMA token-request pipeline as a chain of pure validators
   * and adapter calls. Each step short-circuits on the first failure.
   *
   * Sequence:
   *   parse → validate header → trust issuer → fetch JWKS → select key →
   *   verify signature → validate claims → select token format → prove signing key →
   *   record jti → parse scope → run mapper → validate mapper result →
   *   compute TTL → build token → write grant and token.
   *
   * The `jti` write consumes the assertion, and everything that can fail for a reason
   * unrelated to this assertion is settled before it: the rollout policy, and resolving
   * and proving the signing key. A key-store outage therefore leaves the assertion
   * retryable, while a replay is rejected before the deployer's `mapClaims` runs at all.
   */
  private async runEmaPipeline(args: {
    body: any;
    clientInfo: ClientInfo;
    env: Env & ProviderEnv;
    requestUrl: URL;
    request: Request;
    enterpriseOptions: EmaOptions<Env>;
  }): Promise<Result<TokenResponse, EmaValidationError>> {
    const { body, clientInfo, env, requestUrl, request, enterpriseOptions } = args;
    const { jwksProvider, jtiStore } = this;
    const configuredResource = this.resolveNewTokenResource(body.resource);
    // Unreachable: handleJwtBearerGrant short-circuits when enterpriseOptions is absent.
    if (!jwksProvider || !jtiStore) {
      throw new Error('EMA pipeline invoked without configured adapters');
    }
    const now = Math.floor(Date.now() / 1000);

    const parsed = parseIdJag(body.assertion, EMA_MAX_JWT_BYTES);
    if (!parsed.ok) return parsed;

    const header = validateIdJagHeader(parsed.value.header, EMA_ID_JAG_JWT_TYPE, EMA_SUPPORTED_JWT_ALGORITHMS);
    if (!header.ok) return header;
    const alg = header.value.alg as EmaSupportedAlg;

    const trustedIssuer = await resolveTrustedIssuer({
      iss: parsed.value.rawClaims.iss,
      alg,
      resolver: enterpriseOptions.trustedIssuers,
      env,
      request,
      clientInfo,
    });
    if (!trustedIssuer.ok) return trustedIssuer;

    const verified = await this.verifyAssertionSignature({
      parsed: parsed.value,
      header: header.value,
      trustedIssuer: trustedIssuer.value,
      jwksProvider,
      now,
    });
    if (!verified.ok) return verified;

    const claims = validateIdJagClaims({
      rawClaims: parsed.value.rawClaims,
      trustedIssuer: trustedIssuer.value,
      expectedAudience: trustedIssuer.value.audience ?? this.getAuthorizationServerIssuer(requestUrl),
      clientId: clientInfo.clientId,
      configuredResource,
      // The signed resource claim must always match the configured canonical
      // identifier exactly.
      now,
      clockSkewSeconds: enterpriseOptions.clockSkewSeconds ?? EMA_DEFAULT_CLOCK_SKEW_SECONDS,
      maxAssertionLifetimeSeconds:
        enterpriseOptions.maxAssertionLifetimeSeconds ?? EMA_DEFAULT_MAX_ASSERTION_LIFETIME_SECONDS,
    });
    if (!claims.ok) return claims;

    // Neither a rollout-policy failure nor an unusable signing key may consume the
    // one-use assertion JTI, so both are settled before it is marked used.
    const accessTokenFormat = await this.selectAccessTokenFormat({
      env,
      resource: configuredResource,
    });
    if (accessTokenFormat === 'jwt' && this.jwtAccessTokens) {
      // Resolve and prove the signing key before the one-use assertion is spent. `getJwks`
      // is that resolution, minus the published document nobody reads here.
      await this.jwtAccessTokens.getJwks(env);
    }

    // Consume the assertion before any application code runs. Single use has to mean the
    // deployer's mapClaims sees one presentation of an assertion, not one per replay.
    // Fresh clock read so the marker's TTL reflects the assertion's remaining lifetime.
    const markNow = Math.floor(Date.now() / 1000);
    const replay = await jtiStore.markUsed({
      issuer: claims.value.claims.iss,
      jti: claims.value.claims.jti,
      exp: claims.value.claims.exp,
      now: markNow,
      env,
    });
    if (!replay.ok) return replay;

    const requestedScope = parseEmaScopeParam(body.scope, claims.value.assertionScopes);
    if (!requestedScope.ok) return requestedScope;

    let mapperOutput: unknown;
    try {
      mapperOutput = await enterpriseOptions.mapClaims({
        claims: claims.value.claims,
        clientInfo,
        resource: configuredResource,
        requestedScope: requestedScope.value,
        request: args.request,
        env,
      });
    } catch {
      return err({ reason: 'mapper_threw' });
    }
    const mapped = validateEmaMapperResult(mapperOutput);
    if (!mapped.ok) return mapped;

    // Fresh clock read so both the TTL TOCTOU guard and the grant `createdAt`
    // reflect post-mapper time — the pipeline-start `now` is stale by the
    // time we reach this point (JWKS fetch + mapper invocation may take
    // hundreds of ms).
    const issueNow = Math.floor(Date.now() / 1000);
    const ttl = computeEmaAccessTokenTTL({
      configuredDefaultSeconds: this.options.accessTokenTTL ?? DEFAULT_ACCESS_TOKEN_TTL,
      assertionExp: claims.value.claims.exp,
      mapperTtl: mapped.value.accessTokenTTL,
      now: issueNow,
      minTtlSeconds: KV_MIN_EXPIRATION_TTL_SECONDS,
    });
    if (!ttl.ok) return ttl;

    // Mint and sign before either write, so a failure here leaves no orphaned grant or
    // token record; the signing key was already proven usable before the jti write above.
    const prepared = await this.prepareEmaAccessToken({
      format: accessTokenFormat,
      clientId: clientInfo.clientId,
      userId: mapped.value.userId,
      mapperScope: mapped.value.scope,
      mapperProps: mapped.value.props,
      mapperMetadata: mapped.value.metadata,
      assertionScopes: claims.value.assertionScopes,
      resource: configuredResource,
      accessTokenTTLSeconds: ttl.value,
      env,
      now: issueNow,
    });

    await this.saveGrantWithTTL(env, prepared.grantKey, prepared.grant, issueNow);
    await this.persistAccessToken(env, prepared.prepared);
    return ok(prepared.response);
  }

  /**
   * Verifies the ID-JAG signature against the trusted issuer's JWKS,
   * force-refreshing once on a `kid` miss to accommodate IdP key rotation.
   * Uses the in-memory cached JWKS fetcher with anti-DoS cool-down.
   */
  private async verifyAssertionSignature(args: {
    parsed: { header: Record<string, unknown>; signingInput: Uint8Array; signature: Uint8Array };
    header: { alg: string; kid?: string };
    trustedIssuer: EmaTrustedIssuer;
    jwksProvider: EmaJwksProvider;
    now: number;
  }): Promise<Result<void, EmaValidationError>> {
    const alg = args.header.alg as EmaSupportedAlg;
    const { jwksProvider } = args;

    const initialJwks = await jwksProvider.fetch(args.trustedIssuer, { forceRefresh: false, now: args.now });
    if (!initialJwks.ok) return initialJwks;

    let jwk = selectJwk(initialJwks.value, alg, args.header.kid);
    if (!jwk.ok && args.header.kid) {
      const refreshed = await jwksProvider.fetch(args.trustedIssuer, { forceRefresh: true, now: args.now });
      if (!refreshed.ok) return refreshed;
      jwk = selectJwk(refreshed.value, alg, args.header.kid);
    }
    if (!jwk.ok) return jwk;

    const verified = await verifyIdJagSignature({
      alg,
      jwk: jwk.value,
      signingInput: args.parsed.signingInput,
      signature: args.parsed.signature,
    });
    if (!verified) return err({ reason: 'signature_failed' });

    return ok(undefined);
  }

  /**
   * Mints the access token for an authorized EMA request.
   *
   * Uses the same grant + access-token machinery as the authorization-code
   * grant: encrypt the props, persist the grant under `grant:userId:grantId`,
   * and create an access token bound to the resource as audience.
   */
  /** Builds the grant record and access token for an enterprise-managed grant without writing either. */
  private async prepareEmaAccessToken(args: {
    format: AccessTokenFormat;
    clientId: string;
    userId: string;
    mapperScope: string[];
    mapperProps: unknown;
    mapperMetadata: unknown;
    assertionScopes: string[];
    resource: string;
    accessTokenTTLSeconds: number;
    env: Env & ProviderEnv;
    now: number;
  }): Promise<{ grantKey: string; grant: Grant; prepared: PreparedAccessToken; response: TokenResponse }> {
    // Defense-in-depth downscope: the mapper's output is filtered through the
    // assertion's scope claim (when present) so that a mapper returning an
    // out-of-band `admin` scope cannot escalate beyond what the IdP authorized.
    // `parseEmaScopeParam` already downscoped the *requested* scope before
    // the mapper saw it; this is the second layer that bounds the *mapper's*
    // output too. When the assertion carries no scope claim, the mapper has
    // full discretion (no ceiling to enforce).
    const tokenScopes =
      args.assertionScopes.length > 0 ? this.downscope(args.mapperScope, args.assertionScopes) : args.mapperScope;

    const grantId = generateRandomString(16);
    const { encryptedData, key: encryptionKey } = await encryptProps(args.mapperProps);
    const grant: Grant = {
      id: grantId,
      clientId: args.clientId,
      userId: args.userId,
      scope: tokenScopes,
      metadata: args.mapperMetadata ?? null,
      encryptedProps: encryptedData,
      createdAt: args.now,
      expiresAt: args.now + args.accessTokenTTLSeconds,
      resource: args.resource,
    };
    const prepared = await this.prepareAccessToken({
      format: args.format,
      userId: args.userId,
      grantId,
      clientId: args.clientId,
      scope: tokenScopes,
      encryptedProps: encryptedData,
      encryptionKey,
      expiresIn: args.accessTokenTTLSeconds,
      audience: args.resource,
      env: args.env,
    });

    return {
      grantKey: `grant:${args.userId}:${grantId}`,
      grant,
      prepared,
      response: {
        access_token: prepared.accessToken,
        token_type: 'bearer',
        expires_in: args.accessTokenTTLSeconds,
        scope: tokenScopes.join(' '),
        resource: args.resource,
      },
    };
  }

  /**
   * Handles OAuth 2.0 token revocation requests (RFC 7009)
   * @param body - The parsed request body containing revocation parameters
   * @param env - Cloudflare Worker environment variables
   * @returns Response confirming revocation or error
   */
  private async handleRevocationRequest(body: any, clientInfo: ClientInfo, env: Env & ProviderEnv): Promise<Response> {
    // Handle the revocation request with client ownership verification
    return this.revokeToken(body, clientInfo, env);
  }

  /**
   * - Access tokens: Revokes only the specific token
   * - Refresh tokens: Revokes the entire grant (access + refresh tokens)
   * Per RFC 7009 §2.1, the server MUST verify the token was issued to the client making the request.
   * @param body - The parsed request body containing token parameter
   * @param clientInfo - The authenticated client information
   * @param env - Cloudflare Worker environment variables
   * @returns Response confirming revocation or error
   */
  private async revokeToken(body: any, clientInfo: ClientInfo, env: Env & ProviderEnv): Promise<Response> {
    const token = body.token;
    const tokenTypeHint = body.token_type_hint;

    if (typeof token !== 'string' || !token) {
      return this.createErrorResponse('invalid_request', { description: 'Token parameter is required' });
    }

    if (this.jwtAccessTokens && jwtInternals(this.jwtAccessTokens).isOwnJwt(token)) {
      // Revocation is a lifecycle operation on issuer-owned state. It must keep
      // working even if the token's audience was removed from the live registry.
      const { tokenData } = await this.resolveInternalAccessToken(token, env, 'token-audience');
      if (tokenData) {
        await this.revokeAccessIfOwned(tokenData.id, tokenData.userId, tokenData.grantId, clientInfo, env);
      }
      // RFC 7009 deliberately does not reveal whether the submitted token was valid, and a
      // JWT access token has no refresh-token reading to fall back to.
      return new Response('', { status: 200 });
    }

    const tokenParts = token.split(':');
    if (tokenParts.length !== 3) {
      return new Response('', { status: 200 });
    }

    const [userId, grantId, _] = tokenParts;
    const tokenId = await generateTokenId(token);

    // Use token_type_hint to check the hinted type first (RFC 7009 §2.1).
    // Both paths verify client ownership before revoking (RFC 7009 §2.1).
    if (tokenTypeHint === 'refresh_token') {
      if (await this.revokeRefreshIfOwned(tokenId, userId, grantId, clientInfo, env)) {
        return new Response('', { status: 200 });
      }
      if (await this.revokeAccessIfOwned(tokenId, userId, grantId, clientInfo, env)) {
        return new Response('', { status: 200 });
      }
    } else {
      // Default and unknown hints: access token first (matches hint=access_token or no hint).
      if (await this.revokeAccessIfOwned(tokenId, userId, grantId, clientInfo, env)) {
        return new Response('', { status: 200 });
      }
      if (await this.revokeRefreshIfOwned(tokenId, userId, grantId, clientInfo, env)) {
        return new Response('', { status: 200 });
      }
    }
    return new Response('', { status: 200 });
  }

  /** Revoke an access token if it exists and belongs to the requesting client. */
  private async revokeAccessIfOwned(
    tokenId: string,
    userId: string,
    grantId: string,
    clientInfo: ClientInfo,
    env: Env & ProviderEnv
  ): Promise<boolean> {
    const tokenData: Token | null = await env.OAUTH_KV.get(`token:${userId}:${grantId}:${tokenId}`, { type: 'json' });
    if (!tokenData) return false;

    const tokenClientId = tokenData.grant?.clientId;
    if (tokenClientId !== undefined) {
      if (tokenClientId !== clientInfo.clientId) return false;
    } else {
      // Backward compatibility for token records written before access tokens
      // denormalized grant.clientId. Verify ownership from the backing grant.
      const grantData: Grant | null = await env.OAUTH_KV.get(`grant:${userId}:${grantId}`, { type: 'json' });
      if (grantData?.clientId !== clientInfo.clientId) return false;
    }

    await this.revokeSpecificAccessToken(tokenId, userId, grantId, env);
    return true;
  }

  /** Revoke a refresh token (and its grant) if it exists and belongs to the requesting client. */
  private async revokeRefreshIfOwned(
    tokenId: string,
    userId: string,
    grantId: string,
    clientInfo: ClientInfo,
    env: Env & ProviderEnv
  ): Promise<boolean> {
    const grantData: Grant | null = await env.OAUTH_KV.get(`grant:${userId}:${grantId}`, { type: 'json' });
    if (!grantData) return false;
    const isRefreshToken = grantData.refreshTokenId === tokenId || grantData.previousRefreshTokenId === tokenId;
    if (!isRefreshToken) return false;
    if (grantData.clientId !== clientInfo.clientId) return false;
    await this.createOAuthHelpers(env).revokeGrant(grantId, userId);
    return true;
  }

  /**
   * Revokes a specific access token without affecting the refresh token
   * @param tokenId - The hashed token ID
   * @param userId - The user ID extracted from the token
   * @param grantId - The grant ID extracted from the token
   * @param env - Cloudflare Worker environment variables
   */
  private async revokeSpecificAccessToken(
    tokenId: string,
    userId: string,
    grantId: string,
    env: Env & ProviderEnv
  ): Promise<void> {
    const tokenKey = `token:${userId}:${grantId}:${tokenId}`;
    await env.OAUTH_KV.delete(tokenKey);
  }

  /**
   * Handles the dynamic client registration endpoint (RFC 7591)
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @returns Response with client registration data or error
   */
  private async handleClientRegistration(request: Request, env: Env & ProviderEnv): Promise<Response> {
    if (!this.options.clientRegistrationEndpoint) {
      return this.createErrorResponse('not_implemented', {
        description: 'Client registration is not enabled',
        statusCode: 501,
      });
    }

    // Check method
    if (request.method !== 'POST') {
      return this.createErrorResponse('invalid_request', {
        description: 'Method not allowed',
        statusCode: 405,
        headers: { Allow: 'POST, OPTIONS' },
      });
    }

    // Check content length to ensure it's not too large (1 MiB limit)
    const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (contentLength > 1048576) {
      // 1 MiB = 1048576 bytes
      return this.createErrorResponse('invalid_request', {
        description: 'Request payload too large, must be under 1 MiB',
        statusCode: 413,
      });
    }

    // Clone before reading the body so a downstream clientRegistrationCallback
    // can still consume it (e.g. to verify a signature over the raw bytes).
    const callbackRequest = request.clone();

    // Parse client metadata with a size limitation. JSON syntax errors are
    // invalid_request; the typed metadata resolver reports invalid shapes as
    // invalid_client_metadata.
    let parsedJson: unknown;
    try {
      const text = await request.text();
      if (text.length > 1048576) {
        // Double-check text length
        return this.createErrorResponse('invalid_request', {
          description: 'Request payload too large, must be under 1 MiB',
          statusCode: 413,
        });
      }
      parsedJson = JSON.parse(text);
    } catch {
      return this.createErrorResponse('invalid_request', { description: 'Invalid JSON payload', statusCode: 400 });
    }

    let clientMetadata: Record<string, unknown>;
    let metadata: ResolvedDynamicClientRegistrationMetadata;
    try {
      clientMetadata = requireJsonObject(parsedJson);
      metadata = resolveDynamicClientRegistrationMetadata(clientMetadata, this.serverCapabilities);
    } catch (error) {
      return this.createErrorResponse('invalid_client_metadata', {
        description: error instanceof Error ? error.message : 'Invalid client metadata',
      });
    }

    const authMethod = metadata.tokenEndpointAuthMethod;
    const isPublicClient = authMethod === 'none';
    if (isPublicClient && this.options.disallowPublicClientRegistration) {
      return this.createErrorResponse('invalid_client_metadata', {
        description: 'Public client registration is not allowed',
      });
    }

    const clientId = generateRandomString(16);
    let clientSecret: string | undefined;
    let hashedSecret: string | undefined;
    if (!isPublicClient) {
      clientSecret = generateRandomString(32);
      hashedSecret = await hashSecret(clientSecret);
    }

    const clientInfo: StoredClientInfo = {
      clientId,
      redirectUris: metadata.redirectUris,
      clientName: metadata.clientName,
      logoUri: metadata.logoUri,
      clientUri: metadata.clientUri,
      policyUri: metadata.policyUri,
      tosUri: metadata.tosUri,
      jwksUri: metadata.jwksUri,
      i18n: metadata.i18n,
      contacts: metadata.contacts,
      grantTypes: metadata.grantTypes,
      responseTypes: metadata.responseTypes,
      registrationDate: Math.floor(Date.now() / 1000),
      tokenEndpointAuthMethod: authMethod,
      ...(metadata.authMethodExplicit ? { authMethodExplicit: true as const } : {}),
      ...(!isPublicClient && hashedSecret ? { clientSecret: hashedSecret } : {}),
    };

    if (this.options.clientRegistrationCallback) {
      // Note: RFC 7591 §3.1.1 `software_statement` claims are not processed by
      // this library. If the request body includes a `software_statement` JWT,
      // the callback is responsible for verifying its signature and applying
      // its claims (which per §2 MUST take precedence over plain JSON values).
      let callbackResult;
      try {
        callbackResult = await Promise.resolve(
          this.options.clientRegistrationCallback({ clientMetadata, request: callbackRequest })
        );
      } catch (error) {
        return this.createErrorResponse('server_error', {
          description: error instanceof Error ? error.message : 'Client registration callback failed',
          statusCode: 500,
        });
      }

      if (callbackResult !== undefined) {
        // Default to RFC 7591 §3.2.2 — `invalid_client_metadata` / 400. Callbacks
        // rejecting for non-metadata reasons (missing IAT, policy denial) should
        // override `code` / `status` explicitly.
        return this.createErrorResponse(callbackResult.code || 'invalid_client_metadata', {
          description: callbackResult.description || 'Client registration denied',
          statusCode: callbackResult.status ?? 400,
        });
      }
    }

    // Store client info with optional TTL for DCR clients
    const clientKvOptions: { expirationTtl?: number } = {};
    if (this.options.clientRegistrationTTL !== undefined) {
      clientKvOptions.expirationTtl = this.options.clientRegistrationTTL;
    }
    await env.OAUTH_KV.put(`client:${clientInfo.clientId}`, JSON.stringify(clientInfo), clientKvOptions);

    // Return client information with the original unhashed secret
    const response: Record<string, any> = {
      client_id: clientInfo.clientId,
      redirect_uris: clientInfo.redirectUris,
      client_name: clientInfo.clientName,
      logo_uri: clientInfo.logoUri,
      client_uri: clientInfo.clientUri,
      policy_uri: clientInfo.policyUri,
      tos_uri: clientInfo.tosUri,
      jwks_uri: clientInfo.jwksUri,
      contacts: clientInfo.contacts,
      grant_types: clientInfo.grantTypes,
      response_types: clientInfo.responseTypes,
      token_endpoint_auth_method: clientInfo.tokenEndpointAuthMethod,
      client_id_issued_at: clientInfo.registrationDate,
    };

    // RFC 7591 §2.2: echo internationalized variants back as top-level
    // `field#tag` members alongside their canonical counterparts. Skip any key
    // already present so a localized variant can never shadow a canonical
    // response member (i18n keys always contain `#`, but this stays correct
    // even if a future canonical field name were to include one).
    if (clientInfo.i18n) {
      for (const [key, value] of Object.entries(clientInfo.i18n)) {
        if (!(key in response)) response[key] = value;
      }
    }

    // Only include client_secret for confidential clients (RFC 7591 §3.2.1)
    if (clientSecret) {
      response.client_secret = clientSecret; // Return the original unhashed secret
      response.client_secret_expires_at =
        this.options.clientRegistrationTTL && clientInfo.registrationDate
          ? clientInfo.registrationDate + this.options.clientRegistrationTTL
          : 0;
      response.client_secret_issued_at = clientInfo.registrationDate;
    }

    return new Response(JSON.stringify(response), {
      status: 201,
      headers: { 'Content-Type': 'application/json', ...NO_CACHE_HEADERS },
    });
  }

  /**
   * Handles API requests by validating the access token and calling the API handler
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @param ctx - Cloudflare Worker execution context
   * @returns Response from the API handler or error
   */
  private async handleApiRequest(
    request: Request,
    env: Env & ProviderEnv,
    ctx: ExecutionContext,
    apiRoute: NormalizedApiRoute<Env>
  ): Promise<Response> {
    const url = new URL(request.url);
    const { resourceServer } = apiRoute;
    const configuredResource = resourceServer.resourceMetadata.resource;
    const externalTokenResolver = resourceServer.resolveExternalToken;
    const resourceMetadataUrl = this.getResourceMetadataUrlForRequest(url, resourceServer);
    const challenge = (error?: string, description?: string, scopes: string[] = []) =>
      this.buildWwwAuthenticateHeader(resourceMetadataUrl, error, description, scopes, resourceServer);

    // Get access token from Authorization header
    const authHeader = request.headers.get('Authorization');

    // RFC 7235 §2.1: the authentication scheme is case-insensitive, so `bearer` and
    // `BEARER` are as valid as `Bearer`.
    const bearerMatch = authHeader ? /^Bearer[\t ]+([^\s,]+)$/i.exec(authHeader) : null;
    if (!bearerMatch) {
      // OAuth 2.1 §5.3.2: when authentication information is absent or uses an
      // unsupported scheme, challenge without an error code or description.
      return new Response(null, {
        status: 401,
        headers: {
          ...NO_CACHE_HEADERS,
          'WWW-Authenticate': challenge(),
        },
      });
    }

    const accessToken = bearerMatch[1];
    const { tokenData, isOwnJwt } = await this.resolveInternalAccessToken(accessToken, env);

    // An issuer-owned JWT always fails closed. Unknown credentials may still be
    // handled by the resource's explicit external token resolver.
    if (!tokenData && (isOwnJwt || !externalTokenResolver)) {
      return this.createErrorResponse('invalid_token', {
        description: 'Invalid access token',
        statusCode: 401,
        headers: {
          'WWW-Authenticate': challenge('invalid_token'),
        },
      });
    }

    // Internal token data was found in KV, so we check for expiration and set the context props
    if (tokenData) {
      const tokenAudience = this.resolveStoredTokenAudience(tokenData.audience);
      if (!isExactResource(tokenAudience, configuredResource)) {
        return this.createErrorResponse('invalid_token', {
          description: 'Access token is not bound to the configured resource',
          statusCode: 401,
          headers: {
            'WWW-Authenticate': challenge('invalid_token'),
          },
        });
      }

      // Check if token is expired (should be auto-deleted by KV TTL, but double-check)
      const now = Math.floor(Date.now() / 1000);
      if (tokenData.expiresAt < now) {
        return this.createErrorResponse('invalid_token', {
          description: 'Access token expired',
          statusCode: 401,
          headers: {
            'WWW-Authenticate': challenge('invalid_token'),
          },
        });
      }

      // Validate audience according to RFC 7519 Section 4.1.3
      // "If the principal processing the claim does not identify itself with a value in the
      // 'aud' claim when this claim is present, then the JWT MUST be rejected."
      if (tokenAudience) {
        const requestUrl = new URL(request.url);
        const resourceServer = `${requestUrl.protocol}//${requestUrl.host}${requestUrl.pathname}${requestUrl.search}`;
        const audiences = Array.isArray(tokenAudience) ? tokenAudience : [tokenAudience];

        // Check if any audience matches (RFC 3986: case-insensitive hostname comparison)
        const matches = audiences.some((aud) => audienceMatches(resourceServer, aud));
        if (!matches) {
          return this.createErrorResponse('invalid_token', {
            description: 'Token audience does not match resource server',
            statusCode: 401,
            headers: {
              'WWW-Authenticate': challenge('invalid_token', 'Invalid audience'),
            },
          });
        }
      }

      // Unwrap the encryption key using the access token
      const encryptionKey = await unwrapKeyWithToken(accessToken, tokenData.wrappedEncryptionKey);

      // Decrypt the props
      const decryptedProps = await decryptProps(encryptionKey, tokenData.grant.encryptedProps);

      // Set the decrypted props on the context object
      (ctx as MutableExecutionContext).props = decryptedProps;
    } else if (externalTokenResolver) {
      // No token data was found, so we validate the provided token with the provided validator.
      // Convert only the package's exported ExternalTokenError into a structured response;
      // every other thrown value retains the pre-existing failure behavior.
      let ext: ResolveExternalTokenResult | null;
      try {
        ext = await externalTokenResolver({ token: accessToken, request, env });
      } catch (error) {
        const response = this.createExternalTokenErrorResponse(error, resourceMetadataUrl, resourceServer);
        if (response) return response;
        throw error;
      }

      // Failed external validation
      if (!ext) {
        return this.createErrorResponse('invalid_token', {
          description: 'Invalid access token',
          statusCode: 401,
          headers: {
            'WWW-Authenticate': challenge('invalid_token'),
          },
        });
      }

      // The resolver contract is one string; a stored 0.x array is tolerated only for
      // the provider's own token records.
      if (typeof ext.audience !== 'string' || !isExactResource(ext.audience, configuredResource)) {
        return this.createErrorResponse('invalid_token', {
          description: 'External access token is not bound to the configured resource',
          statusCode: 401,
          headers: {
            'WWW-Authenticate': challenge('invalid_token'),
          },
        });
      }

      // Validate that tokens were issued specifically for them
      if (ext.audience) {
        const requestUrl = new URL(request.url);
        const resourceServer = `${requestUrl.protocol}//${requestUrl.host}${requestUrl.pathname}${requestUrl.search}`;
        const audiences = Array.isArray(ext.audience) ? ext.audience : [ext.audience];

        // Check if any audience matches (RFC 3986: case-insensitive hostname comparison)
        const matches = audiences.some((aud) => audienceMatches(resourceServer, aud));
        if (!matches) {
          return this.createErrorResponse('invalid_token', {
            description: 'Token audience does not match resource server',
            statusCode: 401,
            headers: {
              'WWW-Authenticate': challenge('invalid_token', 'Invalid audience'),
            },
          });
        }
      }

      // Set the external props on the context object
      (ctx as MutableExecutionContext).props = ext.props;
    }

    // Inject OAuth helpers into env if not already present
    if (!(env as Record<string, unknown>).OAUTH_PROVIDER) {
      (env as Record<string, unknown>).OAUTH_PROVIDER = this.createOAuthHelpers(env);
    }

    const apiHandler = apiRoute.handler;

    // Call the API handler based on its type
    if (apiHandler.type === HandlerType.EXPORTED_HANDLER) {
      // It's an object with a fetch method
      return apiHandler.handler.fetch(request as Parameters<ExportedHandlerWithFetch['fetch']>[0], env, ctx);
    } else {
      // It's a WorkerEntrypoint class - instantiate it with ctx and env in that order
      const handler = new apiHandler.handler(ctx, env);
      return handler.fetch(request);
    }
  }
  /**
   * Creates the helper methods object for OAuth operations
   * This is passed to the handler functions to allow them to interact with the OAuth system
   * @param env - Cloudflare Worker environment variables
   * @returns An instance of OAuthHelpers
   */
  public createOAuthHelpers<Props = any>(env: Env & ProviderEnv): OAuthHelpers<Props> {
    return new OAuthHelpersImpl<Env, Props>(env, this);
  }

  /** Resolve a declared resource to its canonical spelling, or throw at module initialization. */
  requireDeclaredResource(resource: string): string {
    const canonical = typeof resource === 'string' ? this.findConfiguredResource(resource) : undefined;
    if (!canonical) {
      throw new TypeError(`${String(resource)} is not declared in resources`);
    }
    return canonical;
  }

  /** Host a declared resource in this Worker during module initialization. */
  registerResourceServer(configuration: InternalProtectedResourceConfiguration<Env>): string {
    const canonical = this.requireDeclaredResource(configuration.resourceMetadata?.resource as string);
    const resourceServer = this.resourceServers.find((server) => server.resourceMetadata.resource === canonical)!;
    if (resourceServer.apiHandler) {
      throw new TypeError(`A protected resource is already hosted for ${canonical}`);
    }
    const resourceMetadata = this.snapshotResourceMetadata({ ...configuration.resourceMetadata, resource: canonical });
    this.validateResourceMetadataOptions(resourceMetadata);
    if (
      this.explicitIssuer &&
      resourceMetadata.authorization_servers &&
      !resourceMetadata.authorization_servers.some((issuer) => resourceMatches(issuer, this.explicitIssuer!))
    ) {
      throw new TypeError(
        `resourceMetadata.authorization_servers for ${canonical} must include ${this.explicitIssuer}`
      );
    }

    const previous: NormalizedResourceServer<Env> = { ...resourceServer };
    resourceServer.resourceMetadata = resourceMetadata;
    resourceServer.apiHandler = this.validateHandler(configuration.handler, 'handler');
    resourceServer.resolveExternalToken = configuration.resolveExternalToken;
    this.typedApiHandlers.push({ route: canonical, handler: resourceServer.apiHandler, resourceServer });
    try {
      this.validateResourceRouteIsolation();
    } catch (error) {
      this.typedApiHandlers.pop();
      Object.assign(resourceServer, previous);
      throw error;
    }
    return canonical;
  }

  /**
   * Saves a grant to KV with appropriate TTL based on expiration
   * @param env - The environment bindings
   * @param grantKey - The KV key for the grant
   * @param grantData - The grant data to save
   * @param now - Current timestamp in seconds
   */
  private async saveGrantWithTTL(
    env: Env & ProviderEnv,
    grantKey: string,
    grantData: Grant,
    now: number
  ): Promise<void> {
    // Use absolute expiration timestamp if grant has an expiration.
    // Cloudflare KV rejects expirations less than 60 seconds in the future, so clamp the
    // absolute expiration to that minimum plus a small margin (KV validates against its own
    // clock at write time, so an exact `now + 60` can be rejected under latency/skew). This
    // is defense-in-depth: callers that refresh near-expiry grants already treat them as
    // expired, but clamping here also protects freshly-issued grants configured with a very
    // short refreshTokenTTL.
    const minExpiration = now + KV_MIN_EXPIRATION_TTL_SECONDS + KV_EXPIRATION_CLAMP_MARGIN_SECONDS;
    const kvOptions =
      grantData.expiresAt !== undefined ? { expiration: Math.max(grantData.expiresAt, minExpiration) } : {};
    try {
      await env.OAUTH_KV.put(grantKey, JSON.stringify(grantData), kvOptions);
    } catch (error) {
      this.throwRetryableTokenStorageErrorIfKvRateLimited(error);
      throw error;
    }
  }

  private throwRetryableTokenStorageErrorIfKvRateLimited(error: unknown): never | void {
    if (!this.isKvRateLimitError(error)) return;
    throw new OAuthError('temporarily_unavailable', {
      description: 'Token issuance is temporarily unavailable; retry shortly',
      statusCode: 429,
      headers: { 'Retry-After': '30' },
    });
  }

  private isKvRateLimitError(error: unknown): boolean {
    if (!(error instanceof Error)) return false;
    return /KV .*failed: 429 Too Many Requests/i.test(error.message) || /429 Too Many Requests/i.test(error.message);
  }

  /**
   * Fetches client information from KV storage or via CIMD (Client ID Metadata Document)
   * This method is not private because `OAuthHelpers` needs to call it. Note that since
   * `OAuthProviderImpl` is not exposed outside this module, this is still effectively
   * module-private.
   *
   * Supports CIMD: If clientId is an HTTPS URL with a non-root path, the metadata
   * document will be fetched from that URL instead of looking up in KV storage.
   *
   * @param env - Cloudflare Worker environment variables
   * @param clientId - The client ID to look up (can be a regular ID or an HTTPS URL for CIMD)
   * @returns The client information, or null if the client does not exist. Null means
   * definitive absence; failures to determine the answer throw instead (KV errors
   * propagate, and a CIMD metadata fetch failure throws `CimdFetchError`), so an
   * upstream outage is distinguishable from an unregistered client.
   */
  async getClient(env: Env & ProviderEnv, clientId: string): Promise<StoredClientInfo | null> {
    // Check if this is a CIMD (Client ID Metadata Document) URL
    if (this.isClientMetadataUrl(clientId)) {
      if (!this.options.clientIdMetadataDocumentEnabled) {
        // CIMD not enabled — treat as standard KV lookup
        const clientKey = `client:${clientId}`;
        return env.OAUTH_KV.get(clientKey, { type: 'json' });
      }
      if (!this.hasGlobalFetchStrictlyPublic()) {
        throw new Error(`CIMD is enabled but 'global_fetch_strictly_public' compatibility flag is not set.`);
      }
      try {
        return await fetchClientIdMetadataDocument(clientId, this.serverCapabilities);
      } catch (error) {
        // CIMD fetch failed (size limit, timeout, HTTP error, invalid metadata, etc.)
        // Throw a tagged error rather than returning null: KV-backed lookups
        // already let infrastructure failures propagate, and conflating a fetch
        // failure with "client not found" hides upstream outages from deployers
        // (e.g. a WAF blocking the metadata URL reads as an unregistered client).
        console.warn(`CIMD fetch failed for ${clientId}:`, error instanceof Error ? error.message : error);
        throw new CimdFetchError(clientId, error);
      }
    }

    // Standard KV lookup
    const clientKey = `client:${clientId}`;
    return env.OAUTH_KV.get(clientKey, { type: 'json' });
  }

  /** Resolve a value to the registry's canonical spelling, requiring one value. */
  /**
   * Resolve a stored grant or token resource. A 0.x record may hold an array; it resolves
   * when exactly one configured resource appears in it, so multi-audience grants for two
   * resources this server still hosts are ambiguous and fail closed.
   */
  private findStoredConfiguredResource(value: string | string[] | undefined): string | undefined {
    if (!Array.isArray(value)) return this.findConfiguredResource(value);
    const matches = new Set<string>();
    for (const entry of value) {
      const configured = this.findConfiguredResource(entry);
      if (configured) matches.add(configured);
    }
    return matches.size === 1 ? [...matches][0] : undefined;
  }

  findConfiguredResource(value: string | string[] | undefined): string | undefined {
    // RFC 8707 §2.1 lets a request repeat the parameter; identical repetitions name one resource.
    const distinct = Array.isArray(value) ? [...new Set(value)] : [value];
    const singular = distinct.length === 1 ? distinct[0] : undefined;
    if (typeof singular !== 'string' || !validateResourceUri(singular)) return undefined;
    return this.resourceServers
      .map((server) => server.resourceMetadata.resource)
      .find((configured) => isExactResource(singular, configured));
  }

  /** Select the audience for a new interactive authorization. */
  resolveAuthorizationRequestResource(requestedResource: string | string[] | undefined): string {
    if (requestedResource === undefined) {
      const defaultResource = this.getDefaultAuthorizationResource();
      if (defaultResource) return defaultResource;
      throw new AuthorizationError('invalid_target', {
        description: 'The resource parameter is required when the authorization server has multiple resources',
      });
    }
    const configured = this.findConfiguredResource(requestedResource);
    if (!configured) {
      throw new AuthorizationError('invalid_target', {
        description: 'The resource parameter must name exactly one configured protected resource',
      });
    }
    return configured;
  }

  /** Whether an existing grant belongs to the replacement bucket for a resource. */
  shouldReplaceGrantForResource(grantResource: string | string[] | undefined, resource: string): boolean {
    if (grantResource === undefined) return this.getLegacyGrantResource() === resource;
    return isExactResource(grantResource, resource);
  }

  /** Select the audience for a new non-interactive grant such as EMA. */
  private resolveNewTokenResource(requestedResource: string | string[] | undefined): string {
    try {
      return this.resolveAuthorizationRequestResource(requestedResource);
    } catch (error) {
      if (error instanceof AuthorizationError) {
        throw new OAuthError('invalid_target', { description: error.description });
      }
      throw error;
    }
  }

  /** Validate explicit resource syntax and configured-resource policy. */
  private validateTokenRequestResourceIndicator(requestedResource: string | string[] | undefined): void {
    if (requestedResource === undefined) return;
    if (!this.findConfiguredResource(requestedResource)) {
      throw new OAuthError('invalid_target', {
        description: 'The resource parameter must name exactly one configured protected resource',
      });
    }
  }

  /** Resolve token exchange strictly within the subject token's audience ceiling. */
  private resolveTokenExchangeResource(
    requestedResource: string | string[] | undefined,
    subjectResource: string | string[] | undefined
  ): string {
    const subjectAudience = this.findStoredConfiguredResource(this.resolveStoredTokenAudience(subjectResource));
    if (!subjectAudience) {
      throw new OAuthError('invalid_target', {
        description: 'Subject token is not bound to a configured resource',
      });
    }

    const resourceWasProvided = requestedResource !== undefined;
    const requestedAudience = resourceWasProvided ? this.findConfiguredResource(requestedResource) : undefined;
    if (resourceWasProvided && (!requestedAudience || requestedAudience !== subjectAudience)) {
      throw new OAuthError('invalid_target', {
        description: 'The requested resource must exactly match the subject token audience',
      });
    }
    return subjectAudience;
  }

  /**
   * Resolves an access-token audience from a token request and its authorization grant.
   * The configured canonical resource is inherited when omitted and cannot be overridden.
   */
  private resolveTokenResource(
    requestedResource: string | string[] | undefined,
    grant: Pick<Grant, 'resource'>
  ): {
    audience: string;
    grantResourceBackfill?: string;
  } {
    const grantedResource = grant.resource;
    const resourceWasProvided = requestedResource !== undefined;
    const grantResourceWasStored = grantedResource !== undefined;
    const canonicalGrantResource = this.findStoredConfiguredResource(grantedResource);
    const canonicalRequestedResource = resourceWasProvided ? this.findConfiguredResource(requestedResource) : undefined;

    if (grantResourceWasStored && !canonicalGrantResource) {
      // A grant defect, not a request defect: `invalid_grant` makes conformant clients
      // discard their tokens and re-authorize, where `invalid_target` would make them fail.
      throw new OAuthError('invalid_grant', {
        description: 'The authorization grant is not bound to a configured resource',
      });
    }
    if (canonicalGrantResource) {
      if (resourceWasProvided && canonicalRequestedResource !== canonicalGrantResource) {
        throw new OAuthError('invalid_target', {
          description: 'The requested resource does not match the authorization grant',
        });
      }
      return {
        audience: canonicalGrantResource,
        ...(grantedResource === canonicalGrantResource ? {} : { grantResourceBackfill: canonicalGrantResource }),
      };
    }

    const legacyGrantResource = this.getLegacyGrantResource();
    if (!legacyGrantResource) {
      throw new OAuthError('invalid_grant', {
        description: 'This legacy authorization grant has no resource binding and must be reauthorized',
      });
    }
    if (resourceWasProvided && canonicalRequestedResource !== legacyGrantResource) {
      throw new OAuthError('invalid_target', {
        description: 'The requested resource does not match the server legacy-grant migration policy',
      });
    }
    return {
      audience: legacyGrantResource,
      grantResourceBackfill: legacyGrantResource,
    };
  }

  async selectAccessTokenFormat(input: AccessTokenFormatInput<Env>): Promise<AccessTokenFormat> {
    if (!this.jwtAccessTokens) return 'opaque';
    // Installing `jwtAccessTokens` turns on the reader, the signer and the JWKS; it does not
    // start writing JWTs. A deployment that flipped issuance the moment the component was
    // configured would mint tokens its resource servers cannot yet verify, which is the
    // one ordering the rollout procedure exists to prevent.
    if (!this.accessTokenFormatPolicy) return 'opaque';

    // Policies may be shared with application code. Give them an immutable
    // snapshot of only the canonical rollout inputs available before any
    // grant, authorization-code, replay-marker, or token mutation.
    const policyInput = Object.freeze({ ...input });
    const format = await this.accessTokenFormatPolicy(policyInput);
    if (format !== 'opaque' && format !== 'jwt') {
      throw new OAuthError('server_error', {
        description: "accessTokenFormat must return either 'opaque' or 'jwt'",
        statusCode: 500,
      });
    }
    return format;
  }

  /**
   * Creates and stores an access token
   * @param params - Options for creating the access token
   * @returns The access token string
   */
  /**
   * Implicit flow issuance. The grant is written only once the token exists, so a signing
   * or key-resolution failure leaves no grant behind, as on the authorization-code and
   * enterprise-assertion paths. There is no one-shot credential here, but a failed attempt
   * would otherwise leave a TTL-less grant the user sees as a live consent.
   */
  async createImplicitAccessToken(
    params: CreateAccessTokenOptions<Env>,
    grantKey: string,
    grant: Grant
  ): Promise<string> {
    const prepared = await this.prepareAccessToken(params);
    await params.env.OAUTH_KV.put(grantKey, JSON.stringify(grant));
    await this.persistAccessToken(params.env, prepared);
    return prepared.accessToken;
  }

  async createAccessToken(params: CreateAccessTokenOptions<Env>): Promise<string> {
    const prepared = await this.prepareAccessToken(params);
    await this.persistAccessToken(params.env, prepared);
    return prepared.accessToken;
  }

  /**
   * Build the access token and its state record without touching KV, so the caller can
   * order the signing against whatever it writes. The authorization-code path signs
   * before the grant write that consumes the code, so a signing or key-resolution failure
   * leaves the code retryable. The enterprise-assertion path must consume its assertion
   * before the mapper runs, so it proves the signing key is resolvable up front and uses
   * this helper only to keep a failed attempt from leaving a grant or token behind.
   * Refresh rotation writes its grant first and stays retryable through the
   * previous-refresh-token window instead.
   */
  private async prepareAccessToken(params: CreateAccessTokenOptions<Env>): Promise<PreparedAccessToken> {
    const {
      format,
      userId,
      grantId,
      clientId,
      scope: requestedScope,
      encryptedProps,
      encryptionKey,
      expiresIn,
      audience,
      env,
    } = params;
    const scope = [...requestedScope];

    // Central guard for all access-token writes: Cloudflare KV rejects an `expirationTtl`
    // below 60 seconds, so a TTL derived from a callback override or a near-expiry source
    // must not reach the write. Callers that clamp to a source's remaining lifetime should
    // already have rejected this case with a more specific error; this is the backstop.
    if (!isValidAccessTokenTTL(expiresIn)) {
      throw new OAuthError('invalid_request', {
        description: 'Requested token lifetime must be at least 60 seconds',
      });
    }
    if (format !== 'opaque' && format !== 'jwt') {
      throw new TypeError("Access-token format must be either 'opaque' or 'jwt'");
    }

    const now = params.issuedAt ?? Math.floor(Date.now() / 1000);
    const accessTokenExpiresAt = now + expiresIn;

    let accessToken: string;
    let jwtId: string | undefined;
    if (format === 'jwt') {
      const jwtAccessTokens = this.jwtAccessTokens;
      if (!jwtAccessTokens) throw new TypeError('JWT access-token issuance requires jwtAccessTokens');
      // The signed payload is client-readable. The JWT helper receives decrypted
      // props only so its explicit publicClaims mapper can select safe values;
      // the complete props remain encrypted in the state record below.
      const props = await decryptProps(encryptionKey, encryptedProps);
      let issued;
      try {
        issued = await jwtAccessTokens.issue({
          props,
          userId,
          grantId,
          clientId,
          scope,
          audience,
          issuedAt: now,
          expiresAt: accessTokenExpiresAt,
          env,
        });
      } catch (error) {
        // Unrepresentable grant state — a scope token that cannot round-trip through a
        // space-delimited claim, an oversized public claim — is a configuration fault, and
        // the deployer needs it shaped as an OAuth error with an `onError` line, not as a
        // bare TypeError escaping the token endpoint.
        if (error instanceof OAuthError) throw error;
        throw withCause(
          new OAuthError('server_error', {
            description: 'Unable to issue a JWT access token',
            statusCode: 500,
          }),
          error
        );
      }
      accessToken = issued.token;
      jwtId = issued.claims.jti;
    } else {
      const accessTokenSecret = generateRandomString(TOKEN_LENGTH);
      accessToken = `${userId}:${grantId}:${accessTokenSecret}`;
    }

    const accessTokenId = await generateTokenId(accessToken);

    // Wrap the key for the access token
    const accessTokenWrappedKey = await wrapKeyWithToken(accessToken, encryptionKey);

    // Store access token with denormalized grant information
    const accessTokenData: Token = {
      id: accessTokenId,
      grantId: grantId,
      userId: userId,
      createdAt: now,
      expiresAt: accessTokenExpiresAt,
      audience: audience,
      scope: scope,
      ...(jwtId === undefined ? {} : { format: 'jwt' as const, jti: jwtId }),
      wrappedEncryptionKey: accessTokenWrappedKey,
      grant: {
        clientId: clientId,
        scope: params.grantScope ?? scope,
        encryptedProps: encryptedProps,
      },
    };

    return {
      accessToken,
      tokenKey: `token:${userId}:${grantId}:${accessTokenId}`,
      tokenData: accessTokenData,
      expiresIn,
    };
  }

  /** Write a prepared access token's state record to KV. */
  private async persistAccessToken(env: Env & ProviderEnv, prepared: PreparedAccessToken): Promise<void> {
    try {
      await env.OAUTH_KV.put(prepared.tokenKey, JSON.stringify(prepared.tokenData), {
        expirationTtl: prepared.expiresIn,
      });
    } catch (error) {
      this.throwRetryableTokenStorageErrorIfKvRateLimited(error);
      throw error;
    }
  }

  /**
   * Restricts requested scopes to the scopes available for the current flow.
   * If no scope is requested, all available scopes are returned.
   * @param requestedScope - The scope parameter from the request (string or array)
   * @param allowedScopes - The maximum scopes available for the current flow
   * @returns The requested scopes that are included in the allowed scopes
   */
  private downscope(requestedScope: string | string[] | undefined, allowedScopes: string[]): string[] {
    if (!requestedScope) return allowedScopes;

    const requestedScopes: string[] =
      typeof requestedScope === 'string' ? requestedScope.split(' ').filter(Boolean) : requestedScope;

    return requestedScopes.filter((scope: string) => allowedScopes.includes(scope));
  }

  /**
   * Checks if the global_fetch_strictly_public compatibility flag is enabled.
   * This flag is required for CIMD to prevent SSRF attacks.
   * See: https://developers.cloudflare.com/workers/configuration/compatibility-flags/#global-fetch-strictly-public
   */
  private hasGlobalFetchStrictlyPublic(): boolean {
    const compatFlags =
      typeof Cloudflare !== 'undefined' && Cloudflare.compatibilityFlags ? Cloudflare.compatibilityFlags : null;
    return !!compatFlags?.global_fetch_strictly_public;
  }

  /**
   * Checks if a client_id is a CIMD URL (HTTPS with non-root path).
   * Not private because OAuthHelpersImpl needs access for purgeExpiredData.
   */
  isClientMetadataUrl(clientId: string): boolean {
    return isClientIdMetadataDocumentUrl(clientId);
  }

  /**
   * Builds a WWW-Authenticate header value with resource_metadata per RFC 9728 §5.1
   */
  private buildWwwAuthenticateHeader(
    resourceMetadataUrl: string | undefined,
    error?: string,
    errorDescription?: string,
    requiredScopes: string[] = [],
    resourceServer: NormalizedResourceServer<Env> = this.resourceServers[0]
  ): string {
    let header = 'Bearer realm="OAuth"';
    if (resourceMetadataUrl) {
      header += `, resource_metadata="${resourceMetadataUrl}"`;
    }
    if (error) {
      header += `, error="${error}"`;
    }
    const challengeScopes =
      requiredScopes.length > 0
        ? this.normalizeProtectedResourceScopes(requiredScopes)
        : this.getProtectedResourceScopes(resourceServer);
    if (challengeScopes.length > 0) {
      header += `, scope="${challengeScopes.join(' ')}"`;
    }
    if (errorDescription) {
      header += `, error_description="${errorDescription}"`;
    }
    return header;
  }

  /** Build the RFC 9728 well-known URL for the configured canonical resource. */
  private getConfiguredResourceMetadataUrl(resource: string): string {
    const authorityStart = resource.indexOf('://') + 3;
    const suffixOffset = resource.slice(authorityStart).search(/[/?]/);
    const suffixStart = suffixOffset === -1 ? resource.length : authorityStart + suffixOffset;
    let suffix = resource.slice(suffixStart);
    if (suffix === '/') suffix = '';
    if (suffix.startsWith('/?')) suffix = suffix.slice(1);
    return resource.slice(0, suffixStart) + PROTECTED_RESOURCE_WELL_KNOWN_PREFIX + suffix;
  }

  /**
   * RFC 9728 §3.3 requires metadata fetched from a challenge to identify the
   * original protected-resource URL. Descendant and alias routes can still use
   * a base audience, but must not advertise a document for a different URL.
   */
  private getResourceMetadataUrlForRequest(
    requestUrl: URL,
    resourceServer: NormalizedResourceServer<Env>
  ): string | undefined {
    const configuredResource = resourceServer.resourceMetadata.resource;
    if (isExactResource(requestUrl.href, configuredResource)) {
      return this.getConfiguredResourceMetadataUrl(configuredResource);
    }

    // RFC 9728 §5.1 permits the canonical document on any request the resource covers.
    // A canonical path is the base audience for its path-boundary descendants, so a 401
    // at /mcp/messages still points clients at the metadata for /mcp. A resource with a
    // query covers only requests that carry that query.
    const resourceUrl = new URL(configuredResource);
    if (
      requestUrl.origin === resourceUrl.origin &&
      requestCarriesResourceQuery(requestUrl, resourceUrl) &&
      isPathDescendant(requestUrl.pathname, resourceUrl.pathname)
    ) {
      return this.getConfiguredResourceMetadataUrl(configuredResource);
    }

    return undefined;
  }

  /**
   * Helper function to create OAuth error responses.
   *
   * `internal` (optional) carries a tagged, server-side-only reason. It is
   * forwarded to the deployer's `onError` hook but never placed on the wire,
   * so the public response stays RFC-compliant and free of information leak
   * while the deployer can still observe which check failed.
   */
  private createErrorResponse(
    code: string,
    options: OAuthErrorOptions,
    internal?: { category: string; reason: string; detail?: unknown },
    request?: Request
  ): Response {
    const { description } = options;
    const responseStatus = options.statusCode ?? 400;
    // RFC 6749 §5.2 / OAuth 2.1 §3.2.4 show `Cache-Control: no-store` on error
    // responses; mirror that so OAuth state isn't cached by intermediaries.
    // Caller-supplied headers (e.g. Retry-After, WWW-Authenticate) take precedence.
    const responseHeaders = { ...NO_CACHE_HEADERS, ...(options.headers ?? {}) };

    // Notify the user of the error and allow them to override the response
    const customErrorResponse = this.options.onError?.({
      code,
      description,
      status: responseStatus,
      headers: responseHeaders,
      ...(internal ? { internal } : {}),
      ...(request ? { request } : {}),
    });
    if (customErrorResponse) return customErrorResponse;

    const body = JSON.stringify({
      error: code,
      error_description: description,
    });

    return new Response(body, {
      status: responseStatus,
      headers: {
        'Content-Type': 'application/json',
        ...responseHeaders,
      },
    });
  }
}

// Constants
/**
 * Error class for OAuth operations
 * Carries OAuth error code and description for proper error responses
 */
/**
 * Options accepted by the {@link OAuthError} constructor.
 */
export interface OAuthErrorOptions {
  /**
   * Human-readable text returned in the `error_description` field.
   */
  description: string;

  /**
   * HTTP status code for the error response. Defaults to `400`.
   */
  statusCode?: number;

  /**
   * Additional response headers.
   *
   * For transient failures (e.g. upstream rate limits), set
   * `Retry-After` here so well-behaved clients back off instead of
   * retry-storming. Per RFC 7231 §7.1.3 the value may be either a
   * number of seconds or an HTTP-date.
   */
  headers?: Record<string, string>;
}

/**
 * Structured OAuth 2.0 token-endpoint error.
 *
 * Throw from a `tokenExchangeCallback` or any code it calls to surface a
 * standard OAuth token response (`{ error, error_description }`) instead of a
 * generic `500 Internal Server Error`.
 *
 * Anything thrown that is **not** an `OAuthError` continues to surface as
 * a 500 so unexpected failures remain visible — the provider does not
 * catch-everything-and-return-400.
 *
 * @example
 * ```ts
 * import { OAuthError } from '@cloudflare/workers-oauth-provider';
 *
 * tokenExchangeCallback: async (options) => {
 *   if (options.grantType === 'refresh_token') {
 *     // refreshUpstream() may throw OAuthError from any depth
 *     return { newProps: await refreshUpstream(options.props) };
 *   }
 * }
 *
 * async function refreshUpstream(props) {
 *   const res = await fetch(...);
 *   if (res.status === 401) {
 *     throw new OAuthError('invalid_grant', { description: 'upstream refresh token is invalid' });
 *   }
 *   if (res.status === 429) {
 *     // Mirror upstream's Retry-After if present, otherwise pick a default.
 *     throw new OAuthError('temporarily_unavailable', {
 *       description: 'upstream rate limited',
 *       statusCode: 429,
 *       headers: { 'Retry-After': res.headers.get('retry-after') ?? '60' },
 *     });
 *   }
 *   return await res.json();
 * }
 * ```
 */
/**
 * Keep the underlying failure reachable for diagnostics without putting it on the wire.
 * Assigned rather than passed to the constructor because the package targets a language
 * level without the ES2022 `cause` option.
 */
function withCause<E extends Error>(error: E, cause: unknown): E {
  Object.defineProperty(error, 'cause', { value: cause, enumerable: false, configurable: true, writable: true });
  return error;
}

export class OAuthError extends Error {
  /** OAuth 2.0 error code. */
  public readonly code: string;
  /** Options controlling the OAuth error response. */
  public readonly options: OAuthErrorOptions & { statusCode: number };
  /** Human-readable description sent in the `error_description` field. */
  public readonly description: string;
  /** HTTP status code for the error response. */
  public readonly statusCode: number;
  /** Additional response headers. */
  public readonly headers?: Record<string, string>;

  constructor(code: string, options: OAuthErrorOptions) {
    super(options.description);
    this.name = 'OAuthError';
    this.code = code;
    this.options = { ...options, statusCode: options.statusCode ?? 400 };
    this.description = this.options.description;
    this.statusCode = this.options.statusCode;
    this.headers = this.options.headers;
  }
}

/** Options accepted by the {@link ExternalTokenError} constructor. */
export interface ExternalTokenErrorOptions {
  /**
   * Public description returned in the OAuth `error_description` field.
   * Do not include credentials, upstream response bodies, or private diagnostics.
   */
  description: string;

  /** HTTP status returned to the protected-resource client. */
  statusCode: number;

  /** Additional public response headers, such as `Retry-After`. */
  headers?: Record<string, string>;

  /**
   * Minimum scopes needed for the protected-resource operation.
   *
   * For `403 insufficient_scope`, these values are validated, deduplicated,
   * and added to the synthesized `WWW-Authenticate` challenge. Each value must
   * use the OAuth scope-token grammar from RFC 6749 §3.3.
   */
  requiredScopes?: string[];
}

/**
 * Intentional public error from an external bearer-token validator.
 *
 * Throw only from `resolveExternalToken` when an expected validation outcome
 * should become a structured protected-resource response. Ordinary errors and
 * {@link OAuthError} retain their pre-existing behavior and propagate as
 * unexpected failures.
 */
export class ExternalTokenError extends Error {
  /** OAuth error code returned in the response body and, when applicable, challenge. */
  public readonly code: OAuthTokenErrorCode;
  /** Public description returned as `error_description`. */
  public readonly description: string;
  /** HTTP status returned to the protected-resource client. */
  public readonly statusCode: number;
  /** Additional public response headers. */
  public readonly headers?: Record<string, string>;
  /** Minimum scopes for an `insufficient_scope` challenge. */
  public readonly requiredScopes?: string[];

  /**
   * Creates an intentional external-token validation error.
   * @param code - Standard OAuth error code to return
   * @param options - Public response details
   */
  constructor(code: OAuthTokenErrorCode, options: ExternalTokenErrorOptions) {
    super(options.description);
    this.name = 'ExternalTokenError';
    this.code = code;
    this.description = options.description;
    this.statusCode = options.statusCode;
    this.headers = options.headers;
    this.requiredScopes = options.requiredScopes;
  }
}

/**
 * Thrown when fetching a Client ID Metadata Document (CIMD) fails — the
 * server-to-server fetch errored, timed out, or returned an invalid document.
 * Distinct from a client that simply does not exist, which is reported as a
 * null client lookup result.
 *
 * At the token endpoint the provider handles this itself: the wire response
 * stays a generic `invalid_client` / "Client not found", and the failure is
 * reported through the `onError` hook's `internal` field (category
 * `client-id-metadata-document`) together with the originating `request`.
 *
 * `OAuthHelpers` methods that look up clients (`lookupClient`, and methods
 * built on it such as `exchangeToken`) let this error propagate to the
 * caller. Callers that previously relied on a `null` result for these
 * failures should catch it to preserve their error contract.
 */
export class CimdFetchError extends Error {
  /** Stable reason slug suitable for telemetry and control flow. */
  public readonly reason = 'metadata_resolution_failed' as const;
  /** The CIMD URL whose fetch or validation failed. */
  public readonly metadataUrl: string;
  /** The underlying failure message (e.g. "Failed to fetch client metadata: HTTP 403"). */
  public readonly detail: string;

  /**
   * Creates an error for a failed CIMD fetch or validation.
   * @param metadataUrl - The CIMD URL that could not be resolved
   * @param cause - The underlying fetch or validation failure
   */
  constructor(metadataUrl: string, cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    super(`CIMD fetch failed for ${metadataUrl}: ${detail}`);
    this.name = 'CimdFetchError';
    this.metadataUrl = metadataUrl;
    this.detail = detail;
  }
}

/**
 * Default expiration time for access tokens (1 hour in seconds)
 */
const DEFAULT_ACCESS_TOKEN_TTL = 60 * 60;

/**
 * Default expiration time for refresh tokens (30 days in seconds)
 */
const DEFAULT_REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60;

/**
 * Default expiration time for dynamically registered clients (90 days in seconds)
 */
const DEFAULT_CLIENT_REGISTRATION_TTL = 90 * 24 * 60 * 60;

/**
 * Minimum number of seconds an absolute KV expiration must be in the future.
 * Cloudflare KV rejects `put` calls whose `expiration` is less than 60 seconds
 * away with "400 Invalid expiration ... Expiration times must be at least 60
 * seconds in the future." We use this to treat near-expiry grants as expired and
 * to clamp absolute expirations when writing grants back to KV.
 */
const KV_MIN_EXPIRATION_TTL_SECONDS = 60;

function isValidAccessTokenTTL(value: number): boolean {
  return Number.isInteger(value) && value >= KV_MIN_EXPIRATION_TTL_SECONDS;
}

/**
 * Safety margin (seconds) added on top of `KV_MIN_EXPIRATION_TTL_SECONDS` when clamping an
 * absolute KV expiration. Absolute expirations are validated against KV's clock at the
 * moment the write is processed, so writing exactly `now + 60` can be rejected once
 * worker→KV latency or minor clock skew is accounted for. The margin keeps clamped writes
 * comfortably above KV's hard minimum without meaningfully extending a grant's lifetime.
 */
const KV_EXPIRATION_CLAMP_MARGIN_SECONDS = 5;

/**
 * Default batch size for purgeExpiredData. Conservative to stay within
 * Cloudflare's 1000 subrequest limit per invocation.
 */
const DEFAULT_PURGE_BATCH_SIZE = 50;

/**
 * Maximum supported Cloudflare KV list page size.
 */
const MAX_KV_LIST_LIMIT = 1000;

/**
 * Default batch size for paginating existing grants when revoking them
 * during completeAuthorization. Conservative for each KV list page.
 */
const DEFAULT_REVOKE_EXISTING_GRANTS_BATCH_SIZE = 50;

function getRevokeExistingGrantsBatchSize(batchSize: number | undefined): number {
  if (batchSize === undefined) {
    return DEFAULT_REVOKE_EXISTING_GRANTS_BATCH_SIZE;
  }

  if (!Number.isFinite(batchSize) || !Number.isInteger(batchSize) || batchSize < 1) {
    throw new Error('revokeExistingGrantsBatchSize must be a positive integer.');
  }

  return Math.min(batchSize, MAX_KV_LIST_LIMIT);
}

/**
 * Length of generated token strings
 */
const TOKEN_LENGTH = 32;

// Helper Functions
/**
 * Checks if a resource server matches an audience claim.
 * Uses origin comparison (case-insensitive hostname via URL normalization)
 * and path-prefix matching on path boundaries for RFC 8707 resource indicators.
 * @param resourceServerUrl - The resource server URL (from request)
 * @param audienceValue - The audience value from token
 * @returns true if they match, false otherwise
 */
function audienceMatches(resourceServerUrl: string, audienceValue: string): boolean {
  try {
    const resource = new URL(resourceServerUrl);
    const audience = new URL(audienceValue);

    // Origins must always match (case-insensitive via URL normalization)
    if (resource.origin !== audience.origin) {
      return false;
    }

    // A query-bearing resource identifier names a more specific resource. A request
    // may add parameters of its own but must preserve the audience's.
    if (!requestCarriesResourceQuery(resource, audience)) {
      return false;
    }

    // Origin-only audience matches any path (backward compatibility)
    if (audience.pathname === '/' || audience.pathname === '') {
      return true;
    }

    // Path-aware audience: prefix match on path boundary (RFC 8707)
    // e.g. audience "/api" matches request "/api", "/api/", "/api/users"
    // but does NOT match "/api-v2" or "/apiary"
    const descendantPrefix = audience.pathname.endsWith('/') ? audience.pathname : audience.pathname + '/';
    return resource.pathname === audience.pathname || resource.pathname.startsWith(descendantPrefix);
  } catch {
    return false;
  }
}

/** Whether either URL path is the other path or one of its descendants. */
function pathsOverlapOnBoundary(leftPath: string, rightPath: string): boolean {
  const normalize = (path: string) => (path === '/' ? '/' : path.replace(/\/$/, ''));
  const left = normalize(leftPath);
  const right = normalize(rightPath);
  if (left === right || left === '/' || right === '/') return true;
  return left.startsWith(right + '/') || right.startsWith(left + '/');
}

function appendHeaderValue(headers: Headers, name: string, value: string): void {
  const values = (headers.get(name) ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (!values.some((item) => item.toLowerCase() === value.toLowerCase())) values.push(value);
  headers.set(name, values.join(', '));
}

/** Whether a request or audience names one canonical configured resource. */
function isExactResource(value: string | string[] | undefined, configuredResource: string): boolean {
  // A stored 0.x record may carry an array audience; it is bound to a configured resource
  // when that resource appears in it. New tokens always carry exactly one audience.
  if (Array.isArray(value)) {
    return value.some((entry) => typeof entry === 'string' && resourceMatches(entry, configuredResource));
  }
  return typeof value === 'string' && resourceMatches(value, configuredResource);
}

/** RFC 9110 §9.3.2: a HEAD response carries the GET headers and no body. */
function withoutBodyForHead(request: Request, response: Response): Response {
  if (request.method !== 'HEAD') return response;
  return new Response(null, { status: response.status, headers: response.headers });
}

/** Whether `candidate` is `base` or a path-boundary descendant of it (trailing slashes ignored). */
function isPathDescendant(candidate: string, base: string): boolean {
  if (base === '' || base === '/') return true;
  // A trailing slash is significant in a resource identifier, as it is for the audience
  // check: "/mcp/" covers "/mcp/" and "/mcp/x" but not "/mcp".
  if (base.endsWith('/')) return candidate.startsWith(base);
  return candidate === base || candidate.startsWith(`${base}/`);
}

/**
 * Hashes a secret value using SHA-256
 * @param secret - The secret value to hash
 * @returns A hex string representation of the hash
 */
async function hashSecret(secret: string): Promise<string> {
  // Use the same approach as generateTokenId for consistency
  return generateTokenId(secret);
}

type BasicAuthorizationResult =
  | { kind: 'not-basic' }
  | { kind: 'malformed' }
  | { kind: 'credentials'; clientId: string; clientSecret: string };

/**
 * Parses RFC 6749 HTTP Basic client credentials.
 */
function parseBasicAuthorizationHeader(header: string | null): BasicAuthorizationResult {
  if (!header) return { kind: 'not-basic' };

  const schemeEnd = header.search(/[ \t]/);
  const scheme = schemeEnd === -1 ? header : header.slice(0, schemeEnd);
  if (scheme.toLowerCase() !== 'basic') return { kind: 'not-basic' };

  if (schemeEnd === -1) return { kind: 'malformed' };
  const encodedCredentials = header.slice(schemeEnd).trim();
  if (!encodedCredentials || /[ \t]/.test(encodedCredentials)) return { kind: 'malformed' };

  try {
    const credentials = atob(encodedCredentials);
    const separatorIndex = credentials.indexOf(':');
    if (separatorIndex === -1) return { kind: 'malformed' };

    return {
      kind: 'credentials',
      clientId: decodeFormUrlEncodedComponent(credentials.slice(0, separatorIndex)),
      clientSecret: decodeFormUrlEncodedComponent(credentials.slice(separatorIndex + 1)),
    };
  } catch {
    return { kind: 'malformed' };
  }
}

/**
 * Decodes an application/x-www-form-urlencoded component.
 * @param value - The encoded component value
 * @returns The decoded component value
 */
function decodeFormUrlEncodedComponent(value: string): string {
  return decodeURIComponent(value.replace(/\+/g, ' '));
}

/**
 * Generates a cryptographically secure random string
 * @param length - The length of the string to generate
 * @returns A random string of the specified length
 */
function generateRandomString(length: number): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let result = '';
  const values = new Uint8Array(length);
  crypto.getRandomValues(values);
  for (let i = 0; i < length; i++) {
    result += characters.charAt(values[i] % characters.length);
  }
  return result;
}

/**
 * Generates a token ID by hashing the token value using SHA-256
 * @param token - The token to hash
 * @returns A hex string representation of the hash
 */
async function generateTokenId(token: string): Promise<string> {
  // Convert the token string to a Uint8Array
  const encoder = new TextEncoder();
  const data = encoder.encode(token);

  // Use the WebCrypto API to create a SHA-256 hash
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  // Convert the hash to a hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

  return hashHex;
}

/**
 * Checks if a URI is a loopback redirect URI (127.0.0.0/8, ::1, or localhost).
 * Per RFC 8252 Section 7.3, loopback IPs get special port handling. This library
 * applies the same port flexibility to localhost for native apps (e.g., Claude Code).
 */
function isLoopbackUri(uri: string): boolean {
  try {
    return isLoopbackHostname(new URL(uri).hostname);
  } catch {
    return false;
  }
}

/**
 * Validates a redirect URI against registered URIs with RFC 8252 loopback support.
 * For loopback URIs (127.x.x.x, ::1, localhost), any port is allowed as long as scheme, host, path, and query match.
 * For non-loopback URIs, exact match is required.
 */
function isValidRedirectUri(requestUri: string, registeredUris: string[]): boolean {
  return registeredUris.some((registered) => {
    // For loopback URIs, allow any port (RFC 8252 Section 7.3)
    if (isLoopbackUri(requestUri) && isLoopbackUri(registered)) {
      try {
        const reqUrl = new URL(requestUri);
        const regUrl = new URL(registered);
        // Must match scheme, hostname, pathname, and query (ignore port only)
        return (
          reqUrl.protocol === regUrl.protocol &&
          reqUrl.hostname === regUrl.hostname &&
          reqUrl.pathname === regUrl.pathname &&
          reqUrl.search === regUrl.search
        );
      } catch {
        return false;
      }
    }
    // Non-loopback: exact match required
    return requestUri === registered;
  });
}

/**
 * Encodes a string as base64url (URL-safe base64)
 * @param str - The string to encode
 * @returns The base64url encoded string
 */
function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decodes a base64url-encoded string to bytes.
 */
export function base64UrlToBytes(base64Url: string): Uint8Array {
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binaryString = atob(padded);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Parses a base64url-encoded JWT JSON part into an object.
 */
export function parseJwtJsonPart(encoded: string): Record<string, unknown> {
  try {
    const json = new TextDecoder().decode(base64UrlToBytes(encoded));
    const parsed = JSON.parse(json);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('JWT part must be an object');
    }
    return parsed as Record<string, unknown>;
  } catch {
    throw new Error('Malformed JWT part');
  }
}

/**
 * Gets WebCrypto import and verify parameters for supported JOSE algorithms.
 */
export function getJwtCryptoAlgorithms(alg: string): {
  importAlgorithm: Parameters<SubtleCrypto['importKey']>[2];
  verifyAlgorithm: Parameters<SubtleCrypto['verify']>[0];
} {
  if (alg === 'RS256') {
    const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    return { importAlgorithm: algorithm, verifyAlgorithm: algorithm };
  }

  if (alg === 'ES256') {
    return {
      importAlgorithm: { name: 'ECDSA', namedCurve: 'P-256' },
      verifyAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    };
  }

  throw new Error(`Unsupported JWT alg: ${alg}`);
}

/**
 * Encodes an ArrayBuffer as base64 string
 * @param buffer - The ArrayBuffer to encode
 * @returns The base64 encoded string
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

/**
 * Decodes a base64 string to an ArrayBuffer
 * @param base64 - The base64 string to decode
 * @returns The decoded ArrayBuffer
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Encrypts props data with a newly generated key
 * @param data - The data to encrypt
 * @returns An object containing the encrypted data and the generated key
 */
async function encryptProps(data: any): Promise<{ encryptedData: string; key: CryptoKey }> {
  // Generate a new encryption key for this specific props data
  // @ts-ignore
  const key: CryptoKey = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );

  // Use a constant IV (all zeros) since each key is used only once
  const iv = new Uint8Array(12);

  // Convert data to string
  const jsonData = JSON.stringify(data);
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(jsonData);

  // Encrypt the data
  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encodedData
  );

  // Convert to base64 for storage
  return {
    encryptedData: arrayBufferToBase64(encryptedBuffer),
    key,
  };
}

/**
 * Decrypts encrypted props data using the provided key
 * @param key - The CryptoKey to use for decryption
 * @param encryptedData - The encrypted data as a base64 string
 * @returns The decrypted data object
 */
async function decryptProps(key: CryptoKey, encryptedData: string): Promise<any> {
  // Convert base64 string back to ArrayBuffer
  const encryptedBuffer = base64ToArrayBuffer(encryptedData);

  // Use the same constant IV (all zeros) that was used for encryption
  const iv = new Uint8Array(12);

  // Decrypt the data
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encryptedBuffer
  );

  // Convert the decrypted buffer to a string, then parse as JSON
  const decoder = new TextDecoder();
  const jsonData = decoder.decode(decryptedBuffer);
  return JSON.parse(jsonData);
}

// Static HMAC key for wrapping key derivation
// This ensures that even if someone has the token ID, they can't derive the wrapping key
// We use a fixed array of 32 bytes for optimal performance
const WRAPPING_KEY_HMAC_KEY = new Uint8Array([
  0x22, 0x7e, 0x26, 0x86, 0x8d, 0xf1, 0xe1, 0x6d, 0x80, 0x70, 0xea, 0x17, 0x97, 0x5b, 0x47, 0xa6, 0x82, 0x18, 0xfa,
  0x87, 0x28, 0xae, 0xde, 0x85, 0xb5, 0x1d, 0x4a, 0xd9, 0x96, 0xca, 0xca, 0x43,
]);

/**
 * Derives a wrapping key from a token string
 * This intentionally uses a different method than token ID generation
 * to ensure the token ID cannot be used to derive the wrapping key
 * @param tokenStr - The token string to use as key material
 * @returns A Promise resolving to the derived CryptoKey
 */
async function deriveKeyFromToken(tokenStr: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();

  // Import the pre-defined HMAC key (already 32 bytes)
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    WRAPPING_KEY_HMAC_KEY,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // Use HMAC-SHA256 to derive the wrapping key material
  const hmacResult = await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(tokenStr));

  // Import the HMAC result as the wrapping key
  return await crypto.subtle.importKey(
    'raw',
    hmacResult,
    { name: 'AES-KW' },
    false, // not extractable
    ['wrapKey', 'unwrapKey']
  );
}

/**
 * Wraps an encryption key using a token-derived key
 * @param tokenStr - The token string to use for key wrapping
 * @param keyToWrap - The encryption key to wrap
 * @returns A Promise resolving to the wrapped key as a base64 string
 */
async function wrapKeyWithToken(tokenStr: string, keyToWrap: CryptoKey): Promise<string> {
  // Derive a key from the token
  const wrappingKey = await deriveKeyFromToken(tokenStr);

  // Wrap the encryption key
  const wrappedKeyBuffer = await crypto.subtle.wrapKey('raw', keyToWrap, wrappingKey, { name: 'AES-KW' });

  // Convert to base64 for storage
  return arrayBufferToBase64(wrappedKeyBuffer);
}

/**
 * Unwraps an encryption key using a token-derived key
 * @param tokenStr - The token string used for key wrapping
 * @param wrappedKeyBase64 - The wrapped key as a base64 string
 * @returns A Promise resolving to the unwrapped CryptoKey
 */
async function unwrapKeyWithToken(tokenStr: string, wrappedKeyBase64: string): Promise<CryptoKey> {
  // Derive a key from the token
  const wrappingKey = await deriveKeyFromToken(tokenStr);

  // Convert base64 wrapped key to ArrayBuffer
  const wrappedKeyBuffer = base64ToArrayBuffer(wrappedKeyBase64);

  // Unwrap the key
  return await crypto.subtle.unwrapKey(
    'raw',
    wrappedKeyBuffer,
    wrappingKey,
    { name: 'AES-KW' },
    { name: 'AES-GCM' },
    true, // extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Class that implements the OAuth helper methods
 * Provides methods for OAuth operations needed by handlers
 */
class OAuthHelpersImpl<Env = Cloudflare.Env, Props = any> implements OAuthHelpers<Props> {
  private env: Env & ProviderEnv;
  private provider: OAuthProviderImpl<Env>;

  /**
   * Creates a new OAuthHelpers instance
   * @param env - Cloudflare Worker environment variables
   * @param provider - Reference to the parent provider instance
   */
  constructor(env: Env & ProviderEnv, provider: OAuthProviderImpl<Env>) {
    this.env = env;
    this.provider = provider;
  }

  /**
   * Parses an OAuth authorization request from the HTTP request
   * @param request - The HTTP request containing OAuth parameters
   * @returns The parsed authorization request parameters
   * @throws AuthorizationError for expected authorization-request validation failures
   * @throws CimdFetchError when the client ID is a CIMD URL whose document cannot be resolved
   */
  async parseAuthRequest(request: Request): Promise<AuthRequest> {
    const url = new URL(request.url);
    // The combined OAuthProvider never checked which URL the application parsed from; the
    // role-based server host-gates its authorize endpoint against the explicit issuer.
    if (this.provider.hasExplicitIssuer && !this.provider.isAuthorizationEndpointRequest(url)) {
      throw new AuthorizationError('invalid_request', {
        description: 'Authorization request was sent to an unconfigured endpoint',
      });
    }
    const responseType = url.searchParams.get('response_type') || '';
    const clientId = url.searchParams.get('client_id') || '';
    const redirectUri = url.searchParams.get('redirect_uri') || '';
    const scope = (url.searchParams.get('scope') || '').split(' ').filter(Boolean);
    const state = url.searchParams.get('state') || '';
    const codeChallenge = url.searchParams.get('code_challenge') || undefined;
    const codeChallengeMethod = url.searchParams.get('code_challenge_method') || undefined;
    const issuer = this.provider.getAuthorizationServerIssuer(url);
    // RFC 8707 Section 2.1: Multiple resource parameters MAY be used
    const resourceParams = url.searchParams.getAll('resource');
    const resourceParam =
      resourceParams.length > 0 ? (resourceParams.length === 1 ? resourceParams[0] : resourceParams) : undefined;

    if (!clientId) {
      throw new AuthorizationError('invalid_request', { description: 'client_id is required' });
    }

    const clientInfo = await this.lookupClient(clientId);
    if (!clientInfo) {
      throw new AuthorizationError('invalid_request', { description: 'Invalid client_id' });
    }

    try {
      validateRedirectUriScheme(redirectUri);
    } catch {
      throw new AuthorizationError('invalid_request', { description: 'Invalid redirect URI' });
    }
    if (!redirectUri || !isValidRedirectUri(redirectUri, clientInfo.redirectUris)) {
      throw new AuthorizationError('invalid_request', { description: 'Invalid redirect URI' });
    }

    const withRedirect = (error: AuthorizationError): never => {
      throw withAuthorizationRedirect(error, redirectUri, state || undefined, issuer);
    };

    // Resource, response type, and PKCE errors are redirectable only after the
    // exact client redirect URI above has been validated.
    let resource: string;
    try {
      resource = this.provider.resolveAuthorizationRequestResource(resourceParam);
    } catch (error) {
      if (error instanceof AuthorizationError) withRedirect(error);
      throw error;
    }

    try {
      validateAuthorizationResponseType(this.provider.serverCapabilities, responseType, clientInfo.responseTypes);
      validateAuthorizationPkce(
        this.provider.serverCapabilities,
        { responseType, codeChallenge, codeChallengeMethod },
        clientInfo
      );
    } catch (error) {
      if (error instanceof AuthorizationError) withRedirect(error);
      throw error;
    }

    return {
      responseType,
      clientId,
      redirectUri,
      scope,
      state,
      codeChallenge,
      codeChallengeMethod,
      resource,
      issuer,
    };
  }

  /**
   * Looks up a client by its client ID
   * @param clientId - The client ID to look up
   * @returns A Promise resolving to the client info, or null if the client does not
   * exist. Null means definitive absence; failures to determine the answer throw
   * instead (KV errors propagate, and a CIMD metadata fetch failure throws
   * `CimdFetchError`), so an upstream outage cannot masquerade as an unregistered
   * client.
   * @throws CimdFetchError when the client ID is a CIMD URL and fetching or
   * validating the metadata document fails.
   */
  async lookupClient(clientId: string): Promise<ClientInfo | null> {
    const client = await this.provider.getClient(this.env, clientId);
    return client ? toPublicClientInfo(client) : null;
  }

  /**
   * Completes an authorization request by creating a grant and either:
   * - For authorization code flow: generating an authorization code
   * - For implicit flow: generating an access token directly
   * @param options - Options specifying the grant details
   * @returns A Promise resolving to an object containing the redirect URL
   * @throws Error when the request's response type is not permitted
   * @throws CimdFetchError when the client ID is a CIMD URL whose document cannot be resolved
   */
  async completeAuthorization(options: CompleteAuthorizationOptions<Props>): Promise<{ redirectTo: string }> {
    const { clientId, redirectUri } = options.request;

    if (!clientId || !redirectUri) {
      throw new Error('Client ID and Redirect URI are required in the authorization request.');
    }

    // Re-validate the redirectUri to prevent open redirect vulnerabilities
    const clientInfo = await this.lookupClient(clientId);
    if (!clientInfo || !isValidRedirectUri(redirectUri, clientInfo.redirectUris)) {
      throw new Error(
        'Invalid redirect URI. The redirect URI provided does not match any registered URI for this client.'
      );
    }
    validateAuthorizationResponseType(
      this.provider.serverCapabilities,
      options.request.responseType,
      clientInfo.responseTypes
    );

    // Callers can pass a reconstructed AuthRequest rather than one returned by
    // parseAuthRequest(), so re-apply registry selection before any mutation.
    const effectiveResource = this.provider.resolveAuthorizationRequestResource(options.request.resource);

    // Re-apply PKCE policy after client, redirect, response-type, and resource
    // validation, preserving their established error precedence while still
    // rejecting before any grant lookup, revocation, or storage.
    validateAuthorizationPkce(this.provider.serverCapabilities, options.request, clientInfo);

    // If requested, collect existing grants for this user+client to revoke AFTER the new grant is created.
    // This avoids a data-loss window where the user has no grants if creation fails.
    let grantsToRevoke: string[] = [];
    if (options.revokeExistingGrants !== false) {
      // A CIMD client_id is the metadata document URL, shared across all installations of
      // the client, so revoking by clientId alone would log the user out everywhere. The
      // redirect URI identifies the installation, so scope revocation to it. Legacy grants
      // without a stored redirectUri never match and are left alone — the bug being fixed
      // is over-revocation, so not revoking is the safe direction.
      const isCimdClient = this.provider.isClientMetadataUrl(clientId);
      const batchSize = getRevokeExistingGrantsBatchSize(options.revokeExistingGrantsBatchSize);
      let cursor: string | undefined;
      do {
        const page = await this.listUserGrants(options.userId, { cursor, limit: batchSize });
        for (const grant of page.items) {
          if (
            grant.clientId === clientId &&
            (!isCimdClient || grant.redirectUri === options.request.redirectUri) &&
            this.provider.shouldReplaceGrantForResource(grant.resource, effectiveResource)
          ) {
            grantsToRevoke.push(grant.id);
          }
        }
        cursor = page.cursor;
      } while (cursor);
    }

    // Generate a unique grant ID
    const grantId = generateRandomString(16);

    // Encrypt the props data with a new key generated for this grant
    const { encryptedData, key: encryptionKey } = await encryptProps(options.props);

    // Get current timestamp
    const now = Math.floor(Date.now() / 1000);

    // Check if this is an implicit flow request (response_type=token)
    if (options.request.responseType === 'token') {
      // Determine token expiration
      const accessTokenTTL = this.provider.options.accessTokenTTL || DEFAULT_ACCESS_TOKEN_TTL;

      // Resource selection was validated before any grant or token mutation.
      const audience = effectiveResource;

      // Select the writer before storing the implicit grant, and build the token before
      // it too, so neither a policy failure nor a signing or key-resolution failure
      // leaves a grant behind. Matches the authorization-code and assertion paths.
      const accessTokenFormat = await this.provider.selectAccessTokenFormat({
        env: this.env,
        resource: audience,
      });

      // Store the grant without an auth code (will be referenced by the access token)
      const grant: Grant = {
        id: grantId,
        clientId: options.request.clientId,
        userId: options.userId,
        scope: options.scope,
        metadata: options.metadata,
        encryptedProps: encryptedData,
        createdAt: now,
        resource: effectiveResource,
        redirectUri: options.request.redirectUri,
      };

      // Store the grant with a key that includes the user ID
      const grantKey = `grant:${options.userId}:${grantId}`;
      const accessToken = await this.provider.createImplicitAccessToken(
        {
          format: accessTokenFormat,
          userId: options.userId,
          grantId,
          clientId: options.request.clientId,
          scope: options.scope,
          encryptedProps: encryptedData,
          encryptionKey,
          expiresIn: accessTokenTTL,
          audience,
          // The grant's own `createdAt`, so the pair written here agree on one clock.
          issuedAt: now,
          env: this.env,
        },
        grantKey,
        grant
      );

      // Build the redirect URL for implicit flow (token in fragment, not query params)
      const redirectUrl = new URL(options.request.redirectUri);
      const fragment = new URLSearchParams();
      fragment.set('access_token', accessToken);
      fragment.set('token_type', 'bearer');
      fragment.set('expires_in', accessTokenTTL.toString());
      fragment.set('scope', options.scope.join(' '));
      fragment.set('resource', effectiveResource);

      if (options.request.state) {
        fragment.set('state', options.request.state);
      }
      if (options.request.issuer) {
        fragment.set('iss', options.request.issuer);
      }

      // Set the fragment (hash) part of the URL
      redirectUrl.hash = fragment.toString();

      // Revoke old grants AFTER the new grant is successfully stored
      try {
        await Promise.allSettled(grantsToRevoke.map((oldGrantId) => this.revokeGrant(oldGrantId, options.userId)));
      } catch {
        // Best-effort revocation — new grant is already stored, don't fail the authorization
      }

      return { redirectTo: redirectUrl.toString() };
    } else {
      // Standard authorization code flow
      // Generate an authorization code with embedded user and grant IDs
      const authCodeSecret = generateRandomString(32);
      const authCode = `${options.userId}:${grantId}:${authCodeSecret}`;

      // Hash the authorization code
      const authCodeId = await hashSecret(authCode);

      // Wrap the encryption key with the auth code
      const authCodeWrappedKey = await wrapKeyWithToken(authCode, encryptionKey);

      // Store the grant with the auth code hash
      const grant: Grant = {
        id: grantId,
        clientId: options.request.clientId,
        userId: options.userId,
        scope: options.scope,
        metadata: options.metadata,
        encryptedProps: encryptedData,
        createdAt: now,
        authCodeId: authCodeId, // Store the auth code hash in the grant
        authCodeWrappedKey: authCodeWrappedKey, // Store the wrapped key
        // Store PKCE parameters if provided
        codeChallenge: options.request.codeChallenge,
        codeChallengeMethod: options.request.codeChallengeMethod,
        resource: effectiveResource,
        redirectUri: options.request.redirectUri,
      };

      // Store the grant with a key that includes the user ID
      const grantKey = `grant:${options.userId}:${grantId}`;

      // Set 10-minute TTL for the grant (will be extended when code is exchanged)
      const codeExpiresIn = 600; // 10 minutes
      await this.env.OAUTH_KV.put(grantKey, JSON.stringify(grant), { expirationTtl: codeExpiresIn });

      // Build the redirect URL for authorization code flow
      const redirectUrl = new URL(options.request.redirectUri);
      redirectUrl.searchParams.set('code', authCode);
      if (options.request.state) {
        redirectUrl.searchParams.set('state', options.request.state);
      }
      if (options.request.issuer) {
        redirectUrl.searchParams.set('iss', options.request.issuer);
      }

      // Revoke old grants AFTER the new grant is successfully stored
      try {
        await Promise.allSettled(grantsToRevoke.map((oldGrantId) => this.revokeGrant(oldGrantId, options.userId)));
      } catch {
        // Best-effort revocation — new grant is already stored, don't fail the authorization
      }

      return { redirectTo: redirectUrl.toString() };
    }
  }

  /**
   * Creates a new OAuth client
   * @param clientInfo - Partial client information to create the client with
   * @returns A Promise resolving to the created client info
   */
  async createClient(clientInfo: Partial<ClientInfo>): Promise<ClientInfo> {
    const clientId = generateRandomString(16);

    // Determine token endpoint auth method
    const authMethodWasExplicit = clientInfo.tokenEndpointAuthMethod !== undefined;
    const tokenEndpointAuthMethod = clientInfo.tokenEndpointAuthMethod || 'client_secret_basic';
    const isPublicClient = tokenEndpointAuthMethod === 'none';

    // Create a new client object
    const newClient: StoredClientInfo = {
      clientId,
      redirectUris: clientInfo.redirectUris || [],
      clientName: clientInfo.clientName,
      logoUri: clientInfo.logoUri,
      clientUri: clientInfo.clientUri,
      policyUri: clientInfo.policyUri,
      tosUri: clientInfo.tosUri,
      jwksUri: clientInfo.jwksUri,
      i18n: clientInfo.i18n,
      contacts: clientInfo.contacts,
      grantTypes: clientInfo.grantTypes || [
        GrantType.AUTHORIZATION_CODE,
        GrantType.REFRESH_TOKEN,
        ...(this.provider.options.allowTokenExchangeGrant ? [GrantType.TOKEN_EXCHANGE] : []),
      ],
      responseTypes: clientInfo.responseTypes || ['code'],
      registrationDate: Math.floor(Date.now() / 1000),
      tokenEndpointAuthMethod,
      ...(authMethodWasExplicit ? { authMethodExplicit: true as const } : {}),
    };

    // Validate each redirect URI scheme
    for (const uri of newClient.redirectUris) {
      validateRedirectUriScheme(uri);
    }

    // Only generate and store client secret for confidential clients
    let clientSecret: string | undefined;
    if (!isPublicClient) {
      clientSecret = generateRandomString(32);
      // Hash the client secret
      newClient.clientSecret = await hashSecret(clientSecret);
    }

    await this.env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(newClient));

    // Create the response object
    const clientResponse = toPublicClientInfo(newClient);

    // Return confidential clients with their unhashed secret
    if (!isPublicClient && clientSecret) {
      clientResponse.clientSecret = clientSecret; // Return original unhashed secret
    }

    return clientResponse;
  }

  /**
   * Lists all registered OAuth clients with pagination support
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with items and optional cursor
   */
  async listClients(options?: ListOptions): Promise<ListResult<ClientInfo>> {
    // Prepare list options for KV
    const listOptions: { limit?: number; cursor?: string; prefix: string } = {
      prefix: 'client:',
    };

    if (options?.limit !== undefined) {
      listOptions.limit = options.limit;
    }

    if (options?.cursor !== undefined) {
      listOptions.cursor = options.cursor;
    }

    // Use the KV list() function to get client keys with pagination
    const response = await this.env.OAUTH_KV.list(listOptions);

    // Fetch all clients in parallel
    const clients: ClientInfo[] = [];
    const promises = response.keys.map(async (key: { name: string }) => {
      const clientId = key.name.substring('client:'.length);
      const client = await this.provider.getClient(this.env, clientId);
      if (client) {
        clients.push(toPublicClientInfo(client));
      }
    });

    await Promise.all(promises);

    // Return result with cursor if there are more results
    return {
      items: clients,
      cursor: response.list_complete ? undefined : response.cursor,
    };
  }

  /**
   * Updates an existing OAuth client
   * @param clientId - The ID of the client to update
   * @param updates - Partial client information with fields to update
   * @returns A Promise resolving to the updated client info, or null if not found
   */
  async updateClient(clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null> {
    const client = await this.provider.getClient(this.env, clientId);
    if (!client) {
      return null;
    }

    // Determine token endpoint auth method
    const authMethodWasExplicit = updates.tokenEndpointAuthMethod !== undefined;
    const authMethod = updates.tokenEndpointAuthMethod || client.tokenEndpointAuthMethod || 'client_secret_basic';
    const isPublicClient = authMethod === 'none';

    // Handle changes in auth method
    let secretToStore = client.clientSecret;
    let originalSecret: string | undefined = undefined;

    if (isPublicClient) {
      // Public clients don't have secrets
      secretToStore = undefined;
    } else if (updates.clientSecret) {
      // For confidential clients, handle secret updates if provided
      originalSecret = updates.clientSecret;
      secretToStore = await hashSecret(updates.clientSecret);
    }

    const updatedClient: StoredClientInfo = {
      ...client,
      ...updates,
      clientId: client.clientId, // Ensure clientId doesn't change
      tokenEndpointAuthMethod: authMethod, // Use determined auth method
      // This is internal provenance: callers cannot inject or remove it through
      // the public Partial<ClientInfo> update object.
      authMethodExplicit: authMethodWasExplicit ? true : client.authMethodExplicit,
    };

    // Only include client secret for confidential clients
    if (!isPublicClient && secretToStore) {
      updatedClient.clientSecret = secretToStore;
    } else {
      delete updatedClient.clientSecret;
    }

    // Preserve TTL for DCR clients: re-apply clientRegistrationTTL if configured
    const clientKvOptions: { expirationTtl?: number } = {};
    if (this.provider.options.clientRegistrationTTL !== undefined) {
      clientKvOptions.expirationTtl = this.provider.options.clientRegistrationTTL;
    }
    await this.env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(updatedClient), clientKvOptions);

    // Create a response object
    const response = toPublicClientInfo(updatedClient);

    // For confidential clients, return unhashed secret if a new one was provided
    if (!isPublicClient && originalSecret) {
      response.clientSecret = originalSecret;
    }

    return response;
  }

  /**
   * Deletes an OAuth client and revokes all associated grants and access tokens
   * across all users. Token exchange can issue a token to this client under a
   * different client's source grant, so both record types must be scanned.
   * @param clientId - The ID of the client to delete
   * @returns A Promise resolving when the deletion is confirmed.
   */
  async deleteClient(clientId: string): Promise<void> {
    // Remove the client record first so an interrupted sweep cannot leave a usable client
    // whose grants and tokens were only partly revoked.
    await this.env.OAUTH_KV.delete(`client:${clientId}`);

    // Revoke all grants associated with this client across all users. Grants are keyed as
    // grant:{userId}:{grantId}, so scan every grant and check the stored clientId. Keys are
    // collected before anything is deleted: deleting while paginating could skip records.
    for (const keyName of await this.listAllKeys('grant:')) {
      const grantData: Grant | null = await this.env.OAUTH_KV.get(keyName, { type: 'json' });
      if (grantData && grantData.clientId === clientId) {
        await this.revokeGrant(grantData.id, grantData.userId);
      }
    }

    // Exchanged access tokens owned by this client can live below a source grant owned by
    // another client. Ordinary tokens were already removed by revokeGrant() above. The sweep
    // does not consult the current allowTokenExchangeGrant setting: tokens issued while
    // exchange was enabled must not outlive their client once it is switched off.
    for (const keyName of await this.listAllKeys('token:')) {
      const tokenData: Token | null = await this.env.OAUTH_KV.get(keyName, { type: 'json' });
      if (tokenData?.grant?.clientId === clientId) {
        await this.env.OAUTH_KV.delete(keyName);
      }
    }
  }

  /** Every key under a prefix, read to completion before the caller mutates anything. */
  private async listAllKeys(prefix: string): Promise<string[]> {
    const names: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.env.OAUTH_KV.list(cursor ? { prefix, cursor } : { prefix });
      names.push(...page.keys.map((key) => key.name));
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    return names;
  }

  /**
   * Lists all authorization grants for a specific user with pagination support
   * Returns a summary of each grant without sensitive information
   * @param userId - The ID of the user whose grants to list
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with grant summaries and optional cursor
   */
  async listUserGrants(userId: string, options?: ListOptions): Promise<ListResult<GrantSummary>> {
    // Prepare list options for KV
    const listOptions: { limit?: number; cursor?: string; prefix: string } = {
      prefix: `grant:${userId}:`,
    };

    if (options?.limit !== undefined) {
      listOptions.limit = options.limit;
    }

    if (options?.cursor !== undefined) {
      listOptions.cursor = options.cursor;
    }

    // Use the KV list() function to get grant keys with pagination
    const response = await this.env.OAUTH_KV.list(listOptions);

    // Fetch all grants in parallel and convert to grant summaries
    const grantSummaries: GrantSummary[] = [];
    const promises = response.keys.map(async (key: { name: string }) => {
      const grantData: Grant | null = await this.env.OAUTH_KV.get(key.name, { type: 'json' });
      if (grantData) {
        // Create a summary with only the public fields
        const summary: GrantSummary = {
          id: grantData.id,
          clientId: grantData.clientId,
          userId: grantData.userId,
          scope: grantData.scope,
          metadata: grantData.metadata,
          createdAt: grantData.createdAt,
          expiresAt: grantData.expiresAt,
          redirectUri: grantData.redirectUri,
          resource: grantData.resource,
        };
        grantSummaries.push(summary);
      }
    });

    await Promise.all(promises);

    // Return result with cursor if there are more results
    return {
      items: grantSummaries,
      cursor: response.list_complete ? undefined : response.cursor,
    };
  }

  /**
   * Revokes an authorization grant and all its associated access tokens
   * @param grantId - The ID of the grant to revoke
   * @param userId - The ID of the user who owns the grant
   * @returns A Promise resolving when the revocation is confirmed.
   */
  async revokeGrant(grantId: string, userId: string): Promise<void> {
    // Construct the full grant key with user ID
    const grantKey = `grant:${userId}:${grantId}`;

    // Delete all access tokens associated with this grant
    const tokenPrefix = `token:${userId}:${grantId}:`;

    // Handle pagination to ensure we delete all tokens even if there are more than 1000
    let cursor: string | undefined;
    let allTokensDeleted = false;

    // Continue fetching and deleting tokens until we've processed all of them
    while (!allTokensDeleted) {
      const listOptions: { prefix: string; cursor?: string } = {
        prefix: tokenPrefix,
      };

      if (cursor) {
        listOptions.cursor = cursor;
      }

      const result = await this.env.OAUTH_KV.list(listOptions);

      // Delete each token in this batch
      if (result.keys.length > 0) {
        await Promise.all(
          result.keys.map((key: { name: string }) => {
            return this.env.OAUTH_KV.delete(key.name);
          })
        );
      }

      // Check if we need to fetch more tokens
      if (result.list_complete) {
        allTokensDeleted = true;
      } else {
        cursor = result.cursor;
      }
    }

    // After all tokens are deleted, delete the grant itself
    await this.env.OAUTH_KV.delete(grantKey);
  }

  /**
   * Decodes a token and returns token data with decrypted props
   * @param token - The token
   * @returns Promise resolving to token data with decrypted props, or null if token is invalid
   */
  async unwrapToken<T = any>(token: string): Promise<TokenSummary<T> | null> {
    return await this.provider.unwrapToken(token, this.env);
  }

  /**
   * Exchanges an existing access token for a new one with modified characteristics
   * Implements OAuth 2.0 Token Exchange (RFC 8693)
   * @param options - Options for token exchange including subject token and optional modifications
   * @returns Promise resolving to token response with new access token
   * @throws CimdFetchError when the grant's client ID is a CIMD URL whose document cannot be resolved
   */
  async exchangeToken(options: ExchangeTokenOptions): Promise<TokenResponse> {
    // Validate subject token first to get client info
    const tokenSummary = await this.unwrapToken(options.subjectToken);
    if (!tokenSummary) {
      throw new Error('Invalid or expired subject token');
    }

    const clientInfo = await this.lookupClient(tokenSummary.grant.clientId);
    if (!clientInfo) {
      throw new Error('Client not found');
    }

    // Perform the token exchange using the shared method
    // Errors will be thrown directly from exchangeToken with appropriate messages
    return await this.provider.exchangeToken(
      options.subjectToken,
      options.scope,
      options.aud,
      options.expiresIn,
      clientInfo,
      this.env
    );
  }

  async purgeExpiredData(options?: PurgeOptions): Promise<PurgeResult> {
    const batchSize = options?.batchSize ?? DEFAULT_PURGE_BATCH_SIZE;
    const purgeOrphanedGrants = options?.purgeOrphanedGrants !== false;
    const purgeExpiredGrants = options?.purgeExpiredGrants !== false;
    const purgeOrphanedTokens = options?.purgeOrphanedTokens !== false;
    const now = Math.floor(Date.now() / 1000);

    const result: PurgeResult = {
      grantsChecked: 0,
      grantsPurged: 0,
      tokensChecked: 0,
      tokensPurged: 0,
      done: false,
    };
    // Phase 1: Grant sweep
    if (purgeOrphanedGrants || purgeExpiredGrants) {
      const knownGoodClients = new Set<string>();
      const knownMissingClients = new Set<string>();
      let grantCursor: string | undefined;
      let grantsDone = false;

      while (!grantsDone && result.grantsChecked < batchSize) {
        const listOptions: { prefix: string; cursor?: string; limit?: number } = {
          prefix: 'grant:',
          limit: Math.min(1000, batchSize - result.grantsChecked),
        };
        if (grantCursor) {
          listOptions.cursor = grantCursor;
        }

        const page = await this.env.OAUTH_KV.list(listOptions);

        for (const key of page.keys) {
          if (result.grantsChecked >= batchSize) break;
          result.grantsChecked++;

          const grantData: Grant | null = await this.env.OAUTH_KV.get(key.name, { type: 'json' });
          if (!grantData) continue;

          let shouldPurge = false;

          // Expiry check (defense-in-depth for KV TTL)
          if (purgeExpiredGrants && grantData.expiresAt !== undefined && now >= grantData.expiresAt) {
            shouldPurge = true;
          }

          // Orphan check: skip CIMD clients (URL-based client IDs not stored in KV)
          if (!shouldPurge && purgeOrphanedGrants && !this.provider.isClientMetadataUrl(grantData.clientId)) {
            if (knownMissingClients.has(grantData.clientId)) {
              shouldPurge = true;
            } else if (!knownGoodClients.has(grantData.clientId)) {
              const client = await this.env.OAUTH_KV.get(`client:${grantData.clientId}`, { type: 'json' });
              if (client) {
                knownGoodClients.add(grantData.clientId);
              } else {
                knownMissingClients.add(grantData.clientId);
                shouldPurge = true;
              }
            }
          }

          if (shouldPurge) {
            await this.revokeGrant(grantData.id, grantData.userId);
            result.grantsPurged++;
          }
        }

        if (page.list_complete) {
          grantsDone = true;
        } else {
          grantCursor = page.cursor;
        }
      }

      // If grant sweep didn't finish, skip token sweep
      if (!grantsDone) {
        return result;
      }
    }

    // Phase 2: Token sweep
    if (purgeOrphanedTokens) {
      const knownGoodGrants = new Set<string>();
      const knownMissingGrants = new Set<string>();
      let tokenCursor: string | undefined;
      let tokensDone = false;

      while (!tokensDone && result.tokensChecked < batchSize) {
        const listOptions: { prefix: string; cursor?: string; limit?: number } = {
          prefix: 'token:',
          limit: Math.min(1000, batchSize - result.tokensChecked),
        };
        if (tokenCursor) {
          listOptions.cursor = tokenCursor;
        }

        const page = await this.env.OAUTH_KV.list(listOptions);

        for (const key of page.keys) {
          if (result.tokensChecked >= batchSize) break;
          result.tokensChecked++;

          const tokenData: Token | null = await this.env.OAUTH_KV.get(key.name, { type: 'json' });
          if (!tokenData) continue;

          const grantKey = `grant:${tokenData.userId}:${tokenData.grantId}`;
          let shouldPurge = false;
          if (knownMissingGrants.has(grantKey)) {
            shouldPurge = true;
          } else if (!knownGoodGrants.has(grantKey)) {
            const grantExists = await this.env.OAUTH_KV.get(grantKey);
            if (grantExists) {
              knownGoodGrants.add(grantKey);
            } else {
              knownMissingGrants.add(grantKey);
              shouldPurge = true;
            }
          }

          if (shouldPurge) {
            await this.env.OAUTH_KV.delete(key.name);
            result.tokensPurged++;
          }
        }

        if (page.list_complete) {
          tokensDone = true;
        } else {
          tokenCursor = page.cursor;
        }
      }

      if (!tokensDone) {
        return result;
      }
    }

    result.done = true;
    return result;
  }
}

/**
 * Default export of the OAuth provider
 * This allows users to import the library and use it directly as in the example
 */
export default OAuthProvider;
