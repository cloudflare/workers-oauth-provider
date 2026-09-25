/**
 * The error your code throws to the library: from a `tokenExchangeCallback`, or from an
 * `OAuthResourceServer`'s `validateToken`, to answer with a standard OAuth error response instead
 * of a generic failure. Its own module so both hosts can use it without importing the package entry.
 */

/**
 * The internal reason behind an error response, forwarded to the `onError` hook and never
 * placed on the wire. `category` is a stable kebab-case subsystem (`client-authentication`,
 * `authorization-code-grant`, `refresh-token-grant`, `token-exchange-grant`,
 * `token-endpoint-request`, `token-revocation`, `token-issuance`, `resource-indicator`,
 * `client-registration`, `client-id-metadata-document`, `protected-resource`,
 * `enterprise-managed-authorization`, `token-exchange-callback`); `reason` is a stable
 * snake_case slug naming the exact check that failed. Treat both like enum members in semver.
 * `detail` may carry structured context such as a caught error; it is never a secret.
 */
export interface OAuthErrorInternal {
  /** Stable kebab-case subsystem that produced the error. */
  category: string;
  /** Stable snake_case slug naming the failed check, often more specific than the wire description. */
  reason: string;
  /** Optional structured context, e.g. the caught error or the offending parameter. */
  detail?: unknown;
}

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

  /**
   * Internal reason forwarded to the `onError` hook and never sent on the wire. The library
   * sets it on every error it originates; a `tokenExchangeCallback` may set its own. An
   * `OAuthError` thrown without one reaches `onError` as
   * `{ category: 'token-exchange-callback', reason: 'callback_error', detail: error }`.
   */
  internal?: OAuthErrorInternal;
  /**
   * For `insufficient_scope` from an `OAuthResourceServer`'s `validateToken`: every scope the
   * operation needs, named in the `403` challenge. Defaults to the resource's `requiredScopes`.
   */
  requiredScopes?: string[];
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
 *     // invalid_grant can never recover: the provider also revokes this grant and its tokens.
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
  /** Scopes an `insufficient_scope` challenge names. */
  public readonly requiredScopes?: string[];

  constructor(code: string, options: OAuthErrorOptions) {
    super(options.description);
    this.name = 'OAuthError';
    this.code = code;
    this.options = { ...options, statusCode: options.statusCode ?? 400 };
    this.description = this.options.description;
    this.statusCode = this.options.statusCode;
    this.headers = this.options.headers;
    this.requiredScopes = this.options.requiredScopes;
  }
}
