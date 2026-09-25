/**
 * HTTP details shared by the authorization-server host (`OAuthProvider`, `OAuthAuthorizationServer`)
 * and the resource-server host (`OAuthResourceServer`), so the two can't drift apart.
 */

/**
 * Adds CORS headers for a browser client. The request's `Origin` is reflected: bearer tokens are
 * not ambient credentials, so any origin may present one it holds. Browser OAuth and MCP clients
 * need `WWW-Authenticate` (discovery, step-up) and `Retry-After` (backoff) exposed. Headers the
 * response already carries are kept, so an API handler can narrow who may read its responses.
 * Preflights (`OPTIONS`) are answered by the hosts before any handler runs and stay permissive, so
 * an MCP client's preflight always succeeds; the browser enforces the handler's policy on the actual
 * response, and sending the request carries no ambient credential to abuse.
 */
export function withCorsHeaders(response: Response, request: Request): Response {
  const origin = request.headers.get('Origin');
  if (!origin) return response;
  const cors = new Response(response.body, response);
  const setUnlessPresent = (name: string, value: string) => {
    if (!cors.headers.has(name)) cors.headers.set(name, value);
  };
  setUnlessPresent('Access-Control-Allow-Origin', origin);
  setUnlessPresent('Access-Control-Allow-Methods', '*');
  // Authorization must be named: `*` doesn't cover it.
  setUnlessPresent('Access-Control-Allow-Headers', 'Authorization, *');
  setUnlessPresent('Access-Control-Max-Age', '86400');
  appendHeaderValue(cors.headers, 'Vary', 'Origin');
  appendHeaderValue(cors.headers, 'Access-Control-Expose-Headers', 'WWW-Authenticate');
  appendHeaderValue(cors.headers, 'Access-Control-Expose-Headers', 'Retry-After');
  return cors;
}

/** Adds `value` to a comma-separated header unless it's already there (case-insensitively). */
export function appendHeaderValue(headers: Headers, name: string, value: string): void {
  const values = (headers.get(name) ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (!values.some((item) => item.toLowerCase() === value.toLowerCase())) values.push(value);
  headers.set(name, values.join(', '));
}

/**
 * A resource's up-front scopes: `baseScopes`, or the deprecated `resourceMetadata.scopes_supported`
 * it replaces. Both at once is ambiguous and refused.
 */
export function resolveBaseScopes(
  baseScopes: readonly string[] | undefined,
  deprecatedScopesSupported: readonly string[] | undefined
): string[] | undefined {
  if (baseScopes !== undefined && deprecatedScopesSupported !== undefined) {
    throw new TypeError('Set baseScopes only: resourceMetadata.scopes_supported is deprecated in its favour');
  }
  const scopes = baseScopes ?? deprecatedScopesSupported;
  return scopes === undefined ? undefined : [...scopes];
}

/**
 * The scopes a protected resource advertises and challenges with: deduplicated, and without
 * `offline_access`, which is an authorization-server capability rather than a resource requirement.
 */
export function baselineResourceScopes(scopes: readonly string[]): string[] {
  return [...new Set(scopes)].filter((scope) => scope !== 'offline_access');
}
