import { validateResourceUri } from './oauth-resource';

const PROTECTED_RESOURCE_WELL_KNOWN_PREFIX = '/.well-known/oauth-protected-resource';
const NO_CACHE_HEADERS = { 'Cache-Control': 'no-store', Pragma: 'no-cache' } as const;

/** RFC 9728 metadata published by a standalone OAuth resource server. */
export interface OAuthResourceMetadata {
  /** The one canonical HTTPS identifier for this protected resource. */
  resource: string;
  /** Authorization server issuers that can issue tokens for this resource. */
  authorization_servers: string[];
  /** Minimal scopes used to access the protected resource. */
  scopes_supported?: string[];
  /** Bearer-token presentation methods. This implementation supports only `header`. */
  bearer_methods_supported?: string[];
  /** Human-readable protected-resource name. */
  resource_name?: string;
}

/** Successful result returned by the application's token validator. */
export interface OAuthResourceTokenValidation<Props> {
  /**
   * Application authorization context exposed to the protected handler as
   * `ctx.props`. Include every identity, scope, tenant, or policy value the
   * handler needs; the resource-server wrapper does not infer authorization
   * fields from the token beyond audience and expiry.
   */
  props: Props;
  /** Canonical audience to which the token is bound. */
  audience: string;
  /** Optional absolute expiry as seconds since the Unix epoch. */
  expiresAt?: number;
}

/** Input supplied to the application's token validator. */
export interface OAuthResourceTokenValidationInput<Env> {
  token: string;
  request: Request;
  env: Env;
}

/** Protected application handler called after successful token validation. */
export interface OAuthResourceHandler<Env, Props> {
  fetch(request: Request, env: Env, ctx: ExecutionContext<Props>): Response | Promise<Response>;
}

/** Configuration for {@link createOAuthResourceServer}. */
export interface OAuthResourceServerOptions<Env = Cloudflare.Env, Props = unknown> {
  /** RFC 9728 metadata, including this server's one canonical resource. */
  resourceMetadata: OAuthResourceMetadata;
  /** Application handler for the canonical resource URL and its path descendants. */
  handler: OAuthResourceHandler<Env, Props>;
  /**
   * Validate a presented bearer token using application-selected infrastructure.
   *
   * This can call an RFC 7662 endpoint, a Worker over a Service Binding, or a
   * JWT verifier. Return `null` for an invalid token. Thrown errors fail closed.
   */
  validateToken(input: OAuthResourceTokenValidationInput<Env>): Promise<OAuthResourceTokenValidation<Props> | null>;
}

/** Fetch handler returned by {@link createOAuthResourceServer}. */
export interface OAuthResourceServer<Env = Cloudflare.Env> {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response>;
}

type MutableExecutionContext<Props> = Omit<ExecutionContext<Props>, 'props'> & { props: Props };

/**
 * Create a standalone OAuth protected-resource Worker.
 *
 * The returned handler publishes RFC 9728 metadata, challenges unauthenticated
 * requests, validates bearer-token audience and expiry after the caller's
 * validator succeeds, and routes only the canonical resource and descendants
 * to the application handler.
 */
export function createOAuthResourceServer<Env = Cloudflare.Env, Props = unknown>(
  options: OAuthResourceServerOptions<Env, Props>
): OAuthResourceServer<Env> {
  const validated = validateOptions(options);

  return {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
      const url = new URL(request.url);

      if (isProtectedResourceMetadataPath(url)) {
        if (!isExactUrl(url, validated.metadataUrl)) {
          return addCorsHeaders(new Response(null, { status: 404 }), request);
        }

        if (request.method === 'OPTIONS') {
          return addCorsHeaders(
            new Response(null, {
              status: 204,
              headers: { 'Content-Length': '0' },
            }),
            request
          );
        }

        if (request.method !== 'GET') {
          return addCorsHeaders(
            new Response(null, {
              status: 405,
              headers: { Allow: 'GET' },
            }),
            request
          );
        }

        return addCorsHeaders(
          Response.json(validated.metadata, {
            headers: NO_CACHE_HEADERS,
          }),
          request
        );
      }

      if (!isCanonicalResourceRequest(url, validated.resourceUrl)) {
        return new Response(null, { status: 404 });
      }

      if (request.method === 'OPTIONS') {
        return addCorsHeaders(
          new Response(null, {
            status: 204,
            headers: { 'Content-Length': '0' },
          }),
          request
        );
      }

      const token = parseBearerToken(request.headers.get('Authorization'));
      if (!token) {
        return addCorsHeaders(createBearerChallenge(url, validated, false), request);
      }

      let validation: OAuthResourceTokenValidation<Props> | null;
      try {
        validation = await options.validateToken({ token, request, env });
      } catch {
        return addCorsHeaders(createValidationUnavailableResponse(), request);
      }

      if (!isValidTokenValidation(validation, validated.resource)) {
        return addCorsHeaders(createBearerChallenge(url, validated, true), request);
      }

      (ctx as MutableExecutionContext<Props>).props = validation.props;
      const response = await options.handler.fetch(request, env, ctx as ExecutionContext<Props>);
      return addCorsHeaders(response, request);
    },
  };
}

interface ValidatedResourceConfiguration {
  resource: string;
  resourceUrl: URL;
  metadataUrl: URL;
  metadata: OAuthResourceMetadata;
}

function validateOptions<Env, Props>(options: OAuthResourceServerOptions<Env, Props>): ValidatedResourceConfiguration {
  if (!options || typeof options !== 'object') {
    throw new TypeError('OAuth resource server options are required');
  }
  if (!options.handler || typeof options.handler.fetch !== 'function') {
    throw new TypeError('handler must provide a fetch function');
  }
  if (typeof options.validateToken !== 'function') {
    throw new TypeError('validateToken must be a function');
  }

  const resource = options.resourceMetadata?.resource;
  const resourceUrl = parseCanonicalHttpsUrl(resource);
  if (!resourceUrl) {
    throw new TypeError('resourceMetadata.resource must be a canonical absolute HTTPS URI without a fragment');
  }

  const authorizationServers = options.resourceMetadata.authorization_servers;
  if (!Array.isArray(authorizationServers) || authorizationServers.length === 0) {
    throw new TypeError('resourceMetadata.authorization_servers must contain at least one issuer');
  }
  for (const issuer of authorizationServers) {
    const issuerUrl = parseCanonicalHttpsUrl(issuer);
    if (!issuerUrl || issuerUrl.search || issuerUrl.hash) {
      throw new TypeError('resourceMetadata.authorization_servers must contain canonical HTTPS issuer URLs');
    }
  }

  const bearerMethods = options.resourceMetadata.bearer_methods_supported;
  if (bearerMethods !== undefined && (bearerMethods.length !== 1 || bearerMethods[0] !== 'header')) {
    throw new TypeError("resourceMetadata.bearer_methods_supported only supports 'header'");
  }

  const configuredScopes = options.resourceMetadata.scopes_supported ?? [];
  if (configuredScopes.some((scope) => !isValidScopeToken(scope))) {
    throw new TypeError('resourceMetadata.scopes_supported must contain valid OAuth scope tokens');
  }
  const resourceScopes = [...new Set(configuredScopes)].filter((scope) => scope !== 'offline_access');

  return {
    resource,
    resourceUrl,
    metadataUrl: new URL(getResourceMetadataUrl(resource)),
    metadata: {
      resource,
      authorization_servers: [...authorizationServers],
      ...(resourceScopes.length ? { scopes_supported: resourceScopes } : {}),
      bearer_methods_supported: bearerMethods ? [...bearerMethods] : ['header'],
      ...(options.resourceMetadata.resource_name !== undefined
        ? { resource_name: options.resourceMetadata.resource_name }
        : {}),
    },
  };
}

function parseCanonicalHttpsUrl(value: unknown): URL | null {
  if (typeof value !== 'string' || !validateResourceUri(value)) {
    return null;
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }

  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    parsed.protocol !== parsed.protocol.toLowerCase() ||
    parsed.hostname !== parsed.hostname.toLowerCase()
  ) {
    return null;
  }

  // `URL` repairs default ports, dot segments, backslashes, and a missing root
  // slash. A bare origin is the only alternate spelling allowed by RFC 9728.
  if (parsed.href !== value && parsed.origin !== value) {
    return null;
  }

  return parsed;
}

function isValidScopeToken(scope: string): boolean {
  return typeof scope === 'string' && scope.length > 0 && /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope);
}

function getResourceMetadataUrl(resource: string): string {
  const parsed = new URL(resource);
  const suffix = parsed.pathname === '/' ? '' : parsed.pathname;
  return `${parsed.origin}${PROTECTED_RESOURCE_WELL_KNOWN_PREFIX}${suffix}${parsed.search}`;
}

function isProtectedResourceMetadataPath(url: URL): boolean {
  return (
    url.pathname === PROTECTED_RESOURCE_WELL_KNOWN_PREFIX ||
    url.pathname.startsWith(`${PROTECTED_RESOURCE_WELL_KNOWN_PREFIX}/`)
  );
}

function isExactUrl(actual: URL, expected: URL): boolean {
  return actual.href === expected.href;
}

function isCanonicalResourceRequest(requestUrl: URL, resourceUrl: URL): boolean {
  if (requestUrl.origin !== resourceUrl.origin) return false;
  if (resourceUrl.search && requestUrl.search !== resourceUrl.search) return false;

  const resourcePath = resourceUrl.pathname;
  if (requestUrl.pathname === resourcePath) return true;
  if (resourcePath === '/') return requestUrl.pathname.startsWith('/');

  const descendantPrefix = resourcePath.endsWith('/') ? resourcePath : `${resourcePath}/`;
  return requestUrl.pathname.startsWith(descendantPrefix);
}

function parseBearerToken(authorization: string | null): string | null {
  if (!authorization) return null;
  const match = /^Bearer[\t ]+([^\s,]+)$/i.exec(authorization);
  return match?.[1] || null;
}

function isValidTokenValidation<Props>(
  validation: OAuthResourceTokenValidation<Props> | null,
  canonicalResource: string
): validation is OAuthResourceTokenValidation<Props> {
  if (!validation || typeof validation !== 'object') return false;
  if (validation.audience !== canonicalResource) return false;
  if (!Object.prototype.hasOwnProperty.call(validation, 'props')) return false;

  if (validation.expiresAt !== undefined) {
    if (typeof validation.expiresAt !== 'number' || !Number.isFinite(validation.expiresAt)) return false;
    if (validation.expiresAt <= Date.now() / 1000) return false;
  }

  return true;
}

function createBearerChallenge(
  requestUrl: URL,
  validated: ValidatedResourceConfiguration,
  invalidToken: boolean
): Response {
  let challenge = 'Bearer realm="OAuth"';
  if (isExactResourceUrl(requestUrl, validated.resourceUrl)) {
    challenge += `, resource_metadata="${validated.metadataUrl.href}"`;
  }
  if (invalidToken) {
    challenge += ', error="invalid_token"';
  }

  return new Response(null, {
    status: 401,
    headers: {
      ...NO_CACHE_HEADERS,
      'WWW-Authenticate': challenge,
    },
  });
}

function createValidationUnavailableResponse(): Response {
  return new Response(null, {
    status: 503,
    headers: NO_CACHE_HEADERS,
  });
}

function isExactResourceUrl(requestUrl: URL, resourceUrl: URL): boolean {
  if (requestUrl.href === resourceUrl.href) return true;
  return (
    resourceUrl.href === resourceUrl.origin &&
    requestUrl.origin === resourceUrl.origin &&
    requestUrl.pathname === '/' &&
    requestUrl.search === ''
  );
}

function addCorsHeaders(response: Response, request: Request): Response {
  const origin = request.headers.get('Origin');
  if (!origin) return response;

  const withCors = new Response(response.body, response);
  withCors.headers.set('Access-Control-Allow-Origin', origin);
  withCors.headers.set('Access-Control-Allow-Methods', '*');
  withCors.headers.set('Access-Control-Allow-Headers', 'Authorization, *');
  appendHeaderValue(withCors.headers, 'Vary', 'Origin');
  appendHeaderValue(withCors.headers, 'Access-Control-Expose-Headers', 'WWW-Authenticate');
  appendHeaderValue(withCors.headers, 'Access-Control-Expose-Headers', 'Retry-After');
  withCors.headers.set('Access-Control-Max-Age', '86400');
  return withCors;
}

function appendHeaderValue(headers: Headers, name: string, value: string): void {
  const values = (headers.get(name) ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (!values.some((item) => item.toLowerCase() === value.toLowerCase())) values.push(value);
  headers.set(name, values.join(', '));
}
