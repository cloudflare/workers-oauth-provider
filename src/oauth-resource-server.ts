import { WorkerEntrypoint } from 'cloudflare:workers';
import {
  hasAcceptedCanonicalScheme,
  requestCarriesResourceQuery,
  resourceMatches,
  validateResourceUri,
} from './oauth-resource';

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

/**
 * Validates a bearer token presented to one resource. `null` for a token that is not
 * valid for that resource; a thrown error fails closed as `503`.
 */
export type OAuthResourceTokenValidator<Props> = (
  resource: string,
  token: string
) => Promise<OAuthResourceTokenValidation<Props> | null>;

/**
 * Protected application handler called after successful token validation: an object with
 * `fetch`, or a `WorkerEntrypoint` subclass instantiated per request with `(ctx, env)`. Either
 * way `ctx.props` carries what the validator returned.
 */
export type OAuthResourceHandler<Env, Props> =
  | { fetch(request: Request, env: Env, ctx: ExecutionContext<Props>): Response | Promise<Response> }
  | (new (ctx: ExecutionContext<Props>, env: Env) => { fetch(request: Request): Response | Promise<Response> });

/** Configuration for {@link createOAuthResourceServer}. */
export interface OAuthResourceServerOptions<Env = Cloudflare.Env, Props = unknown> {
  /** RFC 9728 metadata, including this server's one canonical resource. */
  resourceMetadata: OAuthResourceMetadata;
  /** Application handler for the canonical resource URL and its path descendants. */
  handler: OAuthResourceHandler<Env, Props>;
  /**
   * The validator for a request. The host calls what you return with this server's
   * canonical resource and the bearer token, so neither is repeated here.
   *
   * - The authorization server in another Worker, over a Service Binding to a
   *   `WorkerEntrypoint` that exposes `OAuthAuthorizationServer.validateToken()`:
   *   `(env) => env.AUTH_SERVER.validateToken`
   * - The authorization server in this Worker:
   *   `(env) => (resource, token) => authorizationServer.validateToken(resource, token, env)`
   * - Anything else, at your own risk: a function that validates the token for `resource`.
   */
  validateToken(env: Env, request: Request): OAuthResourceTokenValidator<Props>;
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
        if (request.method === 'OPTIONS') {
          return addCorsHeaders(
            new Response(null, {
              status: 204,
              headers: { 'Content-Length': '0' },
            }),
            request
          );
        }

        // RFC 9728 §3 fixes the origin and path; a cache-busting query must not hide the
        // document, while a resource's own query parameters must still be present.
        if (!isMetadataUrlRequest(url, validated.metadataUrl)) {
          return addCorsHeaders(new Response(null, { status: 404 }), request);
        }

        if (request.method !== 'GET' && request.method !== 'HEAD') {
          return addCorsHeaders(
            new Response(null, {
              status: 405,
              headers: { Allow: 'GET, HEAD, OPTIONS' },
            }),
            request
          );
        }

        const metadata = Response.json(validated.metadata, { headers: NO_CACHE_HEADERS });
        return addCorsHeaders(
          request.method === 'HEAD' ? new Response(null, { status: 200, headers: metadata.headers }) : metadata,
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
        validation = await options.validateToken(env, request)(validated.resource, token);
      } catch {
        return addCorsHeaders(createValidationUnavailableResponse(), request);
      }

      if (!isValidTokenValidation(validation, validated.resource)) {
        return addCorsHeaders(createBearerChallenge(url, validated, true), request);
      }

      (ctx as MutableExecutionContext<Props>).props = validation.props;
      const handler = options.handler;
      const response = isEntrypointClass(handler)
        ? await new handler(ctx as ExecutionContext<Props>, env).fetch(request)
        : await handler.fetch(request, env, ctx as ExecutionContext<Props>);
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
  if (
    !options.handler ||
    (!isEntrypointClass(options.handler) && typeof (options.handler as { fetch?: unknown }).fetch !== 'function')
  ) {
    throw new TypeError('handler must provide a fetch function or extend WorkerEntrypoint');
  }
  if (typeof options.validateToken !== 'function') {
    throw new TypeError('validateToken must be a function');
  }

  const resource = options.resourceMetadata?.resource;
  const resourceUrl = parseCanonicalUrl(resource);
  if (!resourceUrl) {
    throw new TypeError(
      'resourceMetadata.resource must be a canonical absolute HTTPS URI without a fragment (http is accepted only on a loopback host)'
    );
  }
  // The metadata namespace is dispatched to discovery before the protected handler, so a
  // resource inside it could never receive a request.
  if (isProtectedResourceMetadataPath(resourceUrl)) {
    throw new TypeError(
      `resourceMetadata.resource must not be inside the ${PROTECTED_RESOURCE_WELL_KNOWN_PREFIX} namespace`
    );
  }

  const authorizationServers = options.resourceMetadata.authorization_servers;
  if (!Array.isArray(authorizationServers) || authorizationServers.length === 0) {
    throw new TypeError('resourceMetadata.authorization_servers must contain at least one issuer');
  }
  for (const issuer of authorizationServers) {
    const issuerUrl = parseCanonicalUrl(issuer);
    if (!issuerUrl || issuerUrl.search || issuerUrl.hash) {
      throw new TypeError(
        'resourceMetadata.authorization_servers must contain canonical HTTPS issuer URLs (http is accepted only on a loopback host)'
      );
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

function parseCanonicalUrl(value: unknown): URL | null {
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
    !hasAcceptedCanonicalScheme(parsed) ||
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

/** The same test the combined provider applies to its handlers. */
function isEntrypointClass<Env, Props>(
  handler: OAuthResourceHandler<Env, Props>
): handler is new (
  ctx: ExecutionContext<Props>,
  env: Env
) => { fetch(request: Request): Response | Promise<Response> } {
  return typeof handler === 'function' && handler.prototype instanceof WorkerEntrypoint;
}

function isProtectedResourceMetadataPath(url: URL): boolean {
  return (
    url.pathname === PROTECTED_RESOURCE_WELL_KNOWN_PREFIX ||
    url.pathname.startsWith(`${PROTECTED_RESOURCE_WELL_KNOWN_PREFIX}/`)
  );
}

function isMetadataUrlRequest(requestUrl: URL, metadataUrl: URL): boolean {
  return (
    requestUrl.origin === metadataUrl.origin &&
    requestUrl.pathname === metadataUrl.pathname &&
    requestCarriesResourceQuery(requestUrl, metadataUrl)
  );
}

function isCanonicalResourceRequest(requestUrl: URL, resourceUrl: URL): boolean {
  if (requestUrl.origin !== resourceUrl.origin) return false;
  if (!requestCarriesResourceQuery(requestUrl, resourceUrl)) return false;

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
  if (typeof validation.audience !== 'string' || !resourceMatches(validation.audience, canonicalResource)) return false;
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
  // RFC 9728 §5.1: every request this resource covers, including path-boundary
  // descendants of the canonical path, points at the one canonical document.
  if (isCanonicalResourceRequest(requestUrl, validated.resourceUrl)) {
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
