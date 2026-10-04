import { OUTBOUND_USER_AGENT } from './oauth-http';
import { CLIENT_ASSERTION_ALGORITHMS, type ClientAssertionKeys } from './client-assertion';
import type { JsonWebKeySet, OAuthJsonWebKey } from './ema/types';
import { isLoopbackHostname } from './oauth-resource';
import {
  negotiateCimdClientCapabilities,
  negotiateDynamicClientRegistrationCapabilities,
  type OAuthServerCapabilities,
} from './oauth-capabilities';

const CIMD_MAX_SIZE_BYTES = 5 * 1024;
const CIMD_FETCH_TIMEOUT_MS = 10_000;
const CIMD_CACHE_NAME = 'workers-oauth-provider:cimd:v1';
const CIMD_CACHE_MAX_TTL_SECONDS = 7 * 24 * 60 * 60;

/** Human-readable and key-discovery client metadata shared by DCR and CIMD clients. */
interface OAuthClientDisplayMetadata {
  /** Human-readable client name. */
  clientName?: string;
  /** Client homepage URI. */
  clientUri?: string;
  /** Client logo URI. */
  logoUri?: string;
  /** Client policy URI. */
  policyUri?: string;
  /** Client terms-of-service URI. */
  tosUri?: string;
  /** Client JSON Web Key Set URI. */
  jwksUri?: string;
  /** Internationalized human-readable metadata variants. */
  i18n?: Record<string, string>;
  /** Client developer contacts. */
  contacts?: string[];
}

/** Parsed, syntactically validated OAuth client metadata fields used by this package. */
interface ParsedOAuthClientMetadata extends OAuthClientDisplayMetadata {
  /** Client identifier supplied by a metadata document. */
  clientId?: string;
  /** Registered redirect URIs. */
  redirectUris?: string[];
  /** Advertised OAuth grant types. */
  grantTypes?: string[];
  /** Advertised OAuth response types. */
  responseTypes?: string[];
  /** Preferred token endpoint authentication method. */
  tokenEndpointAuthMethod?: string;
  /** Token endpoint authentication methods supported by the client. */
  tokenEndpointAuthMethodsSupported?: string[];
  /** Preferred signing algorithm for JWT client authentication. */
  tokenEndpointAuthSigningAlg?: string;
  /** JWT client-authentication signing algorithms supported by the client. */
  tokenEndpointAuthSigningAlgValuesSupported?: string[];
}

/** Effective metadata accepted by Dynamic Client Registration. */
export interface ResolvedDynamicClientRegistrationMetadata extends OAuthClientDisplayMetadata {
  /** Registered redirect URIs. */
  redirectUris: string[];
  /** Registered OAuth grant types. */
  grantTypes: string[];
  /** Registered OAuth response types. */
  responseTypes: string[];
  /** Registered token endpoint authentication method. */
  tokenEndpointAuthMethod: string;
  /** Whether the request explicitly selected its authentication method. */
  authMethodExplicit: boolean;
}

/** Effective client metadata returned after resolving a Client ID Metadata Document. */
interface ResolvedClientIdMetadataDocument extends OAuthClientDisplayMetadata {
  /** Client identifier matching the fetched document URL. */
  clientId: string;
  /** Required human-readable client name. */
  clientName: string;
  /** Registered redirect URIs. */
  redirectUris: string[];
  /** Mutually supported OAuth grant types. */
  grantTypes: string[];
  /** Mutually supported OAuth response types. */
  responseTypes: string[];
  /** The weakest token endpoint authentication method the client may use: `none` when it is usable. */
  tokenEndpointAuthMethod: string;
  /** Every token endpoint authentication method the client may present. */
  tokenEndpointAuthMethods: string[];
  /** Keys that verify the client's `private_key_jwt` assertions, when that method is usable. */
  clientAssertionKeys?: ClientAssertionKeys;
}

export function requireJsonObject(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Client metadata must be a JSON object');
  }
  return value as Record<string, unknown>;
}

function optionalString(value: unknown, fieldName: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') {
    throw new Error(`Invalid ${fieldName}: expected string, got ${typeof value}`);
  }
  return value;
}

function optionalStringArray(value: unknown, fieldName: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    throw new Error(`Invalid ${fieldName}: expected array, got ${typeof value}`);
  }
  if (!value.every((item) => typeof item === 'string')) {
    throw new Error(`Invalid ${fieldName}: array must contain only strings`);
  }
  return [...value];
}

function optionalHttpUri(value: unknown, fieldName: string): string | undefined {
  const uri = optionalString(value, fieldName);
  if (uri === undefined) return undefined;

  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error(`Invalid ${fieldName}: must be an absolute http: or https: URL`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Invalid ${fieldName}: must be an absolute http: or https: URL`);
  }

  return uri;
}

const I18N_FIELDS: Record<string, 'string' | 'uri'> = {
  client_name: 'string',
  client_uri: 'uri',
  logo_uri: 'uri',
  tos_uri: 'uri',
  policy_uri: 'uri',
};

function extractI18nFields(raw: Record<string, unknown>): Record<string, string> | undefined {
  const result: Record<string, string> = {};

  for (const key of Object.keys(raw)) {
    const hashIndex = key.indexOf('#');
    if (hashIndex <= 0 || hashIndex === key.length - 1) continue;

    const kind = I18N_FIELDS[key.slice(0, hashIndex)];
    if (!kind) continue;

    const value = kind === 'uri' ? optionalHttpUri(raw[key], key) : optionalString(raw[key], key);
    if (value !== undefined) result[key] = value;
  }

  return Object.keys(result).length > 0 ? result : undefined;
}

function validateChoiceConsistency(
  preferredName: string,
  preferredValue: string | undefined,
  choicesName: string,
  choices: readonly string[] | undefined
): void {
  if (preferredValue !== undefined && choices !== undefined && !choices.includes(preferredValue)) {
    throw new Error(`${preferredName} must be included in ${choicesName}`);
  }
}

function parseOAuthClientMetadata(raw: Record<string, unknown>): ParsedOAuthClientMetadata {
  const tokenEndpointAuthMethod = optionalString(raw.token_endpoint_auth_method, 'token_endpoint_auth_method');
  const tokenEndpointAuthMethodsSupported = optionalStringArray(
    raw.token_endpoint_auth_methods_supported,
    'token_endpoint_auth_methods_supported'
  );
  const tokenEndpointAuthSigningAlg = optionalString(
    raw.token_endpoint_auth_signing_alg,
    'token_endpoint_auth_signing_alg'
  );
  const tokenEndpointAuthSigningAlgValuesSupported = optionalStringArray(
    raw.token_endpoint_auth_signing_alg_values_supported,
    'token_endpoint_auth_signing_alg_values_supported'
  );
  validateChoiceConsistency(
    'token_endpoint_auth_method',
    tokenEndpointAuthMethod,
    'token_endpoint_auth_methods_supported',
    tokenEndpointAuthMethodsSupported
  );
  validateChoiceConsistency(
    'token_endpoint_auth_signing_alg',
    tokenEndpointAuthSigningAlg,
    'token_endpoint_auth_signing_alg_values_supported',
    tokenEndpointAuthSigningAlgValuesSupported
  );

  return {
    clientId: optionalString(raw.client_id, 'client_id'),
    redirectUris: optionalStringArray(raw.redirect_uris, 'redirect_uris'),
    clientName: optionalString(raw.client_name, 'client_name'),
    clientUri: optionalHttpUri(raw.client_uri, 'client_uri'),
    logoUri: optionalHttpUri(raw.logo_uri, 'logo_uri'),
    policyUri: optionalHttpUri(raw.policy_uri, 'policy_uri'),
    tosUri: optionalHttpUri(raw.tos_uri, 'tos_uri'),
    jwksUri: optionalHttpUri(raw.jwks_uri, 'jwks_uri'),
    i18n: extractI18nFields(raw),
    contacts: optionalStringArray(raw.contacts, 'contacts'),
    grantTypes: optionalStringArray(raw.grant_types, 'grant_types'),
    responseTypes: optionalStringArray(raw.response_types, 'response_types'),
    tokenEndpointAuthMethod,
    tokenEndpointAuthMethodsSupported,
    tokenEndpointAuthSigningAlg,
    tokenEndpointAuthSigningAlgValuesSupported,
  };
}

function pickDisplayMetadata(metadata: ParsedOAuthClientMetadata): OAuthClientDisplayMetadata {
  const { clientName, clientUri, logoUri, policyUri, tosUri, jwksUri, i18n, contacts } = metadata;
  return { clientName, clientUri, logoUri, policyUri, tosUri, jwksUri, i18n, contacts };
}

/**
 * The checks every listed redirect URI passes, whatever the policy: no control characters, a
 * scheme, and not a dangerous one (`javascript:`, `data:` and the like). A Client ID Metadata
 * Document is held to these alone; the URI a request uses is then held to {@link validateRedirectUri}.
 * @throws Error when the redirect URI is not safe to store
 */
function validateRedirectUriSafety(redirectUri: string): void {
  const dangerousSchemes = ['javascript:', 'data:', 'vbscript:', 'file:', 'mailto:', 'blob:'];
  const normalized = redirectUri.trim();

  for (let i = 0; i < normalized.length; i++) {
    const code = normalized.charCodeAt(i);
    if ((code >= 0x00 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f)) {
      throw new Error('Invalid redirect URI');
    }
  }

  const colonIndex = normalized.indexOf(':');
  if (colonIndex === -1) throw new Error('Invalid redirect URI');

  const scheme = normalized.slice(0, colonIndex + 1).toLowerCase();
  if (dangerousSchemes.includes(scheme)) throw new Error('Invalid redirect URI');
}

/**
 * The checks every redirect URI a client registers passes, whether or not this server would send a
 * code to it: the {@link validateRedirectUriSafety} checks, a parseable URI, and no fragment (not
 * even an empty `#`) or userinfo.
 * @throws Error when the redirect URI can't be registered at all
 */
function validateListedRedirectUri(redirectUri: string): URL {
  validateRedirectUriSafety(redirectUri);
  const normalized = redirectUri.trim();

  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    throw new Error('Invalid redirect URI');
  }
  // RFC 6749 §3.1.2: no fragment, including an empty trailing `#` (which leaves url.hash empty).
  // Userinfo only disguises where the code goes.
  if (normalized.includes('#') || url.username || url.password) throw new Error('Invalid redirect URI');
  return url;
}

/**
 * Validates a redirect URI against the MCP / OAuth 2.1 redirect policy: `https`, or `http` on a
 * loopback host (`localhost`, `127.0.0.0/8`, `::1`), with no userinfo and no fragment (not even an
 * empty `#`). RFC 8252 private-use schemes are accepted only when the server enables
 * `allowPrivateUseRedirectUris`; remote `http` never is. The {@link validateRedirectUriSafety}
 * checks always apply.
 * @throws Error describing why the redirect URI is not acceptable
 */
export function validateRedirectUri(redirectUri: string, server: OAuthServerCapabilities): void {
  const url = validateListedRedirectUri(redirectUri);

  // MCP and OAuth 2.1: https, or http only on a loopback host (RFC 8252 §7.3). Remote http is never
  // acceptable; private-use schemes (RFC 8252 §7.1) only when the server opts in for native apps.
  if (url.protocol === 'https:') return;
  if (url.protocol === 'http:') {
    if (isLoopbackHostname(url.hostname)) return;
    throw new Error('Redirect URI must use https, or http on a loopback host');
  }
  if (!server.allowPrivateUseRedirectUris) {
    throw new Error('Redirect URI must use https, or http on a loopback host');
  }
}

/**
 * Validates the redirect URIs a client registers (dynamic registration, `createClient()`,
 * `updateClient()`). A client may list callbacks for surfaces this server won't send codes to:
 * Cursor lists `cursor://anysphere.cursor-mcp/oauth/callback` next to its https and loopback
 * callbacks. So each URI is held to {@link validateListedRedirectUri}, and at least one must satisfy
 * {@link validateRedirectUri} so the client can sign in. The URI a request uses is held to the full
 * policy by `parseAuthRequest()` and `completeAuthorization()`.
 * @throws Error when a URI can't be registered, or none of them could ever receive a code
 */
export function validateRegisteredRedirectUris(
  redirectUris: string[] | undefined,
  server: OAuthServerCapabilities
): string[] {
  if (!redirectUris || redirectUris.length === 0) {
    throw new Error('redirect_uris is required and must not be empty');
  }
  for (const redirectUri of redirectUris) validateListedRedirectUri(redirectUri);

  let firstRefusal: unknown;
  for (const redirectUri of redirectUris) {
    try {
      validateRedirectUri(redirectUri, server);
      return redirectUris;
    } catch (error) {
      firstRefusal ??= error;
    }
  }
  throw firstRefusal instanceof Error ? firstRefusal : new Error('Invalid redirect URI');
}

function requireValidRedirectUris(
  redirectUris: string[] | undefined,
  validate: (redirectUri: string) => void
): string[] {
  if (!redirectUris || redirectUris.length === 0) {
    throw new Error('redirect_uris is required and must not be empty');
  }
  for (const redirectUri of redirectUris) validate(redirectUri);
  return redirectUris;
}

/**
 * Resolves a Dynamic Client Registration request into the complete metadata
 * shape that can be stored, applying RFC 7591 defaults and server capability
 * validation exactly once.
 */
export function resolveDynamicClientRegistrationMetadata(
  raw: Record<string, unknown>,
  server: OAuthServerCapabilities
): ResolvedDynamicClientRegistrationMetadata {
  const metadata = parseOAuthClientMetadata(raw);
  const capabilities = negotiateDynamicClientRegistrationCapabilities(server, {
    tokenEndpointAuthMethod: metadata.tokenEndpointAuthMethod,
    tokenEndpointAuthMethodsSupported: metadata.tokenEndpointAuthMethodsSupported,
    grantTypes: metadata.grantTypes ?? ['authorization_code'],
    responseTypes: metadata.responseTypes ?? ['code'],
  });

  return {
    ...pickDisplayMetadata(metadata),
    redirectUris: validateRegisteredRedirectUris(metadata.redirectUris, server),
    ...capabilities,
    authMethodExplicit:
      metadata.tokenEndpointAuthMethod !== undefined || metadata.tokenEndpointAuthMethodsSupported !== undefined,
  };
}

/**
 * Path component of the raw client ID string. Deliberately not
 * `new URL().pathname`: WHATWG parsing collapses the `.` and `..` segments
 * that CIMD §3 requires rejecting, and normalizes `\` and scheme-relative
 * forms this validation must see verbatim.
 */
function rawPath(clientId: string): string {
  const schemeEnd = clientId.indexOf('://');
  if (schemeEnd === -1) return '';
  const authorityStart = schemeEnd + 3;
  const authorityEndOffset = clientId.slice(authorityStart).search(/[/?#]/);
  if (authorityEndOffset === -1) return '';
  const pathStart = authorityStart + authorityEndOffset;
  if (clientId[pathStart] !== '/') return '';
  const pathEndOffset = clientId.slice(pathStart).search(/[?#]/);
  return pathEndOffset === -1 ? clientId.slice(pathStart) : clientId.slice(pathStart, pathStart + pathEndOffset);
}

function validateClientIdentifierUrl(clientId: string): void {
  if (clientId !== clientId.trim() || /[\x00-\x20\x7f-\x9f\\]/.test(clientId)) {
    throw new Error('Client Identifier URL contains invalid whitespace or characters');
  }
  if (!/^https:\/\//i.test(clientId)) {
    throw new Error('Client Identifier URL must use an absolute HTTPS URL');
  }

  let parsed: URL;
  try {
    parsed = new URL(clientId);
  } catch {
    throw new Error('Client Identifier URL must be a valid HTTPS URL');
  }

  if (parsed.protocol !== 'https:') throw new Error('Client Identifier URL must use HTTPS');
  if (parsed.username || parsed.password) throw new Error('Client Identifier URL must not contain userinfo');
  if (parsed.hash) throw new Error('Client Identifier URL must not contain a fragment');

  const path = rawPath(clientId);
  if (!path) throw new Error('Client Identifier URL must contain a path component');

  for (const segment of path.split('/')) {
    let decodedSegment: string;
    try {
      decodedSegment = decodeURIComponent(segment);
    } catch {
      throw new Error('Client Identifier URL contains invalid percent encoding');
    }
    if (decodedSegment === '.' || decodedSegment === '..') {
      throw new Error('Client Identifier URL must not contain dot path segments');
    }
  }
}

/** Returns whether a client ID has the URL shape this package resolves through CIMD. */
export function isClientIdMetadataDocumentUrl(clientId: string): boolean {
  try {
    const parsed = new URL(clientId);
    return parsed.protocol === 'https:' && rawPath(clientId) !== '';
  } catch {
    return false;
  }
}

const PRIVATE_JWK_MEMBERS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);

/** Parses an inline `jwks`, refusing private or symmetric key material, which a public document must never carry. */
function parsePublicJwks(value: unknown): JsonWebKeySet | undefined {
  if (value === undefined) return undefined;
  const jwks = requireJsonObject(value);
  if (!Array.isArray(jwks.keys)) throw new Error('Invalid jwks: keys must be an array');

  const keys = jwks.keys.map((value) => {
    const key = requireJsonObject(value);
    if (Object.keys(key).some((member) => PRIVATE_JWK_MEMBERS.has(member))) {
      throw new Error('CIMD documents must not contain private key material');
    }
    return key as unknown as OAuthJsonWebKey;
  });
  return { keys };
}

/**
 * The keys and algorithms a document offering `private_key_jwt` supplies, or why they can't be used.
 * An unusable offer only matters when `private_key_jwt` is the document's sole method.
 */
function resolvePrivateKeyJwtKeys(
  metadata: ParsedOAuthClientMetadata,
  jwks: JsonWebKeySet | undefined
): { keys: ClientAssertionKeys } | { problem: string } {
  const { jwksUri } = metadata;
  if (jwks && jwksUri) return { problem: 'jwks and jwks_uri must not both be present' };
  if (!jwks && !jwksUri) return { problem: 'private_key_jwt requires jwks or jwks_uri' };
  if (jwks && (jwks.keys ?? []).length === 0) return { problem: 'private_key_jwt jwks must contain a key' };
  if (jwksUri) {
    const url = new URL(jwksUri);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
      return { problem: 'private_key_jwt jwks_uri must be an https: URL without userinfo or a fragment' };
    }
  }

  const algorithms = CLIENT_ASSERTION_ALGORITHMS.filter(
    (alg) =>
      (metadata.tokenEndpointAuthSigningAlg === undefined || metadata.tokenEndpointAuthSigningAlg === alg) &&
      (metadata.tokenEndpointAuthSigningAlgValuesSupported === undefined ||
        metadata.tokenEndpointAuthSigningAlgValuesSupported.includes(alg))
  );
  if (algorithms.length === 0) {
    return {
      problem: `private_key_jwt requires a token_endpoint_auth_signing_alg of ${CLIENT_ASSERTION_ALGORITHMS.join(' or ')}`,
    };
  }

  return { keys: jwks ? { jwks, algorithms } : { jwksUri, algorithms } };
}

function resolveClientIdMetadataDocument(
  metadataUrl: string,
  value: unknown,
  server: OAuthServerCapabilities
): ResolvedClientIdMetadataDocument {
  const raw = requireJsonObject(value);
  const metadata = parseOAuthClientMetadata(raw);

  if (metadata.clientId !== metadataUrl) {
    throw new Error(`client_id "${metadata.clientId}" does not match metadata URL "${metadataUrl}"`);
  }
  if (!metadata.clientName?.trim()) throw new Error('client_name is required and must not be empty');
  // The document is the client's, shared by every server it uses, so it may list a redirect this
  // server's policy refuses, such as a desktop app's private-use scheme next to its https callback.
  // Only the redirect URI a request uses must satisfy the policy, which parseAuthRequest() and
  // completeAuthorization() enforce; one unusable entry doesn't lock the client out.
  const redirectUris = requireValidRedirectUris(metadata.redirectUris, validateRedirectUriSafety);

  if ('client_secret' in raw || 'client_secret_expires_at' in raw) {
    throw new Error('CIMD documents must not contain client secrets');
  }
  const jwks = parsePublicJwks(raw.jwks);

  const offersPrivateKeyJwt =
    metadata.tokenEndpointAuthMethod === 'private_key_jwt' ||
    !!metadata.tokenEndpointAuthMethodsSupported?.includes('private_key_jwt');
  const privateKeyJwt = offersPrivateKeyJwt ? resolvePrivateKeyJwtKeys(metadata, jwks) : undefined;
  const clientAssertionKeys = privateKeyJwt && 'keys' in privateKeyJwt ? privateKeyJwt.keys : undefined;

  let capabilities: ReturnType<typeof negotiateCimdClientCapabilities>;
  try {
    capabilities = negotiateCimdClientCapabilities(
      server,
      {
        tokenEndpointAuthMethod: metadata.tokenEndpointAuthMethod,
        tokenEndpointAuthMethodsSupported: metadata.tokenEndpointAuthMethodsSupported,
        grantTypes: metadata.grantTypes ?? ['authorization_code'],
        responseTypes: metadata.responseTypes ?? ['code'],
      },
      { privateKeyJwt: clientAssertionKeys !== undefined }
    );
  } catch (error) {
    // Name the key problem rather than the method mismatch it caused.
    if (privateKeyJwt && 'problem' in privateKeyJwt) throw new Error(privateKeyJwt.problem);
    throw error;
  }

  return {
    ...pickDisplayMetadata(metadata),
    clientId: metadata.clientId,
    clientName: metadata.clientName,
    redirectUris,
    ...capabilities,
    ...(capabilities.tokenEndpointAuthMethods.includes('private_key_jwt') ? { clientAssertionKeys } : {}),
  };
}

function readStreamChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal
): Promise<ReadableStreamReadResult<Uint8Array>> {
  if (signal.aborted) return Promise.reject(new DOMException('Aborted', 'AbortError'));

  return new Promise((resolve, reject) => {
    const abort = () => {
      void reader.cancel().catch(() => undefined);
      reject(new DOMException('Aborted', 'AbortError'));
    };
    signal.addEventListener('abort', abort, { once: true });
    reader
      .read()
      .then(resolve, reject)
      .finally(() => signal.removeEventListener('abort', abort));
  });
}

async function readJsonWithSizeLimit(
  response: Response,
  maxBytes: number,
  signal: AbortSignal
): Promise<{ value: unknown; bytes: Uint8Array }> {
  const contentLength = response.headers.get('Content-Length');
  if (contentLength !== null) {
    const declaredSize = Number(contentLength);
    if (Number.isFinite(declaredSize) && declaredSize > maxBytes) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error(`Client metadata exceeds size limit: ${contentLength} bytes (max ${maxBytes})`);
    }
  }

  const reader = response.body?.getReader();
  if (!reader) throw new Error('Client metadata response body is empty');

  const chunks: Uint8Array[] = [];
  let totalSize = 0;

  while (true) {
    const { done, value } = await readStreamChunk(reader, signal);
    if (done) break;
    if (!value) continue;

    totalSize += value.length;
    if (totalSize > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new Error(`Response exceeded size limit of ${maxBytes} bytes`);
    }
    chunks.push(value);
  }

  if (signal.aborted) throw new DOMException('Aborted', 'AbortError');

  const bytes = new Uint8Array(totalSize);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }

  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw new Error('Client metadata response is not valid UTF-8');
  }

  try {
    return { value: JSON.parse(text), bytes };
  } catch {
    throw new Error('Client metadata response is not valid JSON');
  }
}

function fetchCimdOrigin(metadataUrl: string, signal: AbortSignal): Promise<Response> {
  return fetch(metadataUrl, {
    headers: { Accept: 'application/json', 'Cache-Control': 'no-store', 'User-Agent': OUTBOUND_USER_AGENT },
    signal,
    cache: 'no-store',
  });
}

async function openCimdCache(): Promise<Cache | undefined> {
  if (typeof caches === 'undefined') return undefined;
  try {
    return await caches.open(CIMD_CACHE_NAME);
  } catch {
    return undefined;
  }
}

/**
 * Shared-cache lifetime derived from the origin's Cache-Control directives,
 * bounded by the server-side cap the CIMD draft permits (§5.2 "MAY define its
 * own upper and/or lower bounds on an acceptable cache lifetime"). Returns
 * undefined when the response must not be stored.
 */
function cacheTtlSeconds(response: Response): number | undefined {
  const cacheControl = response.headers.get('Cache-Control');
  if (cacheControl === null || /(?:^|,)\s*(?:no-cache|no-store|private)\b/i.test(cacheControl)) return undefined;

  const directive =
    /(?:^|,)\s*s-maxage\s*=\s*"?(\d+)/i.exec(cacheControl) ?? /(?:^|,)\s*max-age\s*=\s*"?(\d+)/i.exec(cacheControl);
  if (!directive) return undefined;

  const ttl = Math.min(Number(directive[1]), CIMD_CACHE_MAX_TTL_SECONDS);
  return ttl > 0 ? ttl : undefined;
}

async function cacheValidatedDocument(
  cache: Cache | undefined,
  metadataUrl: string,
  response: Response,
  bytes: Uint8Array
): Promise<void> {
  if (!cache) return;
  const ttl = cacheTtlSeconds(response);
  if (ttl === undefined) return;

  const headers = new Headers({ 'Cache-Control': `public, max-age=${ttl}` });
  for (const name of ['Content-Type', 'ETag', 'Last-Modified']) {
    const value = response.headers.get(name);
    if (value !== null) headers.set(name, value);
  }

  try {
    await cache.put(metadataUrl, new Response(bytes, { status: 200, headers }));
  } catch {
    // Caching is an optimization; a cache write failure must not fail OAuth.
  }
}

/**
 * Resolves a previously validated cache entry. A stored document that stops
 * validating (changed server capabilities, stricter rules after an upgrade)
 * is evicted so the caller re-resolves from origin in the same request;
 * timeout aborts propagate instead.
 */
async function tryResolveFromCache(
  cache: Cache | undefined,
  metadataUrl: string,
  server: OAuthServerCapabilities,
  signal: AbortSignal
): Promise<ResolvedClientIdMetadataDocument | undefined> {
  let cached: Response | undefined;
  try {
    cached = await cache?.match(metadataUrl);
  } catch {
    return undefined;
  }
  if (!cached) return undefined;

  try {
    const { value } = await readJsonWithSizeLimit(cached, CIMD_MAX_SIZE_BYTES, signal);
    return resolveClientIdMetadataDocument(metadataUrl, value, server);
  } catch (error) {
    if (signal.aborted) throw error;
    try {
      await cache?.delete(metadataUrl);
    } catch {
      // Ignore cleanup failures; the caller's origin fetch is authoritative.
    }
    return undefined;
  }
}

/**
 * Fetches, bounds, parses, validates, and negotiates a Client ID Metadata
 * Document into the single effective client configuration used by OAuth flows.
 */
export async function fetchClientIdMetadataDocument(
  metadataUrl: string,
  server: OAuthServerCapabilities
): Promise<ResolvedClientIdMetadataDocument> {
  validateClientIdentifierUrl(metadataUrl);

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), CIMD_FETCH_TIMEOUT_MS);

  try {
    const cache = await openCimdCache();
    const cachedDocument = await tryResolveFromCache(cache, metadataUrl, server, abortController.signal);
    if (cachedDocument) return cachedDocument;

    const response = await fetchCimdOrigin(metadataUrl, abortController.signal);
    if (!response.ok) {
      throw new Error(`Failed to fetch client metadata: HTTP ${response.status}`);
    }

    const { value, bytes } = await readJsonWithSizeLimit(response, CIMD_MAX_SIZE_BYTES, abortController.signal);
    const resolved = resolveClientIdMetadataDocument(metadataUrl, value, server);
    clearTimeout(timeoutId);
    await cacheValidatedDocument(cache, metadataUrl, response, bytes);
    return resolved;
  } catch (error) {
    if (abortController.signal.aborted) {
      throw new Error(`Client metadata fetch timed out after ${CIMD_FETCH_TIMEOUT_MS}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}
