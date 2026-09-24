/**
 * Consent and upstream-state primitives for authorization servers that sign users in through a
 * third-party OAuth provider (an MCP "proxy" server). They implement the protections the MCP
 * 2026-07-28 security best practices require under Confused Deputy → Mitigation:
 *
 * - consent per client before any redirect to the third party, with CSRF protection and anti-framing
 *   headers on the consent page;
 * - remembered consent, chosen per call, in a signed `__Host-` cookie bound to the client, its redirect
 *   URI and resource (and the user, when the caller knows them), reused only for a subset of the
 *   approved scopes;
 * - the approved scopes chosen on the consent page, from any the server supports;
 * - a random `state` stored server-side only after consent, bound to the browser by a `__Host-` cookie,
 *   single-use and short-lived.
 *
 * A transaction handle is 256 random bits. KV stores the record under the handle's SHA-256, encrypted
 * with a key derived from the handle, so KV alone reveals neither the request nor deployer data such as
 * a PKCE verifier. Each transaction has its own binding cookie, named after its hash and holding the
 * full hash, so several authorizations can be in flight in one browser (two tabs) without replacing each
 * other. Single use is `get` then `delete`, which KV cannot make atomic: two concurrent requests from the
 * same browser with the same handle could both pass; the cookie binding confines that to the browser
 * that started the transaction.
 */
import { AuthorizationError, isValidOAuthScopeToken } from './oauth-capabilities';
import type { AuthRequest } from './oauth-provider';

/** Remember an approval so the consent page can be skipped for requests it already covers. */
export interface RememberConsentOptions {
  /** HMAC key for the approvals cookie: at least 32 characters, from a Worker secret. */
  secret: string;
  /** How long an approval is remembered. Defaults to 30 days. */
  maxAgeSeconds?: number;
  /**
   * The signed-in user, when you know them before consent (your own sign-in). The approval is then
   * bound to them as well, so another account on the same browser is asked again. Without it an
   * approval belongs to the browser, which suits a proxy server that only learns the user from the
   * third party after consent.
   */
  subject?: string;
}

/** A consent page to render: post `handle` back to {@link approveConsent}; send `headers` with the page. */
export interface ConsentTransaction {
  handle: string;
  headers: Headers;
}

/** The approved authorization request, with the cookies to set on the next response. */
export interface ApprovedConsent {
  request: AuthRequest;
  headers: Headers;
}

/** Where to send the browser after the user declined, with the cookies to set on that redirect. */
export interface DeniedConsent {
  request: AuthRequest;
  /** The client's redirect URI with `error=access_denied`, its `state`, and `iss` (RFC 9207). */
  redirectTo: string;
  headers: Headers;
}

/** The `state` to send to the third-party provider, with the binding cookie to set on the redirect. */
export interface UpstreamTransaction {
  state: string;
  headers: Headers;
}

/** The authorization request and data saved by `beginUpstream()`, recovered at the callback. */
export interface ResumedUpstream<Data = unknown> {
  request: AuthRequest;
  data: Data;
  headers: Headers;
}

const TRANSACTION_TTL_SECONDS = 600;
/** Default for the provider's `cookiePrefix` option. */
export const DEFAULT_COOKIE_PREFIX = '__Host-oauth-';
const DEFAULT_REMEMBER_SECONDS = 30 * 24 * 60 * 60;
const MIN_SECRET_LENGTH = 32;
// Browsers cap a cookie near 4 KB; older approvals are dropped to stay under it.
const MAX_APPROVALS_COOKIE_BYTES = 3800;

type TransactionKind = 'consent' | 'upstream';
interface TransactionRecord {
  kind: TransactionKind;
  request: AuthRequest;
  data?: unknown;
}
/** A transaction whose binding and record checked out; `consume()` makes it single-use. */
interface OpenTransaction {
  record: TransactionRecord;
  cookieName: string;
  consume(): Promise<void>;
}
interface Approval {
  /** base64url SHA-256 of client ID, redirect URI and resource. */
  k: string;
  /** Approved scopes. */
  s: string[];
  /** Expiry, seconds since the epoch. */
  e: number;
}

/** Cookie names derived from the provider's `cookiePrefix`. */
export interface ConsentCookies {
  consent: string;
  upstream: string;
  approvals: string;
}

/** Throws a `TypeError` unless the prefix keeps the `__Host-` guarantees the MCP best practices require. */
export function consentCookies(prefix: string = DEFAULT_COOKIE_PREFIX): ConsentCookies {
  if (typeof prefix !== 'string' || !prefix.startsWith('__Host-') || !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(prefix)) {
    throw new TypeError('cookiePrefix must start with "__Host-" and contain only cookie-name characters');
  }
  return { consent: `${prefix}consent`, upstream: `${prefix}upstream`, approvals: `${prefix}approvals` };
}

function validateRememberConsentOptions(options: RememberConsentOptions): void {
  if (typeof options !== 'object' || options === null) {
    throw new TypeError('remember must be an object with a secret');
  }
  if (typeof options.secret !== 'string' || options.secret.length < MIN_SECRET_LENGTH) {
    throw new TypeError(`remember.secret must be a string of at least ${MIN_SECRET_LENGTH} characters`);
  }
  const maxAge = options.maxAgeSeconds;
  if (maxAge !== undefined && (!Number.isInteger(maxAge) || maxAge <= 0)) {
    throw new TypeError('remember.maxAgeSeconds must be a positive integer');
  }
  if (options.subject !== undefined && (typeof options.subject !== 'string' || options.subject.length === 0)) {
    throw new TypeError('remember.subject must be a non-empty string');
  }
}

/** Start a consent transaction for an authorization request that must be shown to the user. */
export async function beginConsent(
  kv: KVNamespace,
  cookies: ConsentCookies,
  request: AuthRequest
): Promise<ConsentTransaction> {
  const { handle, hash } = await createTransaction(kv, { kind: 'consent', request });
  const headers = new Headers({
    'Set-Cookie': bindingCookie(transactionCookieName(cookies.consent, hash), hash, TRANSACTION_TTL_SECONDS),
    'Cache-Control': 'no-store',
    // Clickjacking protection for the consent page (MUST).
    'Content-Security-Policy': "frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
  });
  return { handle, headers };
}

/**
 * Consume a consent transaction the user approved. `scope`, when given, replaces the requested
 * scopes: the page may narrow them or offer more, but each must be one the server supports
 * (`supportedScopes`, from `scopesSupported`). `remember` stores the approval in a signed cookie.
 */
export async function approveConsent(
  kv: KVNamespace,
  cookies: ConsentCookies,
  supportedScopes: readonly string[] | undefined,
  request: Request,
  handle: string,
  options: { scope?: string[]; remember?: RememberConsentOptions } = {}
): Promise<ApprovedConsent> {
  if (options.remember !== undefined) validateRememberConsentOptions(options.remember);
  const transaction = await openTransaction(kv, request, cookies.consent, handle, 'consent');
  let approved = transaction.record.request;
  if (options.scope !== undefined) {
    // The checkboxes are the user's to edit, so every value is checked against what the server
    // supports; with no scopesSupported configured, any well-formed scope is the page's call.
    const supported = supportedScopes ? new Set(supportedScopes) : undefined;
    const valid = (scope: unknown) =>
      typeof scope === 'string' && isValidOAuthScopeToken(scope) && (!supported || supported.has(scope));
    if (!Array.isArray(options.scope) || !options.scope.every(valid)) {
      throw new AuthorizationError('invalid_scope', {
        description: 'Approved scopes must be ones this server supports',
      });
    }
    approved = { ...approved, scope: [...new Set(options.scope)] };
  }
  // Consumed only once the submission is valid, so a corrected resubmission of the same page works.
  await transaction.consume();
  const headers = new Headers({ 'Cache-Control': 'no-store' });
  headers.append('Set-Cookie', clearCookie(transaction.cookieName));
  if (options.remember) {
    headers.append('Set-Cookie', await rememberApproval(cookies, request, approved, options.remember));
  }
  return { request: approved, headers };
}

/**
 * Consume a consent transaction the user declined, and build the OAuth error redirect back to the
 * client: `error=access_denied`, the client's `state`, and `iss`. The redirect URI comes from the
 * stored request, which `parseAuthRequest()` validated, never from the form.
 */
export async function denyConsent(
  kv: KVNamespace,
  cookies: ConsentCookies,
  request: Request,
  handle: string,
  options: { description?: string } = {}
): Promise<DeniedConsent> {
  const transaction = await openTransaction(kv, request, cookies.consent, handle, 'consent');
  await transaction.consume();
  const record = transaction.record;
  const redirect = new URL(record.request.redirectUri);
  redirect.searchParams.set('error', 'access_denied');
  if (options.description) redirect.searchParams.set('error_description', options.description);
  if (record.request.state) redirect.searchParams.set('state', record.request.state);
  if (record.request.issuer) redirect.searchParams.set('iss', record.request.issuer);
  const headers = new Headers({ 'Cache-Control': 'no-store', Location: redirect.href });
  headers.append('Set-Cookie', clearCookie(transaction.cookieName));
  return { request: record.request, redirectTo: redirect.href, headers };
}

/** Whether a remembered approval covers this request: same client, redirect URI and resource, subset of scopes. */
export async function isConsentRemembered(
  cookies: ConsentCookies,
  request: Request,
  authRequest: AuthRequest,
  remember: Pick<RememberConsentOptions, 'secret' | 'subject'>
): Promise<boolean> {
  validateRememberConsentOptions(remember);
  const approvals = await readApprovals(cookies, request, remember.secret);
  const key = await approvalKey(authRequest, remember.subject);
  const now = Math.floor(Date.now() / 1000);
  const approval = approvals.find((entry) => entry.k === key && entry.e > now);
  if (!approval) return false;
  const approvedScopes = new Set(approval.s);
  return authRequest.scope.every((scope) => approvedScopes.has(scope));
}

/**
 * Save an approved authorization request before redirecting to the third-party provider, and get
 * the `state` to send it. Call only after consent. Pass `headers` to add the binding cookie to
 * headers you are already sending, such as `approveConsent()`'s.
 */
export async function beginUpstream(
  kv: KVNamespace,
  cookies: ConsentCookies,
  request: AuthRequest,
  options: { data?: unknown; headers?: Headers } = {}
): Promise<UpstreamTransaction> {
  const { handle, hash } = await createTransaction(kv, { kind: 'upstream', request, data: options.data });
  const headers = options.headers ?? new Headers();
  headers.append(
    'Set-Cookie',
    bindingCookie(transactionCookieName(cookies.upstream, hash), hash, TRANSACTION_TTL_SECONDS)
  );
  headers.set('Cache-Control', 'no-store');
  return { state: handle, headers };
}

/** Recover the authorization request at the third-party provider's callback, from its `state` parameter. */
export async function finishUpstream<Data = unknown>(
  kv: KVNamespace,
  cookies: ConsentCookies,
  request: Request
): Promise<ResumedUpstream<Data>> {
  const state = new URL(request.url).searchParams.get('state');
  if (!state) {
    throw new AuthorizationError('invalid_request', { description: 'Missing state parameter' });
  }
  const transaction = await openTransaction(kv, request, cookies.upstream, state, 'upstream');
  await transaction.consume();
  const headers = new Headers({ 'Cache-Control': 'no-store' });
  headers.append('Set-Cookie', clearCookie(transaction.cookieName));
  return { request: transaction.record.request, data: transaction.record.data as Data, headers };
}

async function createTransaction(
  kv: KVNamespace,
  record: TransactionRecord
): Promise<{ handle: string; hash: string }> {
  const handle = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const hash = await sha256Hex(handle);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    await transactionKey(handle),
    new TextEncoder().encode(JSON.stringify(record))
  );
  await kv.put(`transaction:${hash}`, `${base64url(iv)}.${base64url(new Uint8Array(sealed))}`, {
    expirationTtl: TRANSACTION_TTL_SECONDS,
  });
  return { handle, hash };
}

async function openTransaction(
  kv: KVNamespace,
  request: Request,
  cookieBase: string,
  handle: string,
  kind: TransactionKind
): Promise<OpenTransaction> {
  if (typeof handle !== 'string' || handle.length === 0) {
    throw new AuthorizationError('invalid_request', { description: 'Missing transaction handle' });
  }
  const hash = await sha256Hex(handle);
  const cookieName = transactionCookieName(cookieBase, hash);
  const bound = readCookie(request, cookieName);
  if (!bound) {
    throw new AuthorizationError('invalid_request', {
      description: 'This authorization was not started in this browser; start again',
    });
  }
  if (!timingSafeEqual(hash, bound)) {
    throw new AuthorizationError('invalid_request', {
      description: 'This authorization belongs to a different browser session; start again',
    });
  }
  const key = `transaction:${hash}`;
  const expired = new AuthorizationError('invalid_request', {
    description: 'This authorization expired or was already used; start again',
  });
  const stored = await kv.get(key);
  if (!stored) throw expired;
  let record: TransactionRecord;
  try {
    const [iv, sealed] = stored.split('.');
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64url(iv) },
      await transactionKey(handle),
      fromBase64url(sealed)
    );
    record = JSON.parse(new TextDecoder().decode(plain));
  } catch {
    throw expired;
  }
  if (record.kind !== kind) throw expired;
  return { record, cookieName, consume: () => kv.delete(key) };
}

/** Only the holder of the handle can decrypt its record; KV keeps the hash, not the handle. */
async function transactionKey(handle: string): Promise<CryptoKey> {
  const material = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`oauth-transaction-key:${handle}`));
  return crypto.subtle.importKey('raw', material, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** One binding cookie per transaction, so concurrent authorizations in one browser don't collide. */
function transactionCookieName(base: string, hash: string): string {
  return `${base}-${hash.slice(0, 16)}`;
}

async function rememberApproval(
  cookies: ConsentCookies,
  request: Request,
  approved: AuthRequest,
  remember: RememberConsentOptions
): Promise<string> {
  const maxAge = remember.maxAgeSeconds ?? DEFAULT_REMEMBER_SECONDS;
  const now = Math.floor(Date.now() / 1000);
  const key = await approvalKey(approved, remember.subject);
  const approvals = (await readApprovals(cookies, request, remember.secret)).filter(
    (entry) => entry.e > now && entry.k !== key
  );
  approvals.push({ k: key, s: approved.scope, e: now + maxAge });
  let value = await signApprovals(approvals, remember.secret);
  while (value.length > MAX_APPROVALS_COOKIE_BYTES && approvals.length > 1) {
    approvals.shift();
    value = await signApprovals(approvals, remember.secret);
  }
  // The cookie lives as long as its longest-lived approval; each entry still expires on its own.
  const cookieMaxAge = Math.max(...approvals.map((entry) => entry.e)) - now;
  return `${cookies.approvals}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${cookieMaxAge}`;
}

async function readApprovals(cookies: ConsentCookies, request: Request, secret: string): Promise<Approval[]> {
  const value = readCookie(request, cookies.approvals);
  if (!value) return [];
  const [payload, signature] = value.split('.');
  if (!payload || !signature) return [];
  const key = await hmacKey(secret);
  let valid = false;
  try {
    valid = await crypto.subtle.verify('HMAC', key, fromBase64url(signature), new TextEncoder().encode(payload));
  } catch {
    return [];
  }
  if (!valid) return [];
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(fromBase64url(payload)));
    return Array.isArray(parsed) ? parsed.filter(isApproval) : [];
  } catch {
    return [];
  }
}

async function signApprovals(approvals: Approval[], secret: string): Promise<string> {
  const payload = base64url(new TextEncoder().encode(JSON.stringify(approvals)));
  const signature = await crypto.subtle.sign('HMAC', await hmacKey(secret), new TextEncoder().encode(payload));
  return `${payload}.${base64url(new Uint8Array(signature))}`;
}

function isApproval(value: unknown): value is Approval {
  if (!value || typeof value !== 'object') return false;
  const entry = value as Record<string, unknown>;
  return (
    typeof entry.k === 'string' &&
    typeof entry.e === 'number' &&
    Array.isArray(entry.s) &&
    entry.s.every((scope) => typeof scope === 'string')
  );
}

/** Approval is bound to the client, where its tokens go, which resource they are for, and the user if known. */
async function approvalKey(request: AuthRequest, subject: string | undefined): Promise<string> {
  const material = JSON.stringify([request.clientId, request.redirectUri, request.resource ?? null, subject ?? null]);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material));
  return base64url(new Uint8Array(digest));
}

function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

function bindingCookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearCookie(name: string): string {
  return `${name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
}

function readCookie(request: Request, name: string): string | undefined {
  const header = request.headers.get('Cookie');
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) continue;
    if (part.slice(0, separator).trim() === name) return part.slice(separator + 1).trim();
  }
  return undefined;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index++) difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return difference === 0;
}

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
