import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AuthorizationError,
  OAuthAuthorizationServer,
  type AuthRequest,
  type OAuthHelpers,
} from '../src/oauth-provider';
import { createMockEnv, type TestEnv } from './test-helpers';

const ISSUER = 'https://auth.example.com';
const RESOURCE = 'https://mcp.example.com/mcp';
const REDIRECT_URI = 'https://client.example/callback';
const SECRET = 'a-consent-cookie-secret-of-32-chars!';

/** A browser's cookie jar: applies Set-Cookie headers and sends the survivors back. */
class Browser {
  #cookies = new Map<string, string>();

  receive(headers: Headers): void {
    for (const cookie of headers.getSetCookie()) {
      const [pair, ...attributes] = cookie.split(';').map((part) => part.trim());
      const separator = pair.indexOf('=');
      const name = pair.slice(0, separator);
      if (attributes.includes('Max-Age=0')) this.#cookies.delete(name);
      else this.#cookies.set(name, pair.slice(separator + 1));
    }
  }

  request(url: string): Request {
    const cookie = [...this.#cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    return new Request(url, cookie ? { headers: { Cookie: cookie } } : {});
  }
}

let env: TestEnv;
let oauth: OAuthHelpers;

function createServer(overrides: { cookiePrefix?: string } = {}) {
  return new OAuthAuthorizationServer<TestEnv>({
    issuer: ISSUER,
    resources: [RESOURCE],
    authorizeEndpoint: '/authorize',
    tokenEndpoint: '/oauth/token',
    scopesSupported: ['read', 'write'],
    ...overrides,
  });
}

async function parsedRequest(scope = 'read write', clientId?: string): Promise<AuthRequest> {
  const id =
    clientId ?? (await oauth.createClient({ redirectUris: [REDIRECT_URI], tokenEndpointAuthMethod: 'none' })).clientId;
  const url = new URL(`${ISSUER}/authorize`);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: id,
    redirect_uri: REDIRECT_URI,
    scope,
    state: 'client-state',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
    resource: RESOURCE,
  }).toString();
  return oauth.parseAuthRequest(new Request(url));
}

/** Every rejection is an AuthorizationError without a redirect: rendered locally, never redirected. */
async function expectLocalRejection(promise: Promise<unknown>, code: string, description: RegExp) {
  const error = await promise.then(
    () => undefined,
    (thrown: unknown) => thrown
  );
  expect(error).toBeInstanceOf(AuthorizationError);
  expect(error).toMatchObject({ code, redirectUri: undefined });
  expect((error as AuthorizationError).description).toMatch(description);
}

beforeEach(() => {
  env = createMockEnv();
  oauth = createServer().getOAuthApi(env);
});
afterEach(() => {
  env.OAUTH_KV.clear();
  vi.restoreAllMocks();
});

describe('consent transactions', () => {
  it('binds each consent page to the browser that opened it, once, for ten minutes', async () => {
    const request = await parsedRequest();
    const browser = new Browser();
    const consent = await oauth.beginConsent(request);

    // MCP best practices: __Host- cookie, CSRF protection, and no framing of the consent page.
    const [cookie] = consent.headers.getSetCookie();
    expect(cookie).toMatch(/^__Host-oauth-consent=[0-9a-f]{64}; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$/);
    expect(consent.headers.get('Content-Security-Policy')).toBe("frame-ancestors 'none'");
    expect(consent.headers.get('X-Frame-Options')).toBe('DENY');
    expect(consent.headers.get('Cache-Control')).toBe('no-store');

    // KV holds the handle's hash, never the handle.
    const { keys } = await env.OAUTH_KV.list({ prefix: 'transaction:' });
    expect(keys.map((key) => key.name)).toEqual([expect.stringMatching(/^transaction:[0-9a-f]{64}$/)]);
    expect(keys[0].name).not.toContain(consent.handle);

    // A forged form post from another site has the handle but not the cookie.
    await expectLocalRejection(
      oauth.approveConsent(new Browser().request(`${ISSUER}/authorize`), consent.handle),
      'invalid_request',
      /not started in this browser/
    );
    // Another browser's own cookie doesn't fit this handle.
    const attacker = new Browser();
    attacker.receive((await oauth.beginConsent(request)).headers);
    await expectLocalRejection(
      oauth.approveConsent(attacker.request(`${ISSUER}/authorize`), consent.handle),
      'invalid_request',
      /different browser session/
    );

    browser.receive(consent.headers);
    const approved = await oauth.approveConsent(browser.request(`${ISSUER}/authorize`), consent.handle);
    expect(approved.request).toEqual(request);
    // The binding cookie is cleared, and nothing is remembered unless the caller asks.
    expect(approved.headers.getSetCookie()).toEqual([
      '__Host-oauth-consent=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0',
    ]);

    // Single use: replaying the post is refused even with the cookie still present.
    const replay = new Browser();
    replay.receive(consent.headers);
    await expectLocalRejection(
      oauth.approveConsent(replay.request(`${ISSUER}/authorize`), consent.handle),
      'invalid_request',
      /expired or was already used/
    );

    // Expiry: an abandoned page stops working after ten minutes.
    const stale = await oauth.beginConsent(request);
    const staleBrowser = new Browser();
    staleBrowser.receive(stale.headers);
    env.OAUTH_KV.advanceTime(601 * 1000);
    await expectLocalRejection(
      oauth.approveConsent(staleBrowser.request(`${ISSUER}/authorize`), stale.handle),
      'invalid_request',
      /expired or was already used/
    );
  });

  it('narrows the approval to a subset of the requested scopes, never beyond them', async () => {
    const request = await parsedRequest('read write');
    const approve = async (scope: string[]) => {
      const consent = await oauth.beginConsent(request);
      const browser = new Browser();
      browser.receive(consent.headers);
      return oauth.approveConsent(browser.request(`${ISSUER}/authorize`), consent.handle, { scope });
    };

    expect((await approve(['read'])).request.scope).toEqual(['read']);
    // The checkboxes are the user's to edit; a scope nobody requested is refused.
    await expectLocalRejection(approve(['read', 'admin']), 'invalid_scope', /subset of those requested/);
  });

  it('remembers an approval only when the call asks, for the same client, redirect URI and resource, and a subset of scopes', async () => {
    const request = await parsedRequest('read write');
    const browser = new Browser();
    const consent = await oauth.beginConsent(request);
    browser.receive(consent.headers);

    // Remembering is chosen per call; the default is to ask every time.
    expect(await oauth.isConsentRemembered(browser.request(`${ISSUER}/authorize`), request, { secret: SECRET })).toBe(
      false
    );
    const approved = await oauth.approveConsent(browser.request(`${ISSUER}/authorize`), consent.handle, {
      remember: { secret: SECRET },
    });
    const approvals = approved.headers.getSetCookie().find((cookie) => cookie.startsWith('__Host-oauth-approvals='))!;
    expect(approvals).toMatch(/; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000$/);
    browser.receive(approved.headers);

    const remembered = (authRequest: AuthRequest, secret = SECRET, from = browser) =>
      oauth.isConsentRemembered(from.request(`${ISSUER}/authorize`), authRequest, { secret });

    expect(await remembered(request)).toBe(true);
    expect(await remembered({ ...request, scope: ['read'] })).toBe(true);
    // Asking for more than was approved brings the consent page back.
    expect(await remembered({ ...request, scope: ['read', 'write', 'admin'] })).toBe(false);
    // Bound to the client, where its tokens go, and the resource.
    expect(await remembered(await parsedRequest('read'))).toBe(false);
    expect(await remembered({ ...request, redirectUri: 'https://client.example/other' })).toBe(false);
    expect(await remembered({ ...request, resource: 'https://other.example.com/mcp' })).toBe(false);
    // Signed: another secret, or an edited cookie, remembers nothing.
    expect(await remembered(request, 'another-secret-that-is-32-chars-long!')).toBe(false);
    const forged = new Browser();
    const [payload, signature] = approvals.split(';')[0].split('=')[1].split('.');
    const edited = btoa(atob(payload.replace(/-/g, '+').replace(/_/g, '/')).replace('"read"', '"admin"'))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    forged.receive(new Headers({ 'Set-Cookie': `__Host-oauth-approvals=${edited}.${signature}; Path=/` }));
    expect(await remembered({ ...request, scope: ['admin'] }, SECRET, forged)).toBe(false);

    // Remembered approvals expire.
    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 2592001 * 1000);
    expect(await remembered(request)).toBe(false);
  });

  it('rejects a remember secret too short to sign with', async () => {
    const request = await parsedRequest();
    await expect(oauth.isConsentRemembered(new Request(ISSUER), request, { secret: 'short' })).rejects.toThrow(
      /at least 32 characters/
    );
    const consent = await oauth.beginConsent(request);
    const browser = new Browser();
    browser.receive(consent.headers);
    await expect(
      oauth.approveConsent(browser.request(ISSUER), consent.handle, { remember: { secret: SECRET, maxAgeSeconds: 0 } })
    ).rejects.toThrow(/positive integer/);
  });
});

describe('upstream transactions', () => {
  it('carries the approved request and data across the third-party redirect, once, in the browser that started it', async () => {
    const request = await parsedRequest('read');
    const browser = new Browser();

    // Consent approved, then state is created only now and its cookie rides on the same redirect.
    const consent = await oauth.beginConsent(request);
    browser.receive(consent.headers);
    const approved = await oauth.approveConsent(browser.request(`${ISSUER}/authorize`), consent.handle);
    const upstream = await oauth.beginUpstream(approved.request, {
      data: { codeVerifier: 'upstream-pkce-verifier' },
      headers: approved.headers,
    });
    expect(upstream.headers).toBe(approved.headers);
    expect(upstream.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(upstream.headers.getSetCookie()).toEqual([
      '__Host-oauth-consent=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0',
      expect.stringMatching(
        /^__Host-oauth-upstream=[0-9a-f]{64}; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$/
      ),
    ]);
    browser.receive(upstream.headers);

    const callback = (state: string | null, from = browser) =>
      from.request(`${ISSUER}/callback?code=upstream-code${state === null ? '' : `&state=${state}`}`);

    await expectLocalRejection(oauth.finishUpstream(callback(null)), 'invalid_request', /Missing state/);
    // A callback replayed into another browser, e.g. a stolen upstream code.
    await expectLocalRejection(
      oauth.finishUpstream(callback(upstream.state, new Browser())),
      'invalid_request',
      /not started in this browser/
    );

    const resumed = await oauth.finishUpstream<{ codeVerifier: string }>(callback(upstream.state));
    expect(resumed.request).toEqual(approved.request);
    expect(resumed.data).toEqual({ codeVerifier: 'upstream-pkce-verifier' });
    expect(resumed.headers.getSetCookie()).toEqual([
      '__Host-oauth-upstream=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0',
    ]);

    const replay = new Browser();
    replay.receive(upstream.headers);
    await expectLocalRejection(
      oauth.finishUpstream(callback(upstream.state, replay)),
      'invalid_request',
      /expired or was already used/
    );

    // The recovered request completes the authorization as if it had never left.
    const { redirectTo } = await oauth.completeAuthorization({
      request: resumed.request,
      userId: 'user-1',
      metadata: {},
      scope: resumed.request.scope,
      props: { upstream: 'tokens' },
    });
    const redirect = new URL(redirectTo);
    expect(redirect.origin + redirect.pathname).toBe(REDIRECT_URI);
    expect(redirect.searchParams.get('state')).toBe('client-state');
    expect(redirect.searchParams.get('code')).toBeTruthy();
  });

  it('keeps a consent handle and an upstream state from standing in for each other', async () => {
    const request = await parsedRequest();
    const browser = new Browser();
    const consent = await oauth.beginConsent(request);
    browser.receive(consent.headers);
    // The consent cookie names the consent transaction, not an upstream one.
    await expectLocalRejection(
      oauth.finishUpstream(browser.request(`${ISSUER}/callback?state=${consent.handle}`)),
      'invalid_request',
      /not started in this browser/
    );
  });
});

describe('cookiePrefix', () => {
  it('renames every cookie and must keep the __Host- guarantees', async () => {
    oauth = createServer({ cookiePrefix: '__Host-mcp-' }).getOAuthApi(env);
    const request = await parsedRequest();
    const consent = await oauth.beginConsent(request);
    const upstream = await oauth.beginUpstream(request);
    expect(consent.headers.getSetCookie()[0]).toMatch(/^__Host-mcp-consent=/);
    expect(upstream.headers.getSetCookie()[0]).toMatch(/^__Host-mcp-upstream=/);

    expect(() => createServer({ cookiePrefix: 'mcp-' })).toThrow(/must start with "__Host-"/);
    expect(() => createServer({ cookiePrefix: '__Host-bad name ' })).toThrow(/cookie-name characters/);
  });
});
