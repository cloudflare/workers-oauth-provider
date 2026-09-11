import {
  AuthorizationError,
  CimdFetchError,
  type AuthRequest,
  type OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { SCOPES_SUPPORTED, type GrantProps } from '../../shared/config';
import { renderLoginPage } from './login-page';

/**
 * The interactive authorization endpoint: the one route an OAuth authorization server
 * cannot implement for an application, because only the application knows who the user
 * is and what they agreed to.
 */
export async function handleAuthorize(request: Request, oauth: OAuthHelpers<GrantProps>): Promise<Response> {
  const url = new URL(request.url);
  if (request.method !== 'GET' && request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, POST' } });
  }

  // PLACEHOLDER AUTHENTICATION, part one. This endpoint believes whatever username the
  // form sends, so it refuses to run anywhere but on a loopback host: deploying the example
  // unchanged cannot mint grants for arbitrary users. Replace the placeholder before
  // deploying; see "Before production" in the README.
  if (!isLoopbackHost(url.hostname)) {
    return new Response('The placeholder login only runs on localhost. Replace it before deploying.', {
      status: 501,
    });
  }

  let authRequest: AuthRequest;
  let clientName: string;
  try {
    authRequest = await oauth.parseAuthRequest(request);
    // Only the display name is needed from the client record. For a CIMD client this can
    // fetch the metadata document again, so it stays inside the same failure handling.
    const client = await oauth.lookupClient(authRequest.clientId);
    clientName = client?.clientName ?? authRequest.clientId;
  } catch (error) {
    return renderAuthorizationFailure(error);
  }

  // The consent screen and the grant must describe the same thing, so both are built
  // from the filtered list rather than from what the client asked for.
  const scope = grantableScopes(authRequest.scope);

  if (request.method === 'GET') {
    return renderLoginPage(url, clientName, scope, authRequest.resource ?? '');
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    // Client-controlled malformed input is a 400, not a Worker error.
    return new Response('Malformed form submission', { status: 400 });
  }
  if (form.get('action') !== 'approve') {
    // A denial is a normal OAuth outcome, not an error page: report it on the client's
    // redirect URI so the client stops waiting.
    return redirectToClient(authRequest, { error: 'access_denied', error_description: 'The user denied the request' });
  }

  // PLACEHOLDER AUTHENTICATION, part two. Production code must establish who the user is
  // before this point; the loopback guard above is all that stops this from running there.
  const userId = String(form.get('username') ?? '').trim() || 'demo';

  // completeAuthorization() looks the client up once more before writing the grant, so a
  // CIMD client's metadata fetch can fail here too; it gets the same controlled failure.
  try {
    const { redirectTo } = await oauth.completeAuthorization({
      request: authRequest,
      userId,
      metadata: { clientName },
      scope,
      // Props are encrypted and stored on the grant. The granted scope is deliberately not
      // copied in: the resource server reads the effective token scope instead, which a
      // client can narrow below this grant at the token endpoint.
      props: { userId, clientId: authRequest.clientId } satisfies GrantProps,
    });
    return Response.redirect(redirectTo, 302);
  } catch (error) {
    return renderAuthorizationFailure(error);
  }
}

/**
 * RFC 6749 section 3.3 lets the authorization server grant less than was requested. The
 * provider advertises `scopesSupported` but never enforces it, so an unfiltered
 * `authRequest.scope` would mint a token carrying scopes this server never offered. A
 * real deployment decides per user and per client; dropping the unadvertised ones is the
 * floor, not a policy.
 */
function grantableScopes(requested: string[]): string[] {
  return requested.filter((scope) => SCOPES_SUPPORTED.includes(scope));
}

/**
 * `parseAuthRequest()` rejects a bad request in two ways, and a failure to fetch a client
 * ID metadata document is a third. Without a validated `redirectUri` the error has to be
 * rendered locally, because redirecting an unvalidated URI is an open redirect.
 */
function renderAuthorizationFailure(error: unknown): Response {
  if (error instanceof CimdFetchError) {
    return new Response('The client ID metadata document could not be fetched', { status: 400 });
  }
  if (!(error instanceof AuthorizationError)) throw error;
  if (!error.redirectUri) {
    return new Response(error.description, { status: 400 });
  }
  const redirect = new URL(error.redirectUri);
  redirect.searchParams.set('error', error.code);
  redirect.searchParams.set('error_description', error.description);
  if (error.state) redirect.searchParams.set('state', error.state);
  // RFC 9207: the client must be able to tell which server answered.
  if (error.issuer) redirect.searchParams.set('iss', error.issuer);
  return Response.redirect(redirect.toString(), 302);
}

function redirectToClient(authRequest: AuthRequest, params: Record<string, string>): Response {
  const redirect = new URL(authRequest.redirectUri);
  for (const [name, value] of Object.entries(params)) redirect.searchParams.set(name, value);
  if (authRequest.state) redirect.searchParams.set('state', authRequest.state);
  if (authRequest.issuer) redirect.searchParams.set('iss', authRequest.issuer);
  return Response.redirect(redirect.toString(), 302);
}

/** `localhost`, `127.0.0.0/8`, or `::1`: the hosts `wrangler dev` serves. */
function isLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || /^127(\.\d{1,3}){3}$/.test(host);
}
