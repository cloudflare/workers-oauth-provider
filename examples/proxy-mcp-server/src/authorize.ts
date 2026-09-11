import {
  AuthorizationError,
  CimdFetchError,
  type AuthRequest,
  type OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { SCOPES_SUPPORTED, type Env, type McpProps } from './config';
import { renderLoginPage } from './login-page';

/**
 * The `defaultHandler`: every request the provider does not serve itself. Here that is
 * the interactive authorization endpoint, plus a 404 for anything else.
 */
export const authorizeHandler: ExportedHandler<Env> = {
  fetch(request, env) {
    if (new URL(request.url).pathname !== '/authorize') {
      return new Response('Not found', { status: 404 });
    }
    // The provider injects its own API into `env` under the `OAUTH_PROVIDER` binding.
    return handleAuthorize(request, env.OAUTH_PROVIDER);
  },
};

/**
 * The interactive authorization endpoint: the one route an OAuth authorization server
 * cannot implement for an application, because only the application knows who the user
 * is and what they agreed to.
 */
async function handleAuthorize(request: Request, oauth: OAuthHelpers<McpProps>): Promise<Response> {
  const url = new URL(request.url);
  if (request.method !== 'GET' && request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, POST' } });
  }

  let authRequest: AuthRequest;
  try {
    authRequest = await oauth.parseAuthRequest(request);
  } catch (error) {
    return renderAuthorizationFailure(error);
  }

  // The consent screen and the grant must describe the same thing, so both are built
  // from the filtered list rather than from what the client asked for.
  const scope = grantableScopes(authRequest.scope);
  const client = await oauth.lookupClient(authRequest.clientId);
  const clientName = client?.clientName ?? authRequest.clientId;

  if (request.method === 'GET') {
    return renderLoginPage(url, clientName, scope, authRequest.resource ?? '');
  }

  const form = await request.formData();
  if (form.get('action') !== 'approve') {
    // A denial is a normal OAuth outcome, not an error page: report it on the client's
    // redirect URI so the client stops waiting.
    return redirectToClient(authRequest, { error: 'access_denied', error_description: 'The user denied the request' });
  }

  // PLACEHOLDER AUTHENTICATION. Production code must establish who the user is before
  // this point. See "Before production" in the README.
  const userId = String(form.get('username') ?? '').trim() || 'demo';

  const { redirectTo } = await oauth.completeAuthorization({
    request: authRequest,
    userId,
    metadata: { clientName },
    scope,
    // Props are encrypted and stored on the grant, then handed back to the protected
    // handler as `ctx.props`. The granted scope is copied in because this configuration
    // exposes no other view of what the token carries.
    props: { userId, clientId: authRequest.clientId, scopes: scope } satisfies McpProps,
  });

  return Response.redirect(redirectTo, 302);
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
