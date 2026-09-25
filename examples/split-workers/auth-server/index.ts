import { AuthorizationError, OAuthAuthorizationServer, type AuthRequest } from '@cloudflare/workers-oauth-provider';
import { WorkerEntrypoint } from 'cloudflare:workers';

interface Env {
  OAUTH_KV: KVNamespace;
}

// Everything this server can grant, across all its resources. Resources advertise their own,
// smaller, up-front baseline; this is the catalogue.
const SCOPES = ['mcp:read', 'mcp:write', 'offline_access'];

const authorizationServer = new OAuthAuthorizationServer<Env>({
  issuer: 'https://auth.example.com',
  resources: ['https://mcp.example.com/mcp'],
  // The token endpoint is served at /oauth/token and /authorize is advertised, both by default.
  scopesSupported: SCOPES,

  // Preferred for clients with no pre-existing relationship.
  // Also requires global_fetch_strictly_public in wrangler.jsonc.
  clientIdMetadataDocumentEnabled: true,

  // Optional compatibility fallback. MCP 2026 deprecates DCR for new clients.
  clientRegistrationEndpoint: '/oauth/register',
});

async function authorize(request: Request, env: Env): Promise<Response> {
  const oauth = authorizationServer.getOAuthApi(env);

  // Parses the OAuth parameters and validates the client, redirect URI,
  // response type, resource indicator, and PKCE.
  let oauthRequest: AuthRequest;
  try {
    oauthRequest = await oauth.parseAuthRequest(request);
  } catch (error) {
    if (!(error instanceof AuthorizationError)) throw error;
    // redirectTo is set only once the client and redirect URI are validated; otherwise render locally.
    if (error.redirectTo) return Response.redirect(error.redirectTo, 302);
    return new Response(error.description, { status: 400 });
  }

  const client = await oauth.lookupClient(oauthRequest.clientId);
  if (!client) return new Response('Unknown OAuth client', { status: 400 });

  // TODO: replace with your own logic to sign the user in and ask for their consent.
  const user = { id: 'user-123', displayName: 'Ada' };
  const { redirectTo } = await oauth.completeAuthorization({
    request: oauthRequest,
    userId: user.id,
    metadata: { clientName: client.clientName },
    // Grant what was asked for, within the catalogue. (Or less: the user may decline some.)
    scope: oauthRequest.scope.filter((scope) => SCOPES.includes(scope)),
    props: { userId: user.id, displayName: user.displayName },
  });
  return Response.redirect(redirectTo, 302);
}

export default class AuthServer extends WorkerEntrypoint<Env> {
  // Your /authorize page; everything else (discovery, token, revocation, registration) is the library's.
  fetch(request: Request) {
    if (new URL(request.url).pathname === '/authorize') return authorize(request, this.env);
    return authorizationServer.fetch(request, this.env, this.ctx);
  }

  // Called by resource Workers over their Service Binding.
  validateToken(resource: string, token: string) {
    return authorizationServer.validateToken(resource, token, this.env);
  }
}
