import {
  AuthorizationError,
  OAuthAuthorizationServer,
  type AuthRequest,
  type JwtKey,
} from '@cloudflare/workers-oauth-provider';

interface Env {
  OAUTH_KV: KVNamespace;
  /** The current ES256 private JWK. Create one with `generate-signing-key.mjs`. */
  JWT_SIGNING_KEY: string;
  /** Optional JSON array of public JWKs published beside it while you rotate keys. */
  JWT_ADDITIONAL_KEYS?: string;
}

/** What `completeAuthorization()` stores with the grant. Encrypted at rest, never sent to the client. */
interface Props {
  userId: string;
  displayName: string;
  plan: 'free' | 'pro';
}

const authorizationServer = new OAuthAuthorizationServer<Env>({
  issuer: 'https://auth.example.com',
  resources: ['https://mcp.example.com/mcp'],
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  clientRegistrationEndpoint: '/oauth/register',
  scopesSupported: ['mcp:read'],

  // Resource servers validate JWTs offline and don't see revocation until the token expires,
  // so keep access tokens short-lived. Refresh tokens do the long-lived work.
  accessTokenTTL: 5 * 60,

  accessTokens: {
    // Switching a deployment that issued opaque tokens? Issue 'opaque' with jwt configured first,
    // so resource servers load the keys before any JWT exists. See docs/jwt-access-tokens.md.
    issuing: 'jwt',
    jwt: {
      // Resolved per request, so rotating a key is a secret change, not a deploy.
      keys: (env) => ({
        current: JSON.parse(env.JWT_SIGNING_KEY) as JwtKey,
        additional: env.JWT_ADDITIONAL_KEYS ? (JSON.parse(env.JWT_ADDITIONAL_KEYS) as JwtKey[]) : [],
      }),
      // Copy what resource servers need into the token. Signed, not encrypted: never add secrets.
      claims: ({ props }) => ({ plan: (props as Props).plan }),
    },
  },
});

async function authorize(request: Request, env: Env): Promise<Response> {
  const oauth = authorizationServer.getOAuthApi(env);

  let oauthRequest: AuthRequest;
  try {
    oauthRequest = await oauth.parseAuthRequest(request);
  } catch (error) {
    if (!(error instanceof AuthorizationError)) throw error;
    if (error.redirectTo) return Response.redirect(error.redirectTo, 302);
    return new Response(error.description, { status: 400 });
  }

  // TODO: replace with your own logic to sign the user in and ask for their consent.
  const props: Props = { userId: 'user-123', displayName: 'Ada', plan: 'pro' };
  const { redirectTo } = await oauth.completeAuthorization({
    request: oauthRequest,
    userId: props.userId,
    metadata: {},
    scope: oauthRequest.scope.filter((scope) => scope === 'mcp:read'),
    props,
  });
  return Response.redirect(redirectTo, 302);
}

export default {
  // Your /authorize page. Everything else is the library's: discovery, token, revocation,
  // registration, and the JWKS at /.well-known/jwks.json.
  fetch(request, env, ctx) {
    if (new URL(request.url).pathname === '/authorize') return authorize(request, env);
    return authorizationServer.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
