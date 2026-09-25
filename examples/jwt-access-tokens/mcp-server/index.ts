import {
  createJwtAccessTokenValidator,
  insufficientScope,
  OAuthResourceServer,
  type JwtAccessTokenClaims,
  type JwtKey,
} from '@cloudflare/workers-oauth-provider';

interface Env {
  /** A Service Binding to the auth server Worker, used only to fetch its public keys. */
  AUTH_SERVER: Fetcher;
}

/** What the handler sees as `ctx.props`, mapped from the verified token claims. */
interface AuthProps {
  userId: string;
  plan: 'free' | 'pro';
}

const AUTH_SERVER = 'https://auth.example.com';

// The auth server's public keys, fetched over the binding and cached for five minutes. Rotation
// publishes a new key before it signs anything, so a cache this short always has it in time.
let cachedKeys: { keys: JwtKey[]; expiresAt: number } | undefined;

async function authServerKeys(env: Env): Promise<JwtKey[]> {
  if (!cachedKeys || cachedKeys.expiresAt < Date.now()) {
    const response = await env.AUTH_SERVER.fetch(`${AUTH_SERVER}/.well-known/jwks.json`);
    if (!response.ok) throw new Error(`JWKS fetch failed with ${response.status}`);
    const { keys } = await response.json<{ keys: JwtKey[] }>();
    cachedKeys = { keys, expiresAt: Date.now() + 5 * 60 * 1000 };
  }
  return cachedKeys.keys;
}

export default new OAuthResourceServer<Env, AuthProps>({
  resourceMetadata: {
    resource: 'https://mcp.example.com/mcp',
    authorization_servers: [AUTH_SERVER],
    resource_name: 'Example MCP server',
  },
  // Needed for any access, so clients request it first. Advertised, not enforced: the handler checks it.
  requiredScopes: ['mcp:read'],

  // No call to the auth server per request: each token is verified locally against its keys.
  validateToken: createJwtAccessTokenValidator<Env, AuthProps>({
    issuer: AUTH_SERVER,
    keys: authServerKeys,
    // The claims are signed, but still check the shape of anything you added before using it.
    mapClaims: (claims: JwtAccessTokenClaims) =>
      claims.plan === 'free' || claims.plan === 'pro' ? { userId: claims.sub, plan: claims.plan } : null,
  }),

  handler: {
    fetch(request, env, ctx) {
      if (!ctx.auth.scope.includes('mcp:read')) return insufficientScope(ctx.auth, ['mcp:read']);
      return Response.json({ userId: ctx.props.userId, plan: ctx.props.plan });
    },
  },
});
