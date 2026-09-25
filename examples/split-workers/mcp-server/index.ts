import {
  OAuthResourceServer,
  insufficientScope,
  type AuthorizationServerBinding,
} from '@cloudflare/workers-oauth-provider';

interface AuthProps {
  userId: string;
  displayName: string;
}

interface Env {
  AUTH_SERVER: AuthorizationServerBinding<AuthProps>;
}

export default new OAuthResourceServer<Env, AuthProps>({
  resourceMetadata: {
    resource: 'https://mcp.example.com/mcp',
    authorization_servers: ['https://auth.example.com'],
    // What a client should request up front: the minimum for basic use (MCP). More comes by step-up.
    scopes_supported: ['mcp:read'],
    resource_name: 'Example MCP server',
  },
  validateToken: (env) => env.AUTH_SERVER.validateToken,
  handler: {
    fetch(request, env, ctx) {
      // ctx.props: what completeAuthorization() stored. ctx.auth: the verified token (scope, userId, clientId, …).
      // Authorization is the handler's. A token without the scope an operation needs gets the MCP 403
      // challenge naming every scope the operation needs, and the client re-authorizes for them (step-up).
      const needed = request.method === 'GET' ? ['mcp:read'] : ['mcp:read', 'mcp:write'];
      if (!needed.every((scope) => ctx.auth.scope.includes(scope))) return insufficientScope(ctx.auth, needed);
      return Response.json({ userId: ctx.props.userId, scope: ctx.auth.scope });
    },
  },
});
