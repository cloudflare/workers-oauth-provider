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
    scopes_supported: ['mcp:read'],
    resource_name: 'Example MCP server',
  },
  validateToken: (env) => env.AUTH_SERVER.validateToken,
  handler: {
    fetch(request, env, ctx) {
      // ctx.props: what completeAuthorization() stored. ctx.auth: the verified token (scope, userId, clientId, …).
      // Authorization is the handler's: a token without the scope gets the MCP 403 challenge.
      if (!ctx.auth.scope.includes('mcp:read')) return insufficientScope(ctx.auth, ['mcp:read']);
      return Response.json({ userId: ctx.props.userId, scope: ctx.auth.scope });
    },
  },
});
