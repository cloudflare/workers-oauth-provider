import { createOAuthResourceServer } from '@cloudflare/workers-oauth-provider';
// Type-only: the entrypoint class itself never ships in this Worker, only its shape.
import type { McpTokenValidator } from '../../authorization-server/src/index';
import { MCP_READ_SCOPE, SCOPES_SUPPORTED, type McpProps } from '../../shared/config';
import { handleMcpRequest } from './mcp';

/**
 * Canonical identifier of this resource, and the issuer that is allowed to mint tokens
 * for it. Both must be absolute HTTPS URLs and both are validated when the resource
 * server is built, which happens once at module scope, so wrangler's `define` map inlines
 * them per environment. They must match the authorization server's values byte for byte.
 */
declare const AUTH_ISSUER: string;
declare const MCP_RESOURCE: string;

export interface Env {
  /**
   * Private Service Binding to the authorization server's `McpTokenValidator`
   * entrypoint. `Service<T>` gives the RPC method the entrypoint's own types, so a change
   * to `validateToken()` on the other side becomes a type error here.
   */
  AUTHORIZATION_SERVER: Service<McpTokenValidator>;
}

/**
 * This Worker stores nothing: no KV, no clients, no tokens. It publishes its RFC 9728
 * metadata, challenges unauthenticated requests, and asks the authorization server
 * whether a presented token is live and issued for this resource.
 */
const resourceServer = createOAuthResourceServer<Env, McpProps>({
  resourceMetadata: {
    resource: MCP_RESOURCE,
    authorization_servers: [AUTH_ISSUER],
    scopes_supported: SCOPES_SUPPORTED,
    resource_name: 'Example MCP server',
  },

  async validateToken({ token, env }) {
    // The binding is pinned to this resource on the other side, so a token minted for
    // another audience cannot be validated here even if this Worker asked.
    const validated = await env.AUTHORIZATION_SERVER.validateToken(token);
    if (!validated) return null;
    return {
      audience: validated.audience,
      expiresAt: validated.expiresAt,
      // Only `props` reaches the handler, so copy in the effective token scope. It can be
      // narrower than the scope stored on the grant.
      props: { ...validated.props, scopes: validated.scope },
    };
  },

  handler: {
    fetch(request, _env, ctx) {
      // The library has checked that the token is live and bound to this exact resource.
      // Scope policy is the application's job.
      if (!ctx.props.scopes.includes(MCP_READ_SCOPE)) {
        // RFC 6750 section 3.1: the token is good, the scope is not.
        return new Response(null, {
          status: 403,
          headers: { 'WWW-Authenticate': `Bearer error="insufficient_scope", scope="${MCP_READ_SCOPE}"` },
        });
      }
      return handleMcpRequest(request, ctx.props);
    },
  },
});

export default resourceServer satisfies ExportedHandler<Env>;
