import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { WorkerEntrypoint } from 'cloudflare:workers';
import { z } from 'zod';
import { MCP_READ_SCOPE, type Env, type McpProps } from './config';

/**
 * The protected handler. By the time it runs, the provider has resolved the bearer token
 * and checked that it is live and issued for this resource, so there is no token parsing
 * here. Scope policy is still the application's job.
 *
 * This is a `WorkerEntrypoint` subclass rather than a plain object handler only because
 * `OAuthProvider` types `apiHandler` without a props type parameter, and the class form
 * is the one way to get `ctx.props` typed as `McpProps`.
 */
export class McpApiHandler extends WorkerEntrypoint<Env, McpProps> {
  async fetch(request: Request): Promise<Response> {
    const props = this.ctx.props;
    if (!props.scopes.includes(MCP_READ_SCOPE)) {
      // RFC 6750 section 3.1: the token is good, the scope is not.
      return new Response(null, {
        status: 403,
        headers: { 'WWW-Authenticate': `Bearer error="insufficient_scope", scope="${MCP_READ_SCOPE}"` },
      });
    }
    return handleMcpRequest(request, props);
  }
}

/**
 * A stateless MCP server: one `McpServer` and one transport per request, with no session
 * id. Nothing about the OAuth topology depends on this, but it is what makes every
 * request authorized independently, so a revoked token stops working immediately.
 */
async function handleMcpRequest(request: Request, props: McpProps): Promise<Response> {
  const server = new McpServer({ name: 'example-proxy-mcp-server', version: '1.0.0' });

  server.registerTool(
    'whoami',
    {
      description: 'Return the identity and scopes carried by the access token.',
      inputSchema: {},
    },
    async () => ({
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify({ userId: props.userId, clientId: props.clientId, scopes: props.scopes }),
        },
      ],
    })
  );

  server.registerTool(
    'add',
    {
      description: 'Add two numbers.',
      inputSchema: { a: z.number(), b: z.number() },
    },
    async ({ a, b }) => ({
      content: [{ type: 'text' as const, text: String(a + b) }],
    })
  );

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  await server.connect(transport);
  return transport.handleRequest(request);
}
