import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { z } from 'zod';
import type { McpProps } from '../../shared/config';

/**
 * A stateless MCP server: one `McpServer` and one transport per request, with no session
 * id. Nothing about the OAuth topology depends on this, but it is what makes every
 * request authorized independently, so a revoked token stops working immediately.
 */
export async function handleMcpRequest(request: Request, props: McpProps): Promise<Response> {
  const server = new McpServer({ name: 'example-mcp-server', version: '1.0.0' });

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
