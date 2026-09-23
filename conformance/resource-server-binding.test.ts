import { describe, expect, it } from 'vitest';
import { MCP_AUTH_REVISIONS } from './spec-versions';
import { worker } from './support/harness';
import { createMcpOAuthClient, MCP_RESOURCE, READ_SCOPE } from './support/oauth-client';

/**
 * A resource server in its own Worker validates tokens by asking the authorization server
 * over a Service Binding: `validateToken: (env) => env.AUTH_SERVER.validateToken`. The
 * conformance Worker binds to itself, so this runs the documented line, a detached RPC stub
 * called with the resource and the token, in real Workerd rather than against a mock.
 */
describe('separate resource Worker over a Service Binding', () => {
  const revision = MCP_AUTH_REVISIONS[MCP_AUTH_REVISIONS.length - 1];

  it("validates the authorization server's tokens through the binding and challenges everything else", async () => {
    const oauth = await createMcpOAuthClient(revision);
    const client = await oauth.createClient('none');
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client, { resource: MCP_RESOURCE, scope: READ_SCOPE });
    const api = await worker.getExport();

    const accepted = await api.probeResourceServerOverBinding(tokens.access_token);
    expect(accepted).toMatchObject({ status: 200, body: { subject: 'conformance-user' } });

    const forged = await api.probeResourceServerOverBinding('not-an-access-token');
    expect(forged.status).toBe(401);
    expect(forged.challenge).toContain('error="invalid_token"');

    const anonymous = await api.probeResourceServerOverBinding(undefined);
    expect(anonymous.status).toBe(401);
    const resourceUrl = new URL(MCP_RESOURCE);
    expect(anonymous.challenge).toContain(
      `resource_metadata="${resourceUrl.origin}/.well-known/oauth-protected-resource${resourceUrl.pathname}"`
    );
    expect(anonymous.challenge).not.toContain('error=');
  });
});
