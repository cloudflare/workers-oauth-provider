import { describe, expect, it } from 'vitest';
import { MCP_AUTH_REVISIONS } from './spec-versions';
import { worker } from './support/harness';
import { createMcpOAuthClient, MCP_RESOURCE, READ_SCOPE, WRITE_SCOPE } from './support/oauth-client';

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
    // ctx.props is what the authorization server decrypted; ctx.auth is what it verified, carried
    // back over the binding: audience, expiry, scopes, subject and client.
    expect(accepted).toMatchObject({
      status: 200,
      body: {
        subject: 'conformance-user',
        auth: {
          token: tokens.access_token,
          audience: MCP_RESOURCE,
          expiresAt: expect.any(Number),
          scope: [READ_SCOPE],
          userId: 'conformance-user',
          clientId: client.clientId,
        },
      },
    });

    // MCP scope challenge handling: a valid token without the operation's scope gets a 403 naming
    // every scope the operation needs and the same metadata document as the 401.
    const resourceUrl = new URL(MCP_RESOURCE);
    const metadataUrl = `${resourceUrl.origin}/.well-known/oauth-protected-resource${resourceUrl.pathname}`;
    const forbidden = await api.probeResourceServerOverBinding(tokens.access_token, 'DELETE');
    expect(forbidden.status).toBe(403);
    expect(forbidden.challenge).toBe(
      `Bearer realm="OAuth", error="insufficient_scope", scope="${WRITE_SCOPE}", resource_metadata="${metadataUrl}"`
    );

    const forged = await api.probeResourceServerOverBinding('not-an-access-token');
    expect(forged.status).toBe(401);
    expect(forged.challenge).toContain('error="invalid_token"');

    // The initial challenge names the scopes to request (MCP 2026-07-28), and no error.
    const anonymous = await api.probeResourceServerOverBinding(undefined);
    expect(anonymous.status).toBe(401);
    expect(anonymous.challenge).toBe(`Bearer realm="OAuth", resource_metadata="${metadataUrl}", scope="${READ_SCOPE}"`);
  });
});
