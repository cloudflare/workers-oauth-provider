import { beforeEach, describe, expect, it } from 'vitest';
import { MCP_AUTH_REVISIONS, mcpAuthRevisionsSince, clientResourceForRevision } from './spec-versions';
import {
  CONFORMANCE_ORIGIN,
  INSUFFICIENT_SCOPE_TOKEN,
  MCP_RESOURCE,
  McpOAuthClient,
  createMcpOAuthClient,
  OFFLINE_ACCESS_SCOPE,
  READ_SCOPE,
  WRITE_SCOPE,
  readJson,
} from './support/oauth-client';

interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported?: string[];
  bearer_methods_supported: string[];
  resource_name?: string;
}

interface OAuthErrorBody {
  error: string;
  error_description?: string;
}

describe.each(MCP_AUTH_REVISIONS)('MCP %s bearer-token conformance', (revision) => {
  let oauth: McpOAuthClient;

  beforeEach(async () => {
    oauth = await createMcpOAuthClient(revision);
  });

  it('returns a bare Bearer challenge when credentials are absent', async () => {
    const response = await oauth.request('/mcp');
    const challenge = response.headers.get('WWW-Authenticate');

    expect(response.status).toBe(401);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(challenge).toContain('Bearer ');
    expect(challenge).not.toContain('error=');
  });

  it('returns invalid_token for a malformed bearer credential', async () => {
    const response = await oauth.request('/mcp', {
      headers: { Authorization: 'Bearer not-an-access-token' },
    });

    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');
    expect(await readJson<OAuthErrorBody>(response)).toMatchObject({ error: 'invalid_token' });
  });
});

describe.each(mcpAuthRevisionsSince('2025-06-18'))('MCP %s protected-resource conformance', (revision) => {
  let oauth: McpOAuthClient;

  beforeEach(async () => {
    oauth = await createMcpOAuthClient(revision);
  });

  it('discovers the protected resource through its path-specific RFC 9728 URL', async () => {
    const response = await oauth.request('/.well-known/oauth-protected-resource/mcp');

    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toMatch(/^application\/json\b/i);
    expect(await readJson<ProtectedResourceMetadata>(response)).toEqual({
      resource: MCP_RESOURCE,
      authorization_servers: [CONFORMANCE_ORIGIN],
      scopes_supported: [READ_SCOPE],
      bearer_methods_supported: ['header'],
      resource_name: 'MCP auth conformance server',
    });
  });

  it('links its path-specific metadata from Bearer challenges', async () => {
    const challenge = (await oauth.request('/mcp')).headers.get('WWW-Authenticate');
    expect(challenge).toContain(`resource_metadata="${CONFORMANCE_ORIGIN}/.well-known/oauth-protected-resource/mcp"`);
  });

  it('rejects a valid token at a resource outside its audience', async () => {
    const client = await oauth.createClient('none');
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client);

    const response = await oauth.request('/other-resource', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');
    expect(await readJson<OAuthErrorBody>(response)).toMatchObject({
      error: 'invalid_token',
      error_description: expect.stringContaining('audience'),
    });
  });

  it('rejects resource expansion at the token endpoint without consuming the code', async () => {
    const client = await oauth.createClient('none');
    const authorization = await oauth.authorize(client);
    const expandedResource = `${CONFORMANCE_ORIGIN}/other-resource`;

    const rejected = await oauth.exchangeAuthorizationCode(client, authorization, {
      resource: expandedResource,
    });
    expect(rejected.response.status).toBe(400);
    expect(await readJson<OAuthErrorBody>(rejected.response)).toMatchObject({ error: 'invalid_target' });

    const accepted = await oauth.exchangeAuthorizationCode(client, authorization, {
      resource: clientResourceForRevision(revision),
    });
    expect(accepted.response.status).toBe(200);
    expect(accepted.tokens?.access_token).toBeTruthy();
  });
});

describe.each(mcpAuthRevisionsSince('2025-11-25'))('MCP %s scope challenge conformance', (revision) => {
  let oauth: McpOAuthClient;

  it('publishes baseline resource scopes without offline_access', async () => {
    oauth = await createMcpOAuthClient(revision, {
      resourceScopes: [READ_SCOPE, OFFLINE_ACCESS_SCOPE, READ_SCOPE],
    });

    const metadataResponse = await oauth.request('/.well-known/oauth-protected-resource/mcp');
    const metadata = await readJson<ProtectedResourceMetadata>(metadataResponse);
    expect(metadata.scopes_supported).toEqual([READ_SCOPE]);

    const challengeResponse = await oauth.request('/mcp');
    expect(challengeResponse.headers.get('WWW-Authenticate')).toContain(`scope="${READ_SCOPE}"`);
    expect(challengeResponse.headers.get('WWW-Authenticate')).not.toContain(OFFLINE_ACCESS_SCOPE);
  });

  it('returns a 403 insufficient_scope challenge with operation-specific scopes', async () => {
    oauth = await createMcpOAuthClient(revision);

    const response = await oauth.request('/mcp', {
      headers: { Authorization: `Bearer ${INSUFFICIENT_SCOPE_TOKEN}` },
    });
    const challenge = response.headers.get('WWW-Authenticate');

    expect(response.status).toBe(403);
    expect(challenge).toContain('error="insufficient_scope"');
    expect(challenge).toContain(`scope="${READ_SCOPE} ${WRITE_SCOPE}"`);
    expect(challenge).toContain('resource_metadata=');
    expect(await readJson<OAuthErrorBody>(response)).toMatchObject({
      error: 'insufficient_scope',
    });
  });
});
