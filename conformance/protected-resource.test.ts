import { beforeEach, describe, expect, it } from 'vitest';
import { MCP_PROTECTED_RESOURCE_REVISIONS, MCP_SCOPE_CHALLENGE_REVISIONS, resourceForRevision } from './spec-versions';
import {
  CONFORMANCE_ORIGIN,
  MCP_RESOURCE,
  McpOAuthConformanceServer,
  OFFLINE_ACCESS_SCOPE,
  READ_SCOPE,
  WRITE_SCOPE,
  readJson,
} from './support/oauth-server';

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

describe.each(MCP_PROTECTED_RESOURCE_REVISIONS)('MCP $version protected-resource conformance', (revision) => {
  let server: McpOAuthConformanceServer;

  beforeEach(() => {
    server = new McpOAuthConformanceServer(revision);
  });

  it('discovers the protected resource through its path-specific RFC 9728 URL', async () => {
    const response = await server.request('/.well-known/oauth-protected-resource/mcp');

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

  it('returns a discoverable Bearer challenge when credentials are absent', async () => {
    const response = await server.request('/mcp');
    const challenge = response.headers.get('WWW-Authenticate');

    expect(response.status).toBe(401);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(challenge).toContain('Bearer ');
    expect(challenge).toContain(`resource_metadata="${CONFORMANCE_ORIGIN}/.well-known/oauth-protected-resource/mcp"`);
    expect(challenge).not.toContain('error=');
  });

  it('returns invalid_token for a malformed bearer credential', async () => {
    const response = await server.request('/mcp', {
      headers: { Authorization: 'Bearer not-an-access-token' },
    });
    const challenge = response.headers.get('WWW-Authenticate');

    expect(response.status).toBe(401);
    expect(challenge).toContain('error="invalid_token"');
    expect(challenge).toContain('resource_metadata=');
    expect(await readJson<OAuthErrorBody>(response)).toMatchObject({ error: 'invalid_token' });
  });

  it('rejects a valid token at a resource outside its audience', async () => {
    const client = await server.createClient('none');
    const { tokens } = await server.completeAuthorizationCodeFlow(client);

    const response = await server.request('/other-resource', {
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
    const client = await server.createClient('none');
    const authorization = await server.authorize(client);
    const expandedResource = `${CONFORMANCE_ORIGIN}/other-resource`;

    const rejected = await server.exchangeAuthorizationCode(client, authorization, {
      resource: expandedResource,
    });
    expect(rejected.response.status).toBe(400);
    expect(await readJson<OAuthErrorBody>(rejected.response)).toMatchObject({ error: 'invalid_target' });

    const accepted = await server.exchangeAuthorizationCode(client, authorization, {
      resource: resourceForRevision(revision),
    });
    expect(accepted.response.status).toBe(200);
    expect(accepted.tokens?.access_token).toBeTruthy();
  });
});

describe.each(MCP_SCOPE_CHALLENGE_REVISIONS)('MCP $version scope challenge conformance', (revision) => {
  let server: McpOAuthConformanceServer;

  it('publishes baseline resource scopes without offline_access', async () => {
    server = new McpOAuthConformanceServer(revision, {
      resourceScopes: [READ_SCOPE, OFFLINE_ACCESS_SCOPE, READ_SCOPE],
    });

    const metadataResponse = await server.request('/.well-known/oauth-protected-resource/mcp');
    const metadata = await readJson<ProtectedResourceMetadata>(metadataResponse);
    expect(metadata.scopes_supported).toEqual([READ_SCOPE]);

    const challengeResponse = await server.request('/mcp');
    expect(challengeResponse.headers.get('WWW-Authenticate')).toContain(`scope="${READ_SCOPE}"`);
    expect(challengeResponse.headers.get('WWW-Authenticate')).not.toContain(OFFLINE_ACCESS_SCOPE);
  });

  it('returns a 403 insufficient_scope challenge with operation-specific scopes', async () => {
    server = new McpOAuthConformanceServer(revision, {
      externalTokenMode: 'insufficient-scope',
    });

    const response = await server.request('/mcp', {
      headers: { Authorization: 'Bearer valid-upstream-token-with-too-little-scope' },
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
