import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  MCP_AUTHORIZATION_RESPONSE_ISSUER_REVISIONS,
  MCP_AUTH_REVISIONS,
  MCP_OFFLINE_ACCESS_GUIDANCE_REVISIONS,
  MCP_PROTECTED_RESOURCE_REVISIONS,
  resourceForRevision,
} from './spec-versions';
import {
  CLIENT_REDIRECT_URI,
  CONFORMANCE_ORIGIN,
  McpOAuthConformanceServer,
  OFFLINE_ACCESS_SCOPE,
  READ_SCOPE,
  readJson,
} from './support/oauth-server';

interface OAuthErrorBody {
  error: string;
  error_description?: string;
}

interface AuthorizationServerMetadata {
  issuer: string;
  authorization_response_iss_parameter_supported?: boolean;
  scopes_supported?: string[];
}

interface ProtectedResourceMetadata {
  scopes_supported?: string[];
}

describe.each(MCP_AUTH_REVISIONS)('MCP $version authorization security conformance', (revision) => {
  let server: McpOAuthConformanceServer;

  beforeEach(() => {
    server = new McpOAuthConformanceServer(revision);
  });

  afterEach(() => {
    server.dispose();
  });

  it('does not redirect an authorization request with an unregistered redirect URI', async () => {
    const client = await server.createClient('none');
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: 'https://attacker.example.com/callback',
      state: 'untrusted-redirect',
      code_challenge: 'a-valid-looking-conformance-code-challenge',
      code_challenge_method: 'S256',
    });
    const resource = resourceForRevision(revision);
    if (resource) params.set('resource', resource);

    const response = await server.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(response.headers.get('Location')).toBeNull();
    expect(await readJson<OAuthErrorBody>(response)).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('Invalid redirect URI'),
    });
  });

  it('does not redirect an authorization request for an unknown client', async () => {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: 'unknown-client',
      redirect_uri: CLIENT_REDIRECT_URI,
      state: 'unknown-client',
      code_challenge: 'a-valid-looking-conformance-code-challenge',
      code_challenge_method: 'S256',
    });
    const resource = resourceForRevision(revision);
    if (resource) params.set('resource', resource);

    const response = await server.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(response.headers.get('Location')).toBeNull();
  });

  it('does not consume an authorization code when redirect_uri validation fails at the token endpoint', async () => {
    const client = await server.createClient('none');
    const authorization = await server.authorize(client);

    const invalid = await server.exchangeAuthorizationCode(
      { ...client, redirectUri: 'https://attacker.example.com/callback' },
      authorization
    );
    expect(invalid.response.status).toBe(400);
    expect(await readJson<OAuthErrorBody>(invalid.response)).toMatchObject({ error: 'invalid_grant' });

    const retry = await server.exchangeAuthorizationCode(client, authorization);
    expect(retry.response.status).toBe(200);
    expect(retry.tokens?.access_token).toBeTruthy();
  });

  it('challenges invalid confidential-client credentials without consuming the code', async () => {
    const client = await server.createClient('client_secret_basic');
    const authorization = await server.authorize(client);

    const invalid = await server.exchangeAuthorizationCode(
      { ...client, clientSecret: 'not-the-client-secret' },
      authorization
    );
    expect(invalid.response.status).toBe(401);
    expect(invalid.response.headers.get('WWW-Authenticate')).toBe('Basic realm="OAuth"');
    expect(await readJson<OAuthErrorBody>(invalid.response)).toMatchObject({ error: 'invalid_client' });

    const retry = await server.exchangeAuthorizationCode(client, authorization);
    expect(retry.response.status).toBe(200);
  });

  it('accepts client_secret_post when that is the registered client authentication method', async () => {
    const client = await server.createClient('client_secret_post');
    const { tokens } = await server.completeAuthorizationCodeFlow(client);
    expect(tokens.access_token).toBeTruthy();
  });
});

describe.each(MCP_PROTECTED_RESOURCE_REVISIONS)(
  'MCP $version Resource Indicator authorization security',
  (revision) => {
    let server: McpOAuthConformanceServer;

    beforeEach(() => {
      server = new McpOAuthConformanceServer(revision);
    });

    afterEach(() => {
      server.dispose();
    });

    it('requires the configured canonical resource in the authorization request', async () => {
      const client = await server.createClient('none');
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: client.clientId,
        redirect_uri: client.redirectUri,
        scope: READ_SCOPE,
        state: 'missing-resource',
        code_challenge: 'a-valid-looking-conformance-code-challenge',
        code_challenge_method: 'S256',
      });

      const response = await server.request(`/authorize?${params}`);

      expect(response.status).toBe(400);
      expect(response.headers.get('Location')).toBeNull();
      expect(await readJson<OAuthErrorBody>(response)).toMatchObject({
        error: 'invalid_request',
        error_description: expect.stringContaining('resource parameter must exactly match'),
      });
    });

    it('rejects a resource URI containing a fragment', async () => {
      const client = await server.createClient('none');
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: client.clientId,
        redirect_uri: client.redirectUri,
        scope: READ_SCOPE,
        state: 'fragment-resource',
        code_challenge: 'a-valid-looking-conformance-code-challenge',
        code_challenge_method: 'S256',
        resource: `${CONFORMANCE_ORIGIN}/mcp#fragment`,
      });

      const response = await server.request(`/authorize?${params}`);

      expect(response.status).toBe(400);
      expect(response.headers.get('Location')).toBeNull();
    });

    it('returns the canonical resource in successful token responses', async () => {
      const client = await server.createClient('none');
      const { tokens } = await server.completeAuthorizationCodeFlow(client);
      expect(tokens.resource).toBe(`${CONFORMANCE_ORIGIN}/mcp`);
    });
  }
);

describe.each(MCP_AUTHORIZATION_RESPONSE_ISSUER_REVISIONS)(
  'MCP $version authorization response issuer conformance',
  (revision) => {
    let server: McpOAuthConformanceServer;

    afterEach(() => {
      server.dispose();
    });

    it('advertises RFC 9207 and includes exactly one matching iss parameter', async () => {
      server = new McpOAuthConformanceServer(revision);
      const metadataResponse = await server.request('/.well-known/oauth-authorization-server');
      const metadata = await readJson<AuthorizationServerMetadata>(metadataResponse);
      expect(metadata.authorization_response_iss_parameter_supported).toBe(true);

      const client = await server.createClient('none');
      const authorization = await server.authorize(client);
      expect(authorization.redirect.searchParams.getAll('iss')).toEqual([metadata.issuer]);
      expect(metadata.issuer).toBe(CONFORMANCE_ORIGIN);
    });
  }
);

describe.each(MCP_OFFLINE_ACCESS_GUIDANCE_REVISIONS)('MCP $version refresh-token scope guidance', (revision) => {
  let server: McpOAuthConformanceServer;

  afterEach(() => {
    server.dispose();
  });

  it('advertises offline_access only as an authorization-server capability', async () => {
    server = new McpOAuthConformanceServer(revision, {
      resourceScopes: [READ_SCOPE, OFFLINE_ACCESS_SCOPE],
    });

    const authorizationMetadata = await readJson<AuthorizationServerMetadata>(
      await server.request('/.well-known/oauth-authorization-server')
    );
    expect(authorizationMetadata.scopes_supported).toContain(OFFLINE_ACCESS_SCOPE);

    const resourceMetadata = await readJson<ProtectedResourceMetadata>(
      await server.request('/.well-known/oauth-protected-resource/mcp')
    );
    expect(resourceMetadata.scopes_supported).toEqual([READ_SCOPE]);

    const challenge = (await server.request('/mcp')).headers.get('WWW-Authenticate');
    expect(challenge).not.toContain(OFFLINE_ACCESS_SCOPE);
  });
});
