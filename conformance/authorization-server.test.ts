import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MCP_AUTH_REVISIONS, resourceForRevision } from './spec-versions';
import {
  CLIENT_REDIRECT_URI,
  CONFORMANCE_ORIGIN,
  McpOAuthConformanceServer,
  READ_SCOPE,
  readJson,
} from './support/oauth-server';

interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  revocation_endpoint: string;
  response_types_supported: string[];
  grant_types_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  code_challenge_methods_supported: string[];
  authorization_response_iss_parameter_supported?: boolean;
  client_id_metadata_document_supported?: boolean;
}

describe.each(MCP_AUTH_REVISIONS)('MCP $version authorization server conformance', (revision) => {
  let server: McpOAuthConformanceServer;

  beforeEach(() => {
    server = new McpOAuthConformanceServer(revision);
  });

  afterEach(() => {
    server.dispose();
  });

  it('publishes RFC 8414 metadata for the configured OAuth capabilities', async () => {
    const response = await server.request('/.well-known/oauth-authorization-server');

    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toMatch(/^application\/json\b/i);

    const metadata = await readJson<AuthorizationServerMetadata>(response);
    expect(metadata).toMatchObject({
      issuer: CONFORMANCE_ORIGIN,
      authorization_endpoint: `${CONFORMANCE_ORIGIN}/authorize`,
      token_endpoint: `${CONFORMANCE_ORIGIN}/oauth/token`,
      registration_endpoint: `${CONFORMANCE_ORIGIN}/oauth/register`,
      revocation_endpoint: `${CONFORMANCE_ORIGIN}/oauth/token`,
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      authorization_response_iss_parameter_supported: true,
      client_id_metadata_document_supported: true,
    });
    expect(metadata.grant_types_supported).toEqual(expect.arrayContaining(['authorization_code', 'refresh_token']));
    expect(metadata.token_endpoint_auth_methods_supported).toEqual(
      expect.arrayContaining(['none', 'client_secret_basic', 'client_secret_post'])
    );
  });

  it('completes a public-client authorization code flow with S256 PKCE', async () => {
    const client = await server.createClient('none');
    const { authorization, response, tokens } = await server.completeAuthorizationCodeFlow(client);

    expect(authorization.redirect.origin + authorization.redirect.pathname).toBe(CLIENT_REDIRECT_URI);
    expect(authorization.redirect.searchParams.getAll('code')).toHaveLength(1);
    expect(authorization.redirect.searchParams.getAll('state')).toEqual([authorization.state]);
    expect(authorization.redirect.searchParams.has('error')).toBe(false);
    if (authorization.issuer !== null) expect(authorization.issuer).toBe(CONFORMANCE_ORIGIN);

    expect(response.headers.get('Content-Type')).toMatch(/^application\/json\b/i);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('Pragma')).toBe('no-cache');
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.token_type.toLowerCase()).toBe('bearer');
    expect(tokens.expires_in).toBeGreaterThan(0);
    expect(tokens.scope).toBe(READ_SCOPE);

    const protectedResponse = await server.request('/mcp', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(protectedResponse.status).toBe(200);
    expect(await protectedResponse.json()).toEqual({
      authenticated: true,
      props: { subject: 'conformance-user' },
    });
  });

  it('rejects public authorization-code requests that omit PKCE', async () => {
    const client = await server.createClient('none');
    const resource = resourceForRevision(revision);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: READ_SCOPE,
      state: 'missing-pkce',
    });
    if (resource) params.set('resource', resource);

    const response = await server.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('PKCE'),
    });
  });

  it('rejects the plain PKCE method', async () => {
    const client = await server.createClient('none');
    const resource = resourceForRevision(revision);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: READ_SCOPE,
      state: 'plain-pkce',
      code_challenge: 'plain-code-verifier',
      code_challenge_method: 'plain',
    });
    if (resource) params.set('resource', resource);

    const response = await server.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('plain PKCE method is not allowed'),
    });
  });

  it('rejects an unsupported PKCE method instead of treating it as plain', async () => {
    const client = await server.createClient('none');
    const resource = resourceForRevision(revision);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: READ_SCOPE,
      state: 'unsupported-pkce',
      code_challenge: 'attacker-controlled-plain-verifier',
      code_challenge_method: 'S512',
    });
    if (resource) params.set('resource', resource);

    const response = await server.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(response.headers.get('Location')).toBeNull();
    expect(await response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('Unsupported PKCE code_challenge_method'),
    });
  });

  it('rejects an invalid PKCE verifier at the token endpoint', async () => {
    const client = await server.createClient('none');
    const authorization = await server.authorize(client);
    const { response } = await server.exchangeAuthorizationCode(client, authorization, {
      codeVerifier: 'a-different-code-verifier-that-is-at-least-43-characters',
    });

    expect(response.status).toBe(400);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
  });
});
