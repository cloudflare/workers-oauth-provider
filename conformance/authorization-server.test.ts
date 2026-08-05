import { beforeEach, describe, expect, it } from 'vitest';
import { MCP_AUTH_REVISIONS, clientResourceForRevision } from './spec-versions';
import {
  CLIENT_REDIRECT_URI,
  CONFORMANCE_ORIGIN,
  McpOAuthClient,
  createMcpOAuthClient,
  READ_SCOPE,
  readJson,
} from './support/oauth-client';

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

describe.each(MCP_AUTH_REVISIONS)('MCP %s authorization server conformance', (revision) => {
  let oauth: McpOAuthClient;

  beforeEach(async () => {
    oauth = await createMcpOAuthClient(revision);
  });

  it('publishes RFC 8414 metadata for the configured OAuth capabilities', async () => {
    const response = await oauth.request('/.well-known/oauth-authorization-server');

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
    const client = await oauth.createClient('none');
    const { authorization, response, tokens } = await oauth.completeAuthorizationCodeFlow(client);

    expect(authorization.redirect.origin + authorization.redirect.pathname).toBe(CLIENT_REDIRECT_URI);
    expect(authorization.redirect.searchParams.getAll('code')).toHaveLength(1);
    expect(authorization.redirect.searchParams.getAll('state')).toEqual([authorization.state]);
    expect(authorization.redirect.searchParams.has('error')).toBe(false);
    expect(authorization.redirect.searchParams.getAll('iss')).toEqual([CONFORMANCE_ORIGIN]);

    expect(response.headers.get('Content-Type')).toMatch(/^application\/json\b/i);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('Pragma')).toBe('no-cache');
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.token_type.toLowerCase()).toBe('bearer');
    expect(tokens.expires_in).toBeGreaterThan(0);
    expect(tokens.scope).toBe(READ_SCOPE);
    expect(tokens.resource).toBe(clientResourceForRevision(revision));

    const protectedResponse = await oauth.request('/mcp', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(protectedResponse.status).toBe(200);
    expect(await protectedResponse.json()).toEqual({
      authenticated: true,
      protocolVersion: revision,
      props: { subject: 'conformance-user' },
    });
  });

  it('rejects public authorization-code requests that omit PKCE', async () => {
    const client = await oauth.createClient('none');
    const resource = clientResourceForRevision(revision);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: READ_SCOPE,
      state: 'missing-pkce',
    });
    if (resource) params.set('resource', resource);

    const response = await oauth.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('PKCE'),
    });
  });

  it('rejects the plain PKCE method', async () => {
    const client = await oauth.createClient('none');
    const resource = clientResourceForRevision(revision);
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

    const response = await oauth.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('plain PKCE method is not allowed'),
    });
  });

  it('rejects a PKCE challenge that omits its method because RFC 7636 defaults it to plain', async () => {
    const client = await oauth.createClient('none');
    const resource = clientResourceForRevision(revision);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: READ_SCOPE,
      state: 'implicit-plain-pkce',
      code_challenge: 'plain-code-verifier',
    });
    if (resource) params.set('resource', resource);

    const response = await oauth.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('plain PKCE method is not allowed'),
    });
  });

  it('rejects an unsupported PKCE method instead of treating it as plain', async () => {
    const client = await oauth.createClient('none');
    const resource = clientResourceForRevision(revision);
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

    const response = await oauth.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(response.headers.get('Location')).toBeNull();
    expect(await response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('Unsupported PKCE code_challenge_method'),
    });
  });

  it('rejects an invalid PKCE verifier at the token endpoint', async () => {
    const client = await oauth.createClient('none');
    const authorization = await oauth.authorize(client);
    const { response } = await oauth.exchangeAuthorizationCode(client, authorization, {
      codeVerifier: 'a-different-code-verifier-that-is-at-least-43-characters',
    });

    expect(response.status).toBe(400);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
  });
});
