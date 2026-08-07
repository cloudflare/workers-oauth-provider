import { afterEach, describe, expect, it, vi } from 'vitest';
import { MCP_AUTH_REVISIONS, mcpAuthRevisionsSince, clientResourceForRevision } from './spec-versions';
import {
  CLIENT_REDIRECT_URI,
  CONFORMANCE_ORIGIN,
  McpOAuthClient,
  createMcpOAuthClient,
  READ_SCOPE,
  readJson,
  type OAuthClientCredentials,
} from './support/oauth-client';

interface AuthorizationServerMetadata {
  registration_endpoint?: string;
  client_id_metadata_document_supported?: boolean;
  token_endpoint_auth_methods_supported: string[];
}

interface OAuthErrorBody {
  error: string;
  error_description?: string;
}

describe.each(MCP_AUTH_REVISIONS)('MCP %s dynamic client registration compatibility', (revision) => {
  let oauth: McpOAuthClient;

  it('registers a public client that can complete an S256 authorization-code flow', async () => {
    oauth = await createMcpOAuthClient(revision);
    const registration = await oauth.registerClient('none');

    expect(registration).toMatchObject({
      client_id: expect.any(String),
      redirect_uris: [CLIENT_REDIRECT_URI],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    });
    expect(registration.client_secret).toBeUndefined();

    const client: OAuthClientCredentials = {
      clientId: registration.client_id,
      redirectUri: CLIENT_REDIRECT_URI,
      tokenEndpointAuthMethod: 'none',
    };
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client);
    expect(tokens.access_token).toBeTruthy();
  });

  it('registers a confidential client and accepts client_secret_basic', async () => {
    oauth = await createMcpOAuthClient(revision);
    const registration = await oauth.registerClient('client_secret_basic');

    expect(registration.client_secret).toBeTruthy();
    const client: OAuthClientCredentials = {
      clientId: registration.client_id,
      clientSecret: registration.client_secret,
      redirectUri: CLIENT_REDIRECT_URI,
      tokenEndpointAuthMethod: 'client_secret_basic',
    };
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client);
    expect(tokens.access_token).toBeTruthy();
  });

  it('rejects unsupported client capabilities before registration', async () => {
    oauth = await createMcpOAuthClient(revision);
    const response = await oauth.request('/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Unsupported MCP client',
        redirect_uris: [CLIENT_REDIRECT_URI],
        grant_types: ['password'],
        response_types: [],
        token_endpoint_auth_method: 'private_key_jwt',
      }),
    });

    expect(response.status).toBe(400);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(await readJson<OAuthErrorBody>(response)).toMatchObject({
      error: 'invalid_client_metadata',
    });
  });
});

describe.each(mcpAuthRevisionsSince('2025-11-25'))('MCP %s client registration choices', (revision) => {
  let oauth: McpOAuthClient;
  let fetchMock: ReturnType<typeof vi.spyOn> | undefined;

  afterEach(() => {
    fetchMock?.mockRestore();
  });

  it('supports a pre-registered client when DCR is disabled', async () => {
    oauth = await createMcpOAuthClient(revision, { dynamicClientRegistration: false });
    const metadataResponse = await oauth.request('/.well-known/oauth-authorization-server');
    const metadata = await readJson<AuthorizationServerMetadata>(metadataResponse);
    expect(metadata.registration_endpoint).toBeUndefined();

    const client = await oauth.createClient('client_secret_basic');
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client);
    expect(tokens.access_token).toBeTruthy();
  });

  it('negotiates the live ChatGPT CIMD shape and completes a public-client flow', async () => {
    // Frozen from the live document and independently verified on 2026-08-07.
    const clientId = 'https://chatgpt.com/oauth/IbUR3zxyNQ16/client.json';
    const redirectUri = 'https://chatgpt.com/connector/oauth/IbUR3zxyNQ16';
    const client: OAuthClientCredentials = {
      clientId,
      redirectUri,
      tokenEndpointAuthMethod: 'none',
    };
    fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      expect(String(input)).toBe(clientId);
      return Response.json({
        client_id: clientId,
        client_uri: 'https://chatgpt.com/',
        client_name: 'ChatGPT',
        logo_uri: 'https://persistent.oaistatic.com/sonic/misc/openai-logo.png',
        redirect_uris: [redirectUri],
        grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
        response_types: ['code', 'id_token'],
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
        token_endpoint_auth_signing_alg: 'RS256',
        jwks_uri: 'https://chatgpt.com/oauth/jwks.json',
      });
    });
    oauth = await createMcpOAuthClient(revision, { dynamicClientRegistration: false });

    const metadataResponse = await oauth.request('/.well-known/oauth-authorization-server');
    const metadata = await readJson<AuthorizationServerMetadata>(metadataResponse);
    expect(metadata.client_id_metadata_document_supported).toBe(true);

    const { tokens } = await oauth.completeAuthorizationCodeFlow(client, {
      resource: clientResourceForRevision(revision),
      scope: READ_SCOPE,
    });
    expect(tokens.access_token).toBeTruthy();
    expect(fetchMock).toHaveBeenCalled();
  });

  it('rejects a CIMD document whose client_id does not match its URL', async () => {
    const clientId = 'https://client.example.com/oauth/client-metadata.json';
    fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({
        client_id: 'https://attacker.example.com/oauth/client-metadata.json',
        client_name: 'Mismatched MCP client',
        redirect_uris: [CLIENT_REDIRECT_URI],
        token_endpoint_auth_method: 'none',
      })
    );
    oauth = await createMcpOAuthClient(revision, { dynamicClientRegistration: false });
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: CLIENT_REDIRECT_URI,
      scope: READ_SCOPE,
      state: 'cimd-mismatch',
      code_challenge: 'a-valid-looking-conformance-code-challenge',
      code_challenge_method: 'S256',
      resource: clientResourceForRevision(revision) ?? `${CONFORMANCE_ORIGIN}/mcp`,
    });

    const response = await oauth.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(await readJson<OAuthErrorBody>(response)).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('CIMD fetch failed'),
    });
  });
});
