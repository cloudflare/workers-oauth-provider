import { beforeEach, describe, expect, it } from 'vitest';
import { MCP_AUTH_REVISIONS, mcpAuthRevisionsSince, clientResourceForRevision } from './spec-versions';
import {
  CLIENT_REDIRECT_URI,
  CONFORMANCE_ORIGIN,
  DENIED_SCOPE,
  MCP_RESOURCE,
  McpOAuthClient,
  createMcpOAuthClient,
  OFFLINE_ACCESS_SCOPE,
  READ_SCOPE,
  readJson,
} from './support/oauth-client';

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

describe.each(MCP_AUTH_REVISIONS)('MCP %s authorization security conformance', (revision) => {
  let oauth: McpOAuthClient;

  beforeEach(async () => {
    oauth = await createMcpOAuthClient(revision);
  });

  it('does not redirect an authorization request with an unregistered redirect URI', async () => {
    const client = await oauth.createClient('none');
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: 'https://attacker.example.com/callback',
      state: 'untrusted-redirect',
      code_challenge: 'a-valid-looking-conformance-code-challenge',
      code_challenge_method: 'S256',
    });
    const resource = clientResourceForRevision(revision);
    if (resource) params.set('resource', resource);

    const response = await oauth.request(`/authorize?${params}`);

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
    const resource = clientResourceForRevision(revision);
    if (resource) params.set('resource', resource);

    const response = await oauth.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(response.headers.get('Location')).toBeNull();
  });

  it('does not consume an authorization code when redirect_uri validation fails at the token endpoint', async () => {
    const client = await oauth.createClient('none');
    const authorization = await oauth.authorize(client);

    const invalid = await oauth.exchangeAuthorizationCode(
      { ...client, redirectUri: 'https://attacker.example.com/callback' },
      authorization
    );
    expect(invalid.response.status).toBe(400);
    expect(await readJson<OAuthErrorBody>(invalid.response)).toMatchObject({ error: 'invalid_grant' });

    const retry = await oauth.exchangeAuthorizationCode(client, authorization);
    expect(retry.response.status).toBe(200);
    expect(retry.tokens?.access_token).toBeTruthy();
  });

  it('challenges invalid confidential-client credentials without consuming the code', async () => {
    const client = await oauth.createClient('client_secret_basic');
    const authorization = await oauth.authorize(client);

    const invalid = await oauth.exchangeAuthorizationCode(
      { ...client, clientSecret: 'not-the-client-secret' },
      authorization
    );
    expect(invalid.response.status).toBe(401);
    expect(invalid.response.headers.get('WWW-Authenticate')).toBe('Basic realm="OAuth"');
    expect(await readJson<OAuthErrorBody>(invalid.response)).toMatchObject({ error: 'invalid_client' });

    const retry = await oauth.exchangeAuthorizationCode(client, authorization);
    expect(retry.response.status).toBe(200);
  });

  it('accepts client_secret_post when that is the registered client authentication method', async () => {
    const client = await oauth.createClient('client_secret_post');
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client);
    expect(tokens.access_token).toBeTruthy();
  });

  it.each([
    ['client_secret_basic', 'client_secret_post'],
    ['client_secret_post', 'client_secret_basic'],
    ['none', 'client_secret_basic'],
    ['none', 'client_secret_post'],
  ] as const)(
    'rejects %s clients that authenticate using %s without consuming the code',
    async (registeredMethod, presentedMethod) => {
      const client = await oauth.createClient(registeredMethod);
      const authorization = await oauth.authorize(client);
      const mismatchedClient = {
        ...client,
        clientSecret: client.clientSecret ?? 'unexpected-public-client-secret',
        tokenEndpointAuthMethod: presentedMethod,
      };

      const invalid = await oauth.exchangeAuthorizationCode(mismatchedClient, authorization);
      expect(invalid.response.status).toBe(401);
      expect(await readJson<OAuthErrorBody>(invalid.response)).toEqual({
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      });
      expect(invalid.response.headers.get('WWW-Authenticate')).toBe(
        presentedMethod === 'client_secret_basic' ? 'Basic realm="OAuth"' : null
      );

      const retry = await oauth.exchangeAuthorizationCode(client, authorization);
      expect(retry.response.status).toBe(200);
    }
  );
});

describe('canonical resource policy compatibility boundary', () => {
  it('defaults and inherits the canonical resource for a 2025-03-26 client that omits it', async () => {
    const oauth = await createMcpOAuthClient('2025-03-26', { resourcePolicy: 'canonical' });
    const client = await oauth.createClient('none');
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client);

    expect(tokens.resource).toBe(MCP_RESOURCE);
  });
});

describe.each(mcpAuthRevisionsSince('2025-06-18'))('MCP %s Resource Indicator authorization security', (revision) => {
  let oauth: McpOAuthClient;

  beforeEach(async () => {
    oauth = await createMcpOAuthClient(revision, { resourcePolicy: 'canonical' });
  });

  it('defaults an omitted authorization resource to the configured canonical resource', async () => {
    const client = await oauth.createClient('none');
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: READ_SCOPE,
      state: 'missing-resource',
      code_challenge: 'a-valid-looking-conformance-code-challenge',
      code_challenge_method: 'S256',
    });

    const response = await oauth.request(`/authorize?${params}`);

    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).not.toBeNull();
  });

  it('rejects a resource URI containing a fragment', async () => {
    const client = await oauth.createClient('none');
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

    const response = await oauth.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(response.headers.get('Location')).toBeNull();
    expect(await readJson<OAuthErrorBody>(response)).toMatchObject({ error: 'invalid_target' });
  });

  it('rejects an explicit resource that does not match the configured canonical resource', async () => {
    const client = await oauth.createClient('none');
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: READ_SCOPE,
      state: 'mismatched-resource',
      code_challenge: 'a-valid-looking-conformance-code-challenge',
      code_challenge_method: 'S256',
      resource: `${CONFORMANCE_ORIGIN}/other`,
    });

    const response = await oauth.request(`/authorize?${params}`);

    expect(response.status).toBe(400);
    expect(await readJson<OAuthErrorBody>(response)).toMatchObject({ error: 'invalid_target' });
  });

  it('accepts the canonical resource throughout authorization and token exchange', async () => {
    const client = await oauth.createClient('none');
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client);
    expect(tokens.resource).toBe(`${CONFORMANCE_ORIGIN}/mcp`);
  });
});

describe.each(mcpAuthRevisionsSince('2026-07-28'))('MCP %s authorization response issuer conformance', (revision) => {
  let oauth: McpOAuthClient;

  it('advertises RFC 9207 and includes exactly one matching iss parameter', async () => {
    oauth = await createMcpOAuthClient(revision);
    const metadataResponse = await oauth.request('/.well-known/oauth-authorization-server');
    const metadata = await readJson<AuthorizationServerMetadata>(metadataResponse);
    expect(metadata.authorization_response_iss_parameter_supported).toBe(true);

    const client = await oauth.createClient('none');
    const authorization = await oauth.authorize(client);
    expect(authorization.redirect.searchParams.getAll('iss')).toEqual([metadata.issuer]);
    expect(metadata.issuer).toBe(CONFORMANCE_ORIGIN);
  });

  it('includes the matching issuer in terminal authorization errors', async () => {
    oauth = await createMcpOAuthClient(revision);
    const client = await oauth.createClient('none');
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: DENIED_SCOPE,
      state: 'denied-state',
      code_challenge: 'a-valid-looking-conformance-code-challenge',
      code_challenge_method: 'S256',
      resource: MCP_RESOURCE,
    });

    const response = await oauth.request(`/authorize?${params}`);
    expect(response.status).toBe(302);
    const redirect = new URL(response.headers.get('Location')!);
    expect(redirect.searchParams.getAll('error')).toEqual(['access_denied']);
    expect(redirect.searchParams.getAll('state')).toEqual(['denied-state']);
    expect(redirect.searchParams.getAll('iss')).toEqual([CONFORMANCE_ORIGIN]);
    expect(redirect.searchParams.has('code')).toBe(false);
  });
});

describe.each(mcpAuthRevisionsSince('2026-07-28'))('MCP %s refresh-token scope guidance', (revision) => {
  let oauth: McpOAuthClient;

  it('advertises offline_access only as an authorization-server capability', async () => {
    oauth = await createMcpOAuthClient(revision, {
      resourceScopes: [READ_SCOPE, OFFLINE_ACCESS_SCOPE],
    });

    const authorizationMetadata = await readJson<AuthorizationServerMetadata>(
      await oauth.request('/.well-known/oauth-authorization-server')
    );
    expect(authorizationMetadata.scopes_supported).toContain(OFFLINE_ACCESS_SCOPE);

    const resourceMetadata = await readJson<ProtectedResourceMetadata>(
      await oauth.request('/.well-known/oauth-protected-resource/mcp')
    );
    expect(resourceMetadata.scopes_supported).toEqual([READ_SCOPE]);

    const challenge = (await oauth.request('/mcp')).headers.get('WWW-Authenticate');
    expect(challenge).not.toContain(OFFLINE_ACCESS_SCOPE);
  });
});
