import { beforeEach, describe, expect, it } from 'vitest';
import { MCP_AUTH_REVISIONS } from './spec-versions';
import {
  CONFORMANCE_ORIGIN,
  MCP_RESOURCE,
  McpOAuthClient,
  createMcpOAuthClient,
  READ_SCOPE,
  WRITE_SCOPE,
  readJson,
  type OAuthClientCredentials,
} from './support/oauth-client';

interface OAuthErrorBody {
  error: string;
  error_description?: string;
}

describe.each(MCP_AUTH_REVISIONS)('MCP %s OAuth token lifecycle conformance', (revision) => {
  let oauth: McpOAuthClient;
  let client: OAuthClientCredentials;

  beforeEach(async () => {
    oauth = await createMcpOAuthClient(revision);
    client = await oauth.createClient('none');
  });

  it('rotates refresh tokens while allowing one retry with the previous token', async () => {
    const initial = await oauth.completeAuthorizationCodeFlow(client, {
      scope: `${READ_SCOPE} ${WRITE_SCOPE}`,
    });
    const originalRefreshToken = initial.tokens.refresh_token;
    expect(originalRefreshToken).toBeTruthy();

    const firstRefresh = await oauth.refresh(client, originalRefreshToken!, { scope: READ_SCOPE });
    expect(firstRefresh.response.status).toBe(200);
    expect(firstRefresh.response.headers.get('Cache-Control')).toBe('no-store');
    expect(firstRefresh.tokens?.scope).toBe(READ_SCOPE);
    expect(firstRefresh.tokens?.refresh_token).toBeTruthy();
    expect(firstRefresh.tokens?.refresh_token).not.toBe(originalRefreshToken);

    const retry = await oauth.refresh(client, originalRefreshToken!, { scope: READ_SCOPE });
    expect(retry.response.status).toBe(200);
    expect(retry.tokens?.access_token).toBeTruthy();
    expect(retry.tokens?.refresh_token).toBeTruthy();

    const acknowledgement = await oauth.refresh(client, retry.tokens!.refresh_token!, { scope: READ_SCOPE });
    expect(acknowledgement.response.status).toBe(200);

    const replay = await oauth.refresh(client, originalRefreshToken!, { scope: READ_SCOPE });
    expect(replay.response.status).toBe(400);
    expect(await readJson<OAuthErrorBody>(replay.response)).toMatchObject({ error: 'invalid_grant' });
  });

  it('allows tokens to be downscoped but not expanded', async () => {
    const authorization = await oauth.authorize(client, {
      scope: `${READ_SCOPE} ${WRITE_SCOPE}`,
    });
    const exchange = await oauth.exchangeAuthorizationCode(client, authorization, {
      scope: `${READ_SCOPE} mcp:admin`,
    });

    expect(exchange.response.status).toBe(200);
    expect(exchange.tokens?.scope).toBe(READ_SCOPE);
  });

  it('rejects a mismatched registered authentication method before revocation', async () => {
    const confidentialClient = await oauth.createClient('client_secret_basic');
    const { tokens } = await oauth.completeAuthorizationCodeFlow(confidentialClient);
    const mismatchedClient: OAuthClientCredentials = {
      ...confidentialClient,
      tokenEndpointAuthMethod: 'client_secret_post',
    };

    const rejected = await oauth.revoke(mismatchedClient, tokens.access_token, 'access_token');
    expect(rejected.status).toBe(401);
    expect(await readJson<OAuthErrorBody>(rejected)).toEqual({
      error: 'invalid_client',
      error_description: 'Client authentication failed',
    });

    const stillValid = await oauth.request('/mcp', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(stillValid.status).toBe(200);

    const revoked = await oauth.revoke(confidentialClient, tokens.access_token, 'access_token');
    expect(revoked.status).toBe(200);

    const noLongerValid = await oauth.request('/mcp', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(noLongerValid.status).toBe(401);
  });

  it('revokes an access token without revoking its refresh token', async () => {
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client);
    expect(tokens.refresh_token).toBeTruthy();

    const revocation = await oauth.revoke(client, tokens.access_token, 'access_token');
    expect(revocation.status).toBe(200);

    const rejected = await oauth.request('/mcp', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(rejected.status).toBe(401);
    expect(rejected.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');

    const refresh = await oauth.refresh(client, tokens.refresh_token!);
    expect(refresh.response.status).toBe(200);
    expect(refresh.tokens?.access_token).toBeTruthy();
  });

  it('revokes the grant when a refresh token is revoked', async () => {
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client);
    expect(tokens.refresh_token).toBeTruthy();

    const revocation = await oauth.revoke(client, tokens.refresh_token!, 'refresh_token');
    expect(revocation.status).toBe(200);

    const accessResponse = await oauth.request('/mcp', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(accessResponse.status).toBe(401);

    const refreshResponse = await oauth.refresh(client, tokens.refresh_token!);
    expect(refreshResponse.response.status).toBe(400);
    expect(await readJson<OAuthErrorBody>(refreshResponse.response)).toMatchObject({ error: 'invalid_grant' });
  });

  it('does not let another client revoke tokens it does not own', async () => {
    const { tokens } = await oauth.completeAuthorizationCodeFlow(client);
    const otherClient = await oauth.createClient('none');

    const revocation = await oauth.revoke(otherClient, tokens.access_token, 'access_token');
    expect(revocation.status).toBe(200);

    const accessResponse = await oauth.request('/mcp', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(accessResponse.status).toBe(200);
  });

  // A server that stops hosting a resource (an `/sse` endpoint, or the bare origin a 0.x server
  // advertised at its root metadata URL) leaves grants bound to it. A client repeats its grant's
  // resource on refresh (RFC 8707 §2.2) from 2025-06-18 on. The grant is the defect, so the answer
  // is invalid_grant, on which clients re-authorize (RFC 6749 §5.2), not invalid_target.
  it('answers a refresh of a grant bound to a resource the server no longer hosts with invalid_grant', async () => {
    const before = await createMcpOAuthClient(revision, { resource: CONFORMANCE_ORIGIN });
    const existingClient = await before.createClient('none');
    const { tokens } = await before.completeAuthorizationCodeFlow(existingClient);
    expect(tokens.refresh_token).toBeTruthy();

    await before.redeploy(MCP_RESOURCE);

    const accessResponse = await before.request('/mcp', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(accessResponse.status).toBe(401);
    expect(accessResponse.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');

    const refreshResponse = await before.refresh(existingClient, tokens.refresh_token!);
    expect(refreshResponse.response.status).toBe(400);
    expect(await readJson<OAuthErrorBody>(refreshResponse.response)).toEqual({
      error: 'invalid_grant',
      error_description:
        'The authorization grant is bound to a resource this server no longer serves. Authorize again.',
    });

    // Re-authorizing for the resource the server now hosts recovers the same client.
    const reauthorized = await oauth.completeAuthorizationCodeFlow(existingClient);
    const recovered = await oauth.request('/mcp', {
      headers: { Authorization: `Bearer ${reauthorized.tokens.access_token}` },
    });
    expect(recovered.status).toBe(200);
  });

  it('rejects authorization-code replay and invalidates tokens issued from that code', async () => {
    const authorization = await oauth.authorize(client);
    const firstExchange = await oauth.exchangeAuthorizationCode(client, authorization);
    expect(firstExchange.response.status).toBe(200);
    expect(firstExchange.tokens?.access_token).toBeTruthy();

    const replay = await oauth.exchangeAuthorizationCode(client, authorization);
    expect(replay.response.status).toBe(400);
    expect(await readJson<OAuthErrorBody>(replay.response)).toMatchObject({ error: 'invalid_grant' });

    const accessResponse = await oauth.request('/mcp', {
      headers: { Authorization: `Bearer ${firstExchange.tokens!.access_token}` },
    });
    expect(accessResponse.status).toBe(401);
  });
});
