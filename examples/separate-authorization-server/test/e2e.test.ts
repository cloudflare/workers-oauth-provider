import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createTestHarness } from 'wrangler';

/**
 * The harness runs the same build as `npm run dev:auth` and `npm run dev:mcp`, so the
 * canonical URLs are the ones wrangler's `define` map inlines at the top level of the two
 * wrangler.jsonc files.
 *
 * Requests go through `getWorker(name).fetch()`: `harness.fetch()` needs route patterns
 * to pick a Worker, and only the named form preserves the `https` scheme that both
 * identifiers depend on.
 */
const AUTH_ISSUER = 'https://localhost:8787';
const MCP_RESOURCE = 'https://localhost:8788/mcp';
const REPORTS_RESOURCE = 'https://reports.localhost/api';
const REDIRECT_URI = 'https://client.example.com/callback';
const CODE_VERIFIER = 'e2e-code-verifier-that-is-at-least-43-characters-long';

// Config paths resolve from the directory vitest runs in, which is this example.
const harness = createTestHarness({
  workers: [{ configPath: './mcp-server/wrangler.jsonc' }, { configPath: './authorization-server/wrangler.jsonc' }],
});
const authorizationServer = harness.getWorker('example-authorization-server');
const mcpServer = harness.getWorker('example-mcp-server');

beforeAll(async () => {
  await harness.listen();
});

afterEach(async ({ task }) => {
  if (task.result?.state === 'fail') harness.debug();
  await harness.reset();
});

afterAll(async () => {
  await harness.close();
});

describe('discovery', () => {
  it('publishes authorization server metadata for both registered resources', async () => {
    const response = await authorizationServer.fetch(`${AUTH_ISSUER}/.well-known/oauth-authorization-server`);
    expect(response.status).toBe(200);

    const metadata = (await response.json()) as Json;
    expect(metadata.issuer).toBe(AUTH_ISSUER);
    expect(metadata.authorization_endpoint).toBe(`${AUTH_ISSUER}/authorize`);
    expect(metadata.token_endpoint).toBe(`${AUTH_ISSUER}/oauth/token`);
    expect(metadata.registration_endpoint).toBe(`${AUTH_ISSUER}/oauth/register`);
    expect(metadata.revocation_endpoint).toBe(`${AUTH_ISSUER}/oauth/token`);
    expect(metadata.code_challenge_methods_supported).toContain('S256');
    expect(metadata.client_id_metadata_document_supported).toBe(true);
    expect(metadata.authorization_response_iss_parameter_supported).toBe(true);
    expect(metadata.protected_resources).toEqual([MCP_RESOURCE, REPORTS_RESOURCE]);
    expect(metadata.scopes_supported).toEqual(['mcp:read', 'mcp:write']);
  });

  it('publishes protected resource metadata at the canonical well-known URL', async () => {
    const response = await mcpServer.fetch('https://localhost:8788/.well-known/oauth-protected-resource/mcp');
    expect(response.status).toBe(200);

    const metadata = (await response.json()) as Json;
    expect(metadata.resource).toBe(MCP_RESOURCE);
    expect(metadata.authorization_servers).toEqual([AUTH_ISSUER]);
    expect(metadata.scopes_supported).toEqual(['mcp:read', 'mcp:write']);
    expect(metadata.resource_name).toBe('Example MCP server');
    expect(metadata.bearer_methods_supported).toEqual(['header']);

    // A resource with a path publishes only the path-suffix form. The bare well-known
    // path belongs to a resource whose path is `/`, so aliasing it there would identify
    // a different resource.
    const root = await mcpServer.fetch('https://localhost:8788/.well-known/oauth-protected-resource');
    expect(root.status).toBe(404);
  });
});

describe('bearer challenges', () => {
  it('challenges an unauthenticated MCP request with a resource_metadata pointer', async () => {
    const response = await mcpServer.fetch(MCP_RESOURCE);
    expect(response.status).toBe(401);

    const challenge = response.headers.get('WWW-Authenticate') ?? '';
    expect(challenge).toMatch(/^Bearer\b/);
    expect(challenge).toContain('resource_metadata="https://localhost:8788/.well-known/oauth-protected-resource/mcp"');
    // RFC 6750 section 3.1: no error code when the request carried no credentials,
    // otherwise a client cannot tell "you never authenticated" from "your token is bad".
    expect(challenge).not.toContain('error=');
  });

  it('rejects a garbage bearer token with invalid_token', async () => {
    const response = await mcpServer.fetch(MCP_RESOURCE, { headers: { Authorization: 'Bearer not-a-real-token' } });
    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');
  });
});

describe('authorization code flow', () => {
  it('registers a public client dynamically', async () => {
    const client = await registerPublicClient();
    expect(client.client_id).toBeTruthy();
    expect(client.client_secret).toBeUndefined();
    expect(client.token_endpoint_auth_method).toBe('none');
    expect(client.redirect_uris).toEqual([REDIRECT_URI]);
  });

  it('redirects back with code, state, and iss, then exchanges the code', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, { resource: MCP_RESOURCE, scope: 'mcp:read mcp:write' });

    expect(`${redirect.origin}${redirect.pathname}`).toBe(REDIRECT_URI);
    expect(redirect.searchParams.get('state')).toBe('e2e-state');
    expect(redirect.searchParams.get('iss')).toBe(AUTH_ISSUER);
    const code = redirect.searchParams.get('code');
    expect(code).toBeTruthy();

    const response = await exchangeCode(client.client_id, code as string, { resource: MCP_RESOURCE });
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');

    const tokens = (await response.json()) as TokenResponse;
    // The provider emits the lowercase spelling; RFC 6749 makes token_type
    // case-insensitive, so clients must compare it that way.
    expect(tokens.token_type).toMatch(/^bearer$/i);
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.resource).toBe(MCP_RESOURCE);
  });

  it('rejects an authorization code replayed with the wrong PKCE verifier', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, { resource: MCP_RESOURCE, scope: 'mcp:read' });

    const response = await exchangeCode(client.client_id, redirect.searchParams.get('code') as string, {
      resource: MCP_RESOURCE,
      codeVerifier: 'a-different-verifier-that-is-also-at-least-43-chars',
    });
    expect(response.status).toBe(400);
    expect((await response.json()) as Json).toMatchObject({ error: 'invalid_grant' });
  });

  it('redirects with access_denied when the user declines', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, {
      resource: MCP_RESOURCE,
      scope: 'mcp:read',
      action: 'deny',
    });

    expect(redirect.searchParams.get('error')).toBe('access_denied');
    expect(redirect.searchParams.get('code')).toBeNull();
    expect(redirect.searchParams.get('state')).toBe('e2e-state');
    expect(redirect.searchParams.get('iss')).toBe(AUTH_ISSUER);
  });

  it('binds a grant to defaultResource when the client omits resource', async () => {
    const client = await registerPublicClient();
    // No `resource` parameter, which is what the conformance suite and older clients
    // send. With two registered audiences, `defaultResource` is what keeps them working.
    const redirect = await driveLoginPage(client.client_id, { scope: 'mcp:read' });
    const tokens = await exchange(client.client_id, redirect);

    expect(tokens.resource).toBe(MCP_RESOURCE);
    expect(await mcpStatus(tokens.access_token)).toBe(200);
  });
});

describe('authorization errors', () => {
  it('renders locally rather than redirecting an unvalidated URI', async () => {
    // An unknown client means no verified redirect URI, so reporting the error by
    // redirect would be an open redirect.
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: 'never-registered',
      redirect_uri: 'https://attacker.example.com/callback',
      scope: 'mcp:read',
      state: 'e2e-state',
      resource: MCP_RESOURCE,
      code_challenge: await codeChallenge(CODE_VERIFIER),
      code_challenge_method: 'S256',
    });

    const response = await authorizationServer.fetch(`${AUTH_ISSUER}/authorize?${query}`, { redirect: 'manual' });
    expect(response.status).toBe(400);
    expect(response.headers.get('Location')).toBeNull();
  });

  it('reports an unregistered resource on the client redirect URI with state and iss', async () => {
    const client = await registerPublicClient();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: client.client_id,
      redirect_uri: REDIRECT_URI,
      scope: 'mcp:read',
      state: 'target-state',
      // RFC 8707: this server hosts two audiences, and this is neither of them.
      resource: 'https://elsewhere.example.com/mcp',
      code_challenge: await codeChallenge(CODE_VERIFIER),
      code_challenge_method: 'S256',
    });

    const response = await authorizationServer.fetch(`${AUTH_ISSUER}/authorize?${query}`, { redirect: 'manual' });
    expect(response.status).toBe(302);

    const location = new URL(response.headers.get('Location') as string);
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
    expect(location.searchParams.get('error')).toBe('invalid_target');
    expect(location.searchParams.get('state')).toBe('target-state');
    expect(location.searchParams.get('iss')).toBe(AUTH_ISSUER);
  });
});

describe('the protected MCP server', () => {
  it('serves initialize, tools/list, and tools/call with a valid token', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, { resource: MCP_RESOURCE, scope: 'mcp:read mcp:write' });
    const tokens = await exchange(client.client_id, redirect);

    const initialize = await callMcp(tokens.access_token, {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e2e', version: '1.0.0' } },
    });
    expect(initialize.result).toMatchObject({ serverInfo: { name: 'example-mcp-server' } });

    const toolList = await callMcp(tokens.access_token, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    expect((toolList.result as { tools: { name: string }[] }).tools.map((tool) => tool.name).sort()).toEqual([
      'add',
      'whoami',
    ]);

    const whoami = await callMcp(tokens.access_token, {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'whoami', arguments: {} },
    });
    const text = (whoami.result as { content: { text: string }[] }).content[0].text;
    expect(JSON.parse(text)).toEqual({
      userId: 'ada',
      clientId: client.client_id,
      scopes: ['mcp:read', 'mcp:write'],
    });

    const add = await callMcp(tokens.access_token, {
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'add', arguments: { a: 2, b: 40 } },
    });
    expect((add.result as { content: { text: string }[] }).content[0].text).toBe('42');
  });

  it('never grants a scope this server does not advertise', async () => {
    // The provider publishes `scopesSupported` but does not enforce it, so an unfiltered
    // consent handler would mint a token carrying `admin:everything`.
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, {
      resource: MCP_RESOURCE,
      scope: 'mcp:read admin:everything',
      assertPage: (html) => {
        // The consent screen must not offer what the grant will not carry.
        expect(html).toContain('mcp:read');
        expect(html).not.toContain('admin:everything');
      },
    });

    const tokens = await exchange(client.client_id, redirect);
    expect(tokens.scope).toBe('mcp:read');
  });

  it('rejects a token whose effective scope is too narrow for this resource', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, { resource: MCP_RESOURCE, scope: 'mcp:read mcp:write' });

    // A client may ask the token endpoint for less than the grant allows, so the resource
    // server reads the effective token scope rather than the scope stored on the grant.
    const tokens = (await (
      await exchangeCode(client.client_id, redirect.searchParams.get('code') as string, {
        resource: MCP_RESOURCE,
        scope: 'mcp:write',
      })
    ).json()) as TokenResponse;
    expect(tokens.scope).toBe('mcp:write');

    const response = await mcpServer.fetch(MCP_RESOURCE, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    // RFC 6750 section 3.1: the token is good, the scope is not.
    expect(response.status).toBe(403);
    expect(response.headers.get('WWW-Authenticate')).toBe('Bearer error="insufficient_scope", scope="mcp:read"');
  });

  it('grants no scope to a client that requests none, which this resource then refuses', async () => {
    const client = await registerPublicClient();
    // The conformance suite sends exactly this: no `scope` and no `resource`.
    const redirect = await driveLoginPage(client.client_id, {});
    const tokens = await exchange(client.client_id, redirect);

    // `defaultResource` supplies the audience, but nothing supplies scope: this
    // authorization server grants only what was asked for.
    expect(tokens.resource).toBe(MCP_RESOURCE);
    expect(tokens.scope).toBe('');
    expect(await mcpStatus(tokens.access_token)).toBe(403);
  });

  it('rejects a token issued for a different registered audience', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, { resource: REPORTS_RESOURCE, scope: 'mcp:read' });
    const tokens = (await (
      await exchangeCode(client.client_id, redirect.searchParams.get('code') as string, {
        resource: REPORTS_RESOURCE,
      })
    ).json()) as TokenResponse;
    expect(tokens.resource).toBe(REPORTS_RESOURCE);

    // Defended twice: `McpTokenValidator` is pinned to MCP_RESOURCE, and the resource
    // server compares the audience it gets back against its own resource.
    const response = await mcpServer.fetch(MCP_RESOURCE, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');
  });
});

describe('token lifecycle', () => {
  it('refreshes an access token and keeps the MCP server reachable', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, { resource: MCP_RESOURCE, scope: 'mcp:read' });
    const tokens = await exchange(client.client_id, redirect);

    const response = await authorizationServer.fetch(`${AUTH_ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token as string,
        client_id: client.client_id,
      }).toString(),
    });
    expect(response.status).toBe(200);

    const refreshed = (await response.json()) as TokenResponse;
    expect(refreshed.access_token).not.toBe(tokens.access_token);
    expect(refreshed.resource).toBe(MCP_RESOURCE);
    expect(await mcpStatus(refreshed.access_token)).toBe(200);
  });

  it('revokes a token at the token endpoint and locks the MCP server immediately', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, { resource: MCP_RESOURCE, scope: 'mcp:read' });
    const tokens = await exchange(client.client_id, redirect);
    expect(await mcpStatus(tokens.access_token)).toBe(200);

    // Revocation is served by the token endpoint on this branch.
    const revocation = await authorizationServer.fetch(`${AUTH_ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: tokens.access_token, client_id: client.client_id }).toString(),
    });
    expect(revocation.status).toBe(200);

    // The MCP Worker holds no token state, so the next request asks the authorization
    // server again over the Service Binding and is refused.
    expect(await mcpStatus(tokens.access_token)).toBe(401);
  });
});

type Json = Record<string, any>;

interface TokenResponse {
  access_token: string;
  token_type: string;
  refresh_token?: string;
  resource?: string;
  scope?: string;
}

interface RegisteredClient {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
}

async function registerPublicClient(): Promise<RegisteredClient> {
  const response = await authorizationServer.fetch(`${AUTH_ISSUER}/oauth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: 'End-to-end test client',
      redirect_uris: [REDIRECT_URI],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    }),
  });
  expect(response.status).toBe(201);
  return (await response.json()) as RegisteredClient;
}

/** Drives the placeholder login page the way a browser would. */
async function driveLoginPage(
  clientId: string,
  options: {
    resource?: string;
    scope?: string;
    action?: 'approve' | 'deny';
    assertPage?: (html: string) => void;
  }
): Promise<URL> {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    state: 'e2e-state',
    code_challenge: await codeChallenge(CODE_VERIFIER),
    code_challenge_method: 'S256',
  });
  // Omitting `resource` exercises the authorization server's `defaultResource`.
  if (options.resource) query.set('resource', options.resource);
  if (options.scope) query.set('scope', options.scope);

  const form = await authorizationServer.fetch(`${AUTH_ISSUER}/authorize?${query}`);
  expect(form.status).toBe(200);
  const html = await form.text();
  expect(html).toContain('name="username"');
  options.assertPage?.(html);

  const approval = await authorizationServer.fetch(`${AUTH_ISSUER}/authorize?${query}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'ada', action: options.action ?? 'approve' }).toString(),
    redirect: 'manual',
  });
  expect(approval.status).toBe(302);
  return new URL(approval.headers.get('Location') as string);
}

function exchangeCode(
  clientId: string,
  code: string,
  options: { resource?: string; scope?: string; codeVerifier?: string } = {}
) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    code_verifier: options.codeVerifier ?? CODE_VERIFIER,
  });
  if (options.resource) body.set('resource', options.resource);
  if (options.scope) body.set('scope', options.scope);
  return authorizationServer.fetch(`${AUTH_ISSUER}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
}

/** The common case: exchange the code from a completed login for tokens. */
async function exchange(clientId: string, redirect: URL): Promise<TokenResponse> {
  const response = await exchangeCode(clientId, redirect.searchParams.get('code') as string, {
    resource: MCP_RESOURCE,
  });
  expect(response.status).toBe(200);
  return (await response.json()) as TokenResponse;
}

async function mcpStatus(accessToken: string): Promise<number> {
  const response = await mcpServer.fetch(MCP_RESOURCE, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  });
  return response.status;
}

async function callMcp(accessToken: string, body: unknown): Promise<{ result?: unknown; error?: unknown }> {
  const response = await mcpServer.fetch(MCP_RESOURCE, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify(body),
  });
  expect(response.status).toBe(200);
  return (await response.json()) as { result?: unknown; error?: unknown };
}

async function codeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return Buffer.from(digest).toString('base64url');
}
