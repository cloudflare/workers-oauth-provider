import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createTestHarness } from 'wrangler';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { UnauthorizedError, type OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';

/**
 * The harness runs the same build as `npm run dev`, so the canonical URLs are the ones
 * wrangler's `define` map inlines at the top level of wrangler.jsonc.
 *
 * Requests go through `getWorker(name).fetch()` rather than `harness.fetch()`: only the
 * named form preserves the `https` scheme, and the combined provider derives its issuer
 * and its audience comparison from the request URL.
 */
const ORIGIN = 'http://localhost:8787';
const MCP_RESOURCE = `${ORIGIN}/mcp`;
const REDIRECT_URI = 'https://client.example.com/callback';
const CODE_VERIFIER = 'e2e-code-verifier-that-is-at-least-43-characters-long';

// Config paths resolve from the directory vitest runs in, which is this example.
const harness = createTestHarness({ workers: [{ configPath: './wrangler.jsonc' }] });
const worker = harness.getWorker('example-proxy-mcp-server');

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
  it('publishes authorization server metadata', async () => {
    const response = await worker.fetch(`${ORIGIN}/.well-known/oauth-authorization-server`);
    expect(response.status).toBe(200);

    const metadata = (await response.json()) as Json;
    expect(metadata.issuer).toBe(ORIGIN);
    expect(metadata.authorization_endpoint).toBe(`${ORIGIN}/authorize`);
    expect(metadata.token_endpoint).toBe(`${ORIGIN}/oauth/token`);
    expect(metadata.registration_endpoint).toBe(`${ORIGIN}/oauth/register`);
    expect(metadata.revocation_endpoint).toBe(`${ORIGIN}/oauth/token`);
    expect(metadata.code_challenge_methods_supported).toContain('S256');
    expect(metadata.client_id_metadata_document_supported).toBe(true);
    expect(metadata.authorization_response_iss_parameter_supported).toBe(true);
    expect(metadata.protected_resources).toEqual([MCP_RESOURCE]);
    expect(metadata.scopes_supported).toEqual(['mcp:read', 'mcp:write']);
  });

  it('publishes protected resource metadata at the canonical well-known URL', async () => {
    const response = await worker.fetch(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`);
    expect(response.status).toBe(200);

    const metadata = (await response.json()) as Json;
    expect(metadata.resource).toBe(MCP_RESOURCE);
    expect(metadata.authorization_servers).toEqual([ORIGIN]);
    expect(metadata.scopes_supported).toEqual(['mcp:read', 'mcp:write']);
    expect(metadata.resource_name).toBe('Proxy MCP server');

    // A resource with a path publishes only the path-suffix form. The bare well-known
    // path belongs to a resource whose path is `/`, so aliasing it there would identify
    // a different resource.
    const root = await worker.fetch(`${ORIGIN}/.well-known/oauth-protected-resource`);
    expect(root.status).toBe(404);
  });
});

describe('bearer challenges', () => {
  it('challenges an unauthenticated MCP request with a resource_metadata pointer', async () => {
    const response = await worker.fetch(MCP_RESOURCE);
    expect(response.status).toBe(401);

    const challenge = response.headers.get('WWW-Authenticate') ?? '';
    expect(challenge).toMatch(/^Bearer\b/);
    expect(challenge).toContain(`resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp"`);
    // RFC 6750 section 3.1: no error code when the request carried no credentials,
    // otherwise a client cannot tell "you never authenticated" from "your token is bad".
    expect(challenge).not.toContain('error=');
  });

  it('rejects a garbage bearer token with invalid_token', async () => {
    const response = await worker.fetch(MCP_RESOURCE, { headers: { Authorization: 'Bearer not-a-real-token' } });
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
    expect(redirect.searchParams.get('iss')).toBe(ORIGIN);
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
    expect(redirect.searchParams.get('iss')).toBe(ORIGIN);
  });

  it('binds a grant to the sole registered resource when the client omits resource', async () => {
    const client = await registerPublicClient();
    // No `resource` parameter, which is what older clients
    // send. A provider that hosts exactly one audience selects it for them.
    const redirect = await driveLoginPage(client.client_id, { scope: 'mcp:read' });
    const tokens = await exchange(client.client_id, redirect);

    expect(tokens.resource).toBe(MCP_RESOURCE);
    expect(await mcpStatus(tokens.access_token)).toBe(200);
  });
});

describe('authorization errors', () => {
  it('answers a malformed approval form with 400 rather than a Worker error', async () => {
    const client = await registerPublicClient();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: client.client_id,
      redirect_uri: REDIRECT_URI,
      state: 'e2e-state',
      code_challenge: await codeChallenge(CODE_VERIFIER),
      code_challenge_method: 'S256',
    });
    const response = await worker.fetch(`${ORIGIN}/authorize?${query}`, {
      method: 'POST',
      headers: { 'Content-Type': 'multipart/form-data; boundary=missing' },
      body: 'not a multipart body',
    });
    expect(response.status).toBe(400);
  });

  it('renders locally rather than redirecting an unvalidated URI', async () => {
    // An unknown client means no verified redirect URI, so reporting the error by
    // redirect would be an open redirect.
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: 'never-registered',
      redirect_uri: 'https://attacker.example.com/callback',
      scope: 'mcp:read',
      state: 'e2e-state',
      code_challenge: await codeChallenge(CODE_VERIFIER),
      code_challenge_method: 'S256',
    });

    const response = await worker.fetch(`${ORIGIN}/authorize?${query}`, { redirect: 'manual' });
    expect(response.status).toBe(400);
    expect(response.headers.get('Location')).toBeNull();
  });

  it('reports an unhosted resource on the client redirect URI with state and iss', async () => {
    const client = await registerPublicClient();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: client.client_id,
      redirect_uri: REDIRECT_URI,
      scope: 'mcp:read',
      state: 'target-state',
      // RFC 8707: this server hosts exactly one audience, and it is not this one.
      resource: 'https://elsewhere.example.com/mcp',
      code_challenge: await codeChallenge(CODE_VERIFIER),
      code_challenge_method: 'S256',
    });

    const response = await worker.fetch(`${ORIGIN}/authorize?${query}`, { redirect: 'manual' });
    expect(response.status).toBe(302);

    const location = new URL(response.headers.get('Location') as string);
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
    expect(location.searchParams.get('error')).toBe('invalid_target');
    expect(location.searchParams.get('state')).toBe('target-state');
    expect(location.searchParams.get('iss')).toBe(ORIGIN);
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
    expect(initialize.result).toMatchObject({ serverInfo: { name: 'example-proxy-mcp-server' } });

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

    const whoami = await callMcp(tokens.access_token, {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'whoami', arguments: {} },
    });
    const text = (whoami.result as { content: { text: string }[] }).content[0].text;
    expect(JSON.parse(text).scopes).toEqual(['mcp:read']);
  });

  it('refuses a grant that does not carry the scope this resource requires', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, { resource: MCP_RESOURCE, scope: 'mcp:write' });
    const tokens = await exchange(client.client_id, redirect);
    expect(tokens.scope).toBe('mcp:write');

    const response = await worker.fetch(MCP_RESOURCE, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    // RFC 6750 section 3.1: the token is good, the scope is not.
    expect(response.status).toBe(403);
    expect(response.headers.get('WWW-Authenticate')).toBe('Bearer error="insufficient_scope", scope="mcp:read"');
  });

  it('rejects a token narrowed below mcp:read at the token endpoint', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, { resource: MCP_RESOURCE, scope: 'mcp:read mcp:write' });

    // A client may ask the token endpoint for less than the grant allows. `ctx.props` is
    // the data the application stored, so the example's `tokenExchangeCallback` rewrites
    // `scopes` to each token's effective scope. Without it the handler would still see
    // the grant's full scope and accept this token.
    const tokens = (await (
      await exchangeCode(client.client_id, redirect.searchParams.get('code') as string, {
        resource: MCP_RESOURCE,
        scope: 'mcp:write',
      })
    ).json()) as TokenResponse;
    expect(tokens.scope).toBe('mcp:write');
    expect(await mcpStatus(tokens.access_token)).toBe(403);
  });
});

describe('token lifecycle', () => {
  it('refreshes an access token and keeps the MCP server reachable', async () => {
    const client = await registerPublicClient();
    const redirect = await driveLoginPage(client.client_id, { resource: MCP_RESOURCE, scope: 'mcp:read' });
    const tokens = await exchange(client.client_id, redirect);

    const response = await worker.fetch(`${ORIGIN}/oauth/token`, {
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
    const revocation = await worker.fetch(`${ORIGIN}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: tokens.access_token, client_id: client.client_id }).toString(),
    });
    expect(revocation.status).toBe(200);

    // Every MCP request is authorized on its own, so revocation takes effect at once.
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

describe('a real MCP SDK client', () => {
  it('discovers, registers, authorizes, calls tools, and refreshes through the SDK', async () => {
    // The same client library Claude Code uses, driven the way a browser flow would be:
    // the SDK discovers the protected resource and authorization server, registers
    // dynamically, opens the authorization request, and exchanges the code; the provider
    // below plays the user agent against the placeholder login.
    const provider = new SdkClientProvider();
    const transportOptions = { authProvider: provider, fetch: routedFetch };
    const client = new Client({ name: 'sdk-e2e', version: '1.0.0' });
    let transport = new StreamableHTTPClientTransport(new URL(MCP_RESOURCE), transportOptions);
    await expect(client.connect(transport)).rejects.toBeInstanceOf(UnauthorizedError);
    expect(provider.authorizationCode).toBeDefined();
    expect(provider.issuer).toBe(ORIGIN);
    expect(provider.requestedResource).toBe(MCP_RESOURCE);

    await transport.finishAuth(provider.authorizationCode!);
    transport = new StreamableHTTPClientTransport(new URL(MCP_RESOURCE), transportOptions);
    await client.connect(transport);
    expect(client.getServerVersion()?.name).toBe('example-proxy-mcp-server');
    expect(provider.tokens()?.scope).toBe('mcp:read mcp:write');

    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name).sort()).toEqual(['add', 'whoami']);
    const whoami = await client.callTool({ name: 'whoami', arguments: {} });
    expect(JSON.parse(textOf(whoami))).toMatchObject({ userId: 'ada', scopes: ['mcp:read', 'mcp:write'] });

    // A dead access token is refreshed transparently rather than surfacing as an error.
    const before = provider.tokens()!.access_token;
    provider.corruptAccessToken();
    const add = await client.callTool({ name: 'add', arguments: { a: 40, b: 2 } });
    expect(textOf(add)).toBe('42');
    expect(provider.tokens()!.access_token).not.toBe(before);
    await client.close();
  });
});

/** Routes the SDK's requests to the harness Workers instead of the network. */
const routedFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
  return (await worker.fetch(url.href, init as Parameters<typeof worker.fetch>[1])) as unknown as Response;
};

function textOf(result: Awaited<ReturnType<Client['callTool']>>): string {
  return (result.content as Array<{ type: string; text: string }>)[0].text;
}

/** An `OAuthClientProvider` that approves the placeholder login itself and keeps state in memory. */
class SdkClientProvider implements OAuthClientProvider {
  private client: OAuthClientInformationMixed | undefined;
  private storedTokens: OAuthTokens | undefined;
  private verifier = '';
  private readonly stateValue = crypto.randomUUID();
  authorizationCode: string | undefined;
  issuer: string | null = null;
  requestedResource: string | null = null;

  get redirectUrl(): string {
    return REDIRECT_URI;
  }
  get clientMetadata(): OAuthClientMetadata {
    return {
      redirect_uris: [REDIRECT_URI],
      client_name: 'sdk-e2e',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    };
  }
  state(): string {
    return this.stateValue;
  }
  clientInformation(): OAuthClientInformationMixed | undefined {
    return this.client;
  }
  saveClientInformation(information: OAuthClientInformationMixed): void {
    this.client = information;
  }
  tokens(): OAuthTokens | undefined {
    return this.storedTokens;
  }
  saveTokens(tokens: OAuthTokens): void {
    this.storedTokens = tokens;
  }
  saveCodeVerifier(verifier: string): void {
    this.verifier = verifier;
  }
  codeVerifier(): string {
    return this.verifier;
  }
  corruptAccessToken(): void {
    this.storedTokens = { ...this.storedTokens!, access_token: 'no-longer-valid' };
  }
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    this.requestedResource = authorizationUrl.searchParams.get('resource');
    const page = await routedFetch(authorizationUrl);
    expect(page.status).toBe(200);
    // The harness follows redirects unless told not to; the code is on the Location header.
    const approval = await routedFetch(authorizationUrl, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'ada', action: 'approve' }).toString(),
    });
    expect(approval.status).toBe(302);
    const location = new URL(approval.headers.get('Location')!);
    expect(location.href.startsWith(REDIRECT_URI)).toBe(true);
    expect(location.searchParams.get('state')).toBe(this.stateValue);
    this.authorizationCode = location.searchParams.get('code') ?? undefined;
    this.issuer = location.searchParams.get('iss');
  }
}

async function registerPublicClient(): Promise<RegisteredClient> {
  const response = await worker.fetch(`${ORIGIN}/oauth/register`, {
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
  // Omitting `resource` leaves the provider to select its sole registered audience.
  if (options.resource) query.set('resource', options.resource);
  if (options.scope) query.set('scope', options.scope);

  const form = await worker.fetch(`${ORIGIN}/authorize?${query}`);
  expect(form.status).toBe(200);
  const html = await form.text();
  expect(html).toContain('name="username"');
  options.assertPage?.(html);

  const approval = await worker.fetch(`${ORIGIN}/authorize?${query}`, {
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
  return worker.fetch(`${ORIGIN}/oauth/token`, {
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
  const response = await worker.fetch(MCP_RESOURCE, {
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
  const response = await worker.fetch(MCP_RESOURCE, {
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
