import { afterAll, beforeAll, expect, it } from 'vitest';
import { createTestHarness } from 'wrangler';

const AUTH_SERVER = { configPath: './examples/split-workers/auth-server/wrangler.jsonc' };
const MCP_SERVER = { configPath: './examples/split-workers/mcp-server/wrangler.jsonc' };

// Both Workers run in workerd; mcp-server reaches auth-server over a real Service Binding.
const harness = createTestHarness({ workers: [AUTH_SERVER, MCP_SERVER] });
const auth = harness.getWorker('auth-server');
const mcp = harness.getWorker('mcp-server');

beforeAll(() => harness.listen());
afterAll(() => harness.close());

const RESOURCE = 'https://mcp.example.com/mcp';
const REDIRECT_URI = 'https://client.example/callback';

/** Discover the authorization server from the MCP server's 401, as an MCP client does. */
async function discover() {
  const challenge = await mcp.fetch(RESOURCE);
  expect(challenge.status).toBe(401);
  const metadataUrl = /resource_metadata="([^"]+)"/.exec(challenge.headers.get('WWW-Authenticate')!)![1];
  const { authorization_servers } = (await (await mcp.fetch(metadataUrl)).json()) as {
    authorization_servers: string[];
  };
  expect(authorization_servers).toEqual(['https://auth.example.com']);
  return (await (
    await auth.fetch(`${authorization_servers[0]}/.well-known/oauth-authorization-server`)
  ).json()) as Record<string, string>;
}

/** Register a public client and start a PKCE authorization for `scope`. */
async function authorize(as: Record<string, string>, scope: string) {
  const client = (await (
    await auth.fetch(as.registration_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: 'none' }),
    })
  ).json()) as { client_id: string };
  const verifier = crypto.randomUUID() + crypto.randomUUID();
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const url = new URL(as.authorization_endpoint);
  for (const [key, value] of Object.entries({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    scope,
    state: 'xyz',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    resource: RESOURCE,
  }))
    url.searchParams.set(key, value);
  const response = await auth.fetch(url, { redirect: 'manual' });
  return { response, clientId: client.client_id, verifier };
}

/** Complete the authorization and exchange the code for an access token. */
async function accessToken(as: Record<string, string>, scope: string) {
  const { response, clientId, verifier } = await authorize(as, scope);
  const code = new URL(response.headers.get('Location')!).searchParams.get('code')!;
  const tokens = (await (
    await auth.fetch(as.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: clientId,
        code_verifier: verifier,
        resource: RESOURCE,
      }),
    })
  ).json()) as { access_token: string };
  return tokens.access_token;
}

it('walks an MCP client from the first 401 to a read, then steps up for a write', async () => {
  // The first 401 names the resource's baseline; the server's metadata lists its whole catalogue.
  const challenge = await mcp.fetch(RESOURCE);
  expect(challenge.headers.get('WWW-Authenticate')).toContain('scope="mcp:read"');
  const as = await discover();
  expect(as.scopes_supported).toEqual(['mcp:read', 'mcp:write', 'offline_access']);

  // The client requests the baseline, as MCP clients do, and can read.
  const readToken = await accessToken(as, 'mcp:read');
  const read = await mcp.fetch(RESOURCE, { headers: { Authorization: `Bearer ${readToken}` } });
  expect(read.status).toBe(200);
  await expect(read.json()).resolves.toEqual({ userId: 'user-123', scope: ['mcp:read'] });

  // A write needs more: the 403 names every scope it needs, and the client re-authorizes for them.
  const denied = await mcp.fetch(RESOURCE, { method: 'POST', headers: { Authorization: `Bearer ${readToken}` } });
  expect(denied.status).toBe(403);
  expect(denied.headers.get('WWW-Authenticate')).toContain('error="insufficient_scope", scope="mcp:read mcp:write"');
  const writeToken = await accessToken(as, 'mcp:read mcp:write');
  const write = await mcp.fetch(RESOURCE, { method: 'POST', headers: { Authorization: `Bearer ${writeToken}` } });
  expect(write.status).toBe(200);

  // Write scope alone isn't enough: every operation needs the baseline too.
  const writeOnly = await accessToken(as, 'mcp:write');
  const refused = await mcp.fetch(RESOURCE, { method: 'POST', headers: { Authorization: `Bearer ${writeOnly}` } });
  expect(refused.status).toBe(403);
});
