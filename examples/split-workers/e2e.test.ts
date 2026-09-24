/// <reference types="vite/client" />
import { afterAll, beforeAll, expect, it } from 'vitest';
import { createTestHarness } from 'wrangler';
import readme from '../../README.md?raw';
import authServerSource from './auth-server/index.ts?raw';
import mcpServerSource from './mcp-server/index.ts?raw';

// Both Workers run in workerd; mcp-server reaches auth-server over a real Service Binding.
const harness = createTestHarness({
  workers: [
    { configPath: './examples/split-workers/auth-server/wrangler.jsonc' },
    { configPath: './examples/split-workers/mcp-server/wrangler.jsonc' },
  ],
});
const auth = harness.getWorker('auth-server');
const mcp = harness.getWorker('mcp-server');

beforeAll(() => harness.listen());
afterAll(() => harness.close());

const RESOURCE = 'https://mcp.example.com/mcp';
const REDIRECT_URI = 'https://client.example/callback';

it('walks an MCP client from the first 401 to an authorized call', async () => {
  // 1. The MCP server challenges and names its metadata, which names the authorization server.
  const challenge = await mcp.fetch(RESOURCE);
  expect(challenge.status).toBe(401);
  const metadataUrl = /resource_metadata="([^"]+)"/.exec(challenge.headers.get('WWW-Authenticate')!)![1];
  const { authorization_servers } = (await (await mcp.fetch(metadataUrl)).json()) as {
    authorization_servers: string[];
  };
  expect(authorization_servers).toEqual(['https://auth.example.com']);
  const as = (await (
    await auth.fetch(`${authorization_servers[0]}/.well-known/oauth-authorization-server`)
  ).json()) as Record<string, string>;

  // 2. Register, authorize with PKCE, and exchange the code.
  const client = (await (
    await auth.fetch(as.registration_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: 'none' }),
    })
  ).json()) as { client_id: string };
  const verifier = crypto.randomUUID() + crypto.randomUUID();
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challengeParam = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const authorizeUrl = new URL(as.authorization_endpoint);
  for (const [key, value] of Object.entries({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    scope: 'mcp:read',
    state: 'xyz',
    code_challenge: challengeParam,
    code_challenge_method: 'S256',
    resource: RESOURCE,
  }))
    authorizeUrl.searchParams.set(key, value);
  const redirect = await auth.fetch(authorizeUrl, { redirect: 'manual' });
  const code = new URL(redirect.headers.get('Location')!).searchParams.get('code')!;
  const tokens = (await (
    await auth.fetch(as.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: client.client_id,
        code_verifier: verifier,
        resource: RESOURCE,
      }),
    })
  ).json()) as { access_token: string };

  // 3. The token works at the MCP server, which validated it over the binding.
  const call = await mcp.fetch(RESOURCE, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  expect(call.status).toBe(200);
  await expect(call.json()).resolves.toEqual({ userId: 'user-123', scope: ['mcp:read'] });
});

it('is the README quick start, verbatim', () => {
  const quickStart = readme.slice(readme.indexOf('## Quick start'), readme.indexOf('## Single Worker'));
  const blocks = [...quickStart.matchAll(/```ts\n([\s\S]*?)```/g)].map((match) => match[1]);
  expect(blocks).toEqual([authServerSource, mcpServerSource]);
});
