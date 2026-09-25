import { afterAll, beforeAll, expect, it } from 'vitest';
import { createTestHarness } from 'wrangler';

const RESOURCE = 'https://mcp.example.com/mcp';
const REDIRECT_URI = 'https://client.example/callback';

/** A fresh ES256 signing key per run, supplied as a test-only secret: no key is committed. */
async function signingKey(kid: string): Promise<string> {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const { kty, crv, x, y, d } = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey;
  return JSON.stringify({ kty, crv, x, y, d, kid });
}

// Both Workers run in workerd. mcp-server fetches the auth server's JWKS once over its Service
// Binding, then verifies every token itself.
const harness = createTestHarness({
  workers: [
    {
      configPath: './examples/jwt-access-tokens/auth-server/wrangler.jsonc',
      secrets: { JWT_SIGNING_KEY: await signingKey('2026-09-24') },
    },
    { configPath: './examples/jwt-access-tokens/mcp-server/wrangler.jsonc' },
  ],
});
const auth = harness.getWorker('jwt-auth-server');
const mcp = harness.getWorker('jwt-mcp-server');

beforeAll(() => harness.listen());
afterAll(() => harness.close());

/** Register a public client, authorize with PKCE, and exchange the code for tokens. */
async function tokens(scope = 'mcp:read') {
  const client = (await (
    await auth.fetch('https://auth.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: 'none' }),
    })
  ).json()) as { client_id: string };
  const verifier = crypto.randomUUID() + crypto.randomUUID();
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const authorize = new URL('https://auth.example.com/authorize');
  authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    scope,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    resource: RESOURCE,
  }).toString();
  const redirect = await auth.fetch(authorize, { redirect: 'manual' });
  const code = new URL(redirect.headers.get('Location')!).searchParams.get('code')!;
  const response = await auth.fetch('https://auth.example.com/oauth/token', {
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
  });
  expect(response.status).toBe(200);
  return (await response.json()) as { access_token: string; refresh_token: string; expires_in: number };
}

function claimsOf(jwt: string): Record<string, unknown> {
  const payload = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(atob(payload));
}

it('issues a short-lived ES256 JWT carrying the claims the auth server added', async () => {
  const { access_token, refresh_token, expires_in } = await tokens();
  expect(expires_in).toBe(300);
  expect(JSON.parse(atob(access_token.split('.')[0]))).toEqual({ alg: 'ES256', typ: 'at+jwt', kid: '2026-09-24' });
  expect(claimsOf(access_token)).toMatchObject({
    iss: 'https://auth.example.com',
    sub: 'user-123',
    aud: RESOURCE,
    scope: 'mcp:read',
    plan: 'pro',
  });
  // Props are encrypted with the grant and never appear in the token; refresh tokens stay opaque.
  expect(JSON.stringify(claimsOf(access_token))).not.toContain('Ada');
  expect(refresh_token).not.toContain('.');
});

it('publishes the public key and advertises it in the authorization server metadata', async () => {
  const metadata = (await (
    await auth.fetch('https://auth.example.com/.well-known/oauth-authorization-server')
  ).json()) as {
    jwks_uri: string;
  };
  expect(metadata.jwks_uri).toBe('https://auth.example.com/.well-known/jwks.json');
  const { keys } = (await (await auth.fetch(metadata.jwks_uri)).json()) as { keys: Record<string, string>[] };
  expect(keys).toEqual([expect.objectContaining({ kid: '2026-09-24', kty: 'EC', crv: 'P-256', alg: 'ES256' })]);
  expect(keys[0]).not.toHaveProperty('d');
});

it('lets the MCP server verify the token offline and use its claims', async () => {
  const { access_token } = await tokens();
  const call = await mcp.fetch(RESOURCE, { headers: { Authorization: `Bearer ${access_token}` } });
  expect(call.status).toBe(200);
  await expect(call.json()).resolves.toEqual({ userId: 'user-123', plan: 'pro' });
});

it('rejects a tampered token and answers a token without the scope with insufficient_scope', async () => {
  const { access_token } = await tokens();
  const [header, , signature] = access_token.split('.');
  const forgedClaims = btoa(JSON.stringify({ ...claimsOf(access_token), sub: 'someone-else' }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const tampered = await mcp.fetch(RESOURCE, {
    headers: { Authorization: `Bearer ${header}.${forgedClaims}.${signature}` },
  });
  expect(tampered.status).toBe(401);

  const { access_token: noScope } = await tokens('profile');
  const call = await mcp.fetch(RESOURCE, { headers: { Authorization: `Bearer ${noScope}` } });
  expect(call.status).toBe(403);
  expect(call.headers.get('WWW-Authenticate')).toContain('error="insufficient_scope", scope="mcp:read"');
});
