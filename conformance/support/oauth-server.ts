import { afterAll, afterEach, beforeAll } from 'vitest';
import { createTestHarness } from 'wrangler';
import { resourceForRevision, type McpAuthRevision } from '../spec-versions';
import type { ConformanceWorkerEnv, WorkerClientCredentials, WorkerConfiguration } from '../worker';

const CONFIG_HEADER = 'x-mcp-conformance-config';

export const CONFORMANCE_ORIGIN = 'https://mcp.example.com';
export const MCP_RESOURCE = `${CONFORMANCE_ORIGIN}/mcp`;
export const CLIENT_REDIRECT_URI = 'https://client.example.com/callback';
export const READ_SCOPE = 'mcp:read';
export const WRITE_SCOPE = 'mcp:write';
export const OFFLINE_ACCESS_SCOPE = 'offline_access';

export type TokenEndpointAuthMethod = WorkerClientCredentials['tokenEndpointAuthMethod'];
export type OAuthClientCredentials = WorkerClientCredentials;

export interface AuthorizationResult {
  code: string;
  issuer: string | null;
  redirect: URL;
  state: string;
}

export interface OAuthTokenSet {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  resource?: string | string[];
}

export interface DcrResponse {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  grant_types: string[];
  response_types: string[];
}

export interface ConformanceServerOptions {
  clientRegistration?: boolean;
  clientIdMetadataDocuments?: boolean;
  resource?: string;
  resourceScopes?: string[];
  externalTokenMode?: 'insufficient-scope';
}

const harness = createTestHarness({
  workers: [{ configPath: './conformance/worker/wrangler.jsonc' }],
});
const worker = harness.getWorker<ConformanceWorkerEnv, typeof import('../worker')>('mcp-oauth-conformance-worker');

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

/** Thin OAuth client for the real Worker started by createTestHarness(). */
export class McpOAuthConformanceServer {
  readonly revision: McpAuthRevision;
  readonly #configuration: WorkerConfiguration;

  constructor(revision: McpAuthRevision, options: ConformanceServerOptions = {}) {
    this.revision = revision;
    this.#configuration = {
      clientRegistration: options.clientRegistration !== false,
      clientIdMetadataDocuments: options.clientIdMetadataDocuments !== false,
      resource: options.resource ?? resourceForRevision(revision),
      resourceScopes: options.resourceScopes ?? [READ_SCOPE],
      ...(options.externalTokenMode ? { externalTokenMode: options.externalTokenMode } : {}),
    };
  }

  async request(path: string, init: RequestInit = {}): Promise<Response> {
    const url = path.startsWith('http://') || path.startsWith('https://') ? path : `${CONFORMANCE_ORIGIN}${path}`;
    const headers = new Headers(init.headers);
    headers.set(CONFIG_HEADER, btoa(JSON.stringify(this.#configuration)));
    const harnessInit = {
      redirect: 'manual',
      ...init,
      headers: Object.fromEntries(headers.entries()),
    } as unknown as Parameters<typeof harness.fetch>[1];
    return (await harness.fetch(url, harnessInit)) as unknown as Response;
  }

  async createClient(tokenEndpointAuthMethod: TokenEndpointAuthMethod = 'none'): Promise<OAuthClientCredentials> {
    const client = await (await worker.getExport()).createClient(this.#configuration, tokenEndpointAuthMethod);
    return { ...client };
  }

  async registerClient(tokenEndpointAuthMethod: TokenEndpointAuthMethod = 'none'): Promise<DcrResponse> {
    const response = await this.request('/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'MCP conformance DCR client',
        redirect_uris: [CLIENT_REDIRECT_URI],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: tokenEndpointAuthMethod,
      }),
    });
    assertStatus(response, 201, 'dynamic client registration');
    return readJson<DcrResponse>(response);
  }

  async authorize(
    client: OAuthClientCredentials,
    options: {
      codeVerifier?: string;
      resource?: string;
      scope?: string;
      state?: string;
    } = {}
  ): Promise<AuthorizationResult> {
    const codeVerifier = options.codeVerifier ?? 'conformance-code-verifier-that-is-at-least-43-characters';
    const state = options.state ?? 'mcp-conformance-state';
    const challenge = await createS256Challenge(codeVerifier);
    const resource = options.resource ?? resourceForRevision(this.revision);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: options.scope ?? READ_SCOPE,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    if (resource) params.set('resource', resource);

    const response = await this.request(`/authorize?${params}`);
    assertStatus(response, 302, 'authorization request');
    const location = response.headers.get('Location');
    if (!location) throw new Error('authorization response did not include Location');

    const redirect = new URL(location);
    const code = redirect.searchParams.get('code');
    if (!code) throw new Error(`authorization response did not include code: ${location}`);

    return {
      code,
      issuer: redirect.searchParams.get('iss'),
      redirect,
      state,
    };
  }

  async exchangeAuthorizationCode(
    client: OAuthClientCredentials,
    authorization: AuthorizationResult,
    options: {
      codeVerifier?: string;
      resource?: string;
      scope?: string;
    } = {}
  ): Promise<{ response: Response; tokens?: OAuthTokenSet }> {
    const resource = options.resource ?? resourceForRevision(this.revision);
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: authorization.code,
      redirect_uri: client.redirectUri,
      code_verifier: options.codeVerifier ?? 'conformance-code-verifier-that-is-at-least-43-characters',
    });
    if (resource) body.set('resource', resource);
    if (options.scope) body.set('scope', options.scope);

    const headers = new Headers({ 'Content-Type': 'application/x-www-form-urlencoded' });
    applyClientAuthentication(body, headers, client);
    const response = await this.request('/oauth/token', { method: 'POST', headers, body });
    const tokens = response.ok ? await readJson<OAuthTokenSet>(response.clone()) : undefined;
    return { response, tokens };
  }

  async completeAuthorizationCodeFlow(
    client: OAuthClientCredentials,
    options: {
      codeVerifier?: string;
      resource?: string;
      scope?: string;
    } = {}
  ): Promise<{ authorization: AuthorizationResult; response: Response; tokens: OAuthTokenSet }> {
    const authorization = await this.authorize(client, options);
    const { response, tokens } = await this.exchangeAuthorizationCode(client, authorization, options);
    assertStatus(response, 200, 'authorization code exchange');
    if (!tokens) throw new Error('token response did not contain a token set');
    return { authorization, response, tokens };
  }

  async refresh(
    client: OAuthClientCredentials,
    refreshToken: string,
    options: { resource?: string; scope?: string } = {}
  ): Promise<{ response: Response; tokens?: OAuthTokenSet }> {
    const resource = options.resource ?? resourceForRevision(this.revision);
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });
    if (resource) body.set('resource', resource);
    if (options.scope) body.set('scope', options.scope);

    const headers = new Headers({ 'Content-Type': 'application/x-www-form-urlencoded' });
    applyClientAuthentication(body, headers, client);
    const response = await this.request('/oauth/token', { method: 'POST', headers, body });
    const tokens = response.ok ? await readJson<OAuthTokenSet>(response.clone()) : undefined;
    return { response, tokens };
  }

  async revoke(client: OAuthClientCredentials, token: string, tokenTypeHint?: string): Promise<Response> {
    const body = new URLSearchParams({ token });
    if (tokenTypeHint) body.set('token_type_hint', tokenTypeHint);
    const headers = new Headers({ 'Content-Type': 'application/x-www-form-urlencoded' });
    applyClientAuthentication(body, headers, client);
    return this.request('/oauth/token', { method: 'POST', headers, body });
  }
}

function applyClientAuthentication(body: URLSearchParams, headers: Headers, client: OAuthClientCredentials): void {
  if (client.tokenEndpointAuthMethod === 'client_secret_post') {
    body.set('client_id', client.clientId);
    if (client.clientSecret) body.set('client_secret', client.clientSecret);
    return;
  }

  if (client.clientSecret) {
    headers.set('Authorization', `Basic ${btoa(`${client.clientId}:${client.clientSecret}`)}`);
  } else {
    body.set('client_id', client.clientId);
  }
}

export async function createS256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const bytes = new Uint8Array(digest);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function readJson<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}

export function assertStatus(response: Response, expected: number, operation: string): void {
  if (response.status !== expected) {
    throw new Error(`${operation} returned ${response.status}; expected ${expected}`);
  }
}
