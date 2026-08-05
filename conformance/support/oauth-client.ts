import { clientResourceForRevision, type McpAuthRevision } from '../spec-versions';
import {
  CLIENT_REDIRECT_URI,
  CONFORMANCE_ORIGIN,
  DENIED_SCOPE,
  INSUFFICIENT_SCOPE_TOKEN,
  MCP_RESOURCE,
  OFFLINE_ACCESS_SCOPE,
  READ_SCOPE,
  WRITE_SCOPE,
  type OAuthClientCredentials,
  type TokenEndpointAuthMethod,
  type WorkerConfiguration,
} from '../shared';
import { harness, worker, type HarnessResponse } from './harness';

type WorkerApi = Awaited<ReturnType<typeof worker.getExport>>;

export {
  CLIENT_REDIRECT_URI,
  CONFORMANCE_ORIGIN,
  DENIED_SCOPE,
  INSUFFICIENT_SCOPE_TOKEN,
  MCP_RESOURCE,
  OFFLINE_ACCESS_SCOPE,
  READ_SCOPE,
  WRITE_SCOPE,
  type OAuthClientCredentials,
};

const DEFAULT_CODE_VERIFIER = 'conformance-code-verifier-that-is-at-least-43-characters';
const FORM_CONTENT_TYPE = 'application/x-www-form-urlencoded';

type RequestHeaders = Record<string, string>;

interface RequestOptions {
  method?: 'POST';
  headers?: RequestHeaders;
  body?: string | URLSearchParams;
}

interface AuthorizationResult {
  code: string;
  redirect: URL;
  state: string;
}

interface OAuthTokenSet {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  resource?: string | string[];
}

interface DcrResponse {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  grant_types: string[];
  response_types: string[];
}

interface ConformanceClientOptions {
  dynamicClientRegistration?: boolean;
  resourcePolicy?: 'compatible' | 'canonical';
  resourceScopes?: string[];
}

interface TokenResult {
  response: HarnessResponse;
  tokens?: OAuthTokenSet;
}

export async function createMcpOAuthClient(
  revision: McpAuthRevision,
  options: ConformanceClientOptions = {}
): Promise<McpOAuthClient> {
  const clientResource = clientResourceForRevision(revision);
  const configuration: WorkerConfiguration = {
    dynamicClientRegistration: options.dynamicClientRegistration !== false,
    origin: CONFORMANCE_ORIGIN,
    resource: options.resourcePolicy === 'canonical' ? MCP_RESOURCE : undefined,
    resourceScopes: options.resourceScopes ?? [READ_SCOPE],
  };
  const api = await worker.getExport();
  await api.configure(configuration);
  return new McpOAuthClient(revision, clientResource, api);
}

/** OAuth client for the real Worker started by createTestHarness(). */
class McpOAuthClient {
  constructor(
    private readonly revision: McpAuthRevision,
    private readonly resource: string | undefined,
    private readonly api: WorkerApi
  ) {}

  request(path: `/${string}`, options: RequestOptions = {}): Promise<HarnessResponse> {
    return harness.fetch(`${CONFORMANCE_ORIGIN}${path}`, {
      redirect: 'manual',
      method: options.method,
      headers: { 'MCP-Protocol-Version': this.revision, ...options.headers },
      body: options.body?.toString(),
    });
  }

  async createClient(tokenEndpointAuthMethod: TokenEndpointAuthMethod = 'none'): Promise<OAuthClientCredentials> {
    return { ...(await this.api.createClient(tokenEndpointAuthMethod)) };
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
    const codeVerifier = options.codeVerifier ?? DEFAULT_CODE_VERIFIER;
    const state = options.state ?? 'mcp-conformance-state';
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: options.scope ?? READ_SCOPE,
      state,
      code_challenge: await createS256Challenge(codeVerifier),
      code_challenge_method: 'S256',
    });
    const resource = options.resource ?? this.resource;
    if (resource) params.set('resource', resource);

    const response = await this.request(`/authorize?${params}`);
    assertStatus(response, 302, 'authorization request');
    const location = response.headers.get('Location');
    if (!location) throw new Error('authorization response did not include Location');

    const redirect = new URL(location);
    const code = redirect.searchParams.get('code');
    if (!code) throw new Error(`authorization response did not include code: ${location}`);

    return { code, redirect, state };
  }

  exchangeAuthorizationCode(
    client: OAuthClientCredentials,
    authorization: AuthorizationResult,
    options: { codeVerifier?: string; resource?: string; scope?: string } = {}
  ): Promise<TokenResult> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: authorization.code,
      redirect_uri: client.redirectUri,
      code_verifier: options.codeVerifier ?? DEFAULT_CODE_VERIFIER,
    });
    this.addResourceAndScope(body, options);
    return this.postToken(client, body);
  }

  async completeAuthorizationCodeFlow(
    client: OAuthClientCredentials,
    options: { codeVerifier?: string; resource?: string; scope?: string } = {}
  ): Promise<{ authorization: AuthorizationResult; response: HarnessResponse; tokens: OAuthTokenSet }> {
    const authorization = await this.authorize(client, options);
    const { response, tokens } = await this.exchangeAuthorizationCode(client, authorization, options);
    assertStatus(response, 200, 'authorization code exchange');
    if (!tokens) throw new Error('token response did not contain a token set');
    return { authorization, response, tokens };
  }

  refresh(
    client: OAuthClientCredentials,
    refreshToken: string,
    options: { resource?: string; scope?: string } = {}
  ): Promise<TokenResult> {
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });
    this.addResourceAndScope(body, options);
    return this.postToken(client, body);
  }

  revoke(client: OAuthClientCredentials, token: string, tokenTypeHint?: string): Promise<HarnessResponse> {
    const body = new URLSearchParams({ token });
    if (tokenTypeHint) body.set('token_type_hint', tokenTypeHint);
    return this.request('/oauth/token', {
      method: 'POST',
      headers: authenticateClient(body, client),
      body,
    });
  }

  private addResourceAndScope(body: URLSearchParams, options: { resource?: string; scope?: string }): void {
    const resource = options.resource ?? this.resource;
    if (resource) body.set('resource', resource);
    if (options.scope) body.set('scope', options.scope);
  }

  private async postToken(client: OAuthClientCredentials, body: URLSearchParams): Promise<TokenResult> {
    const response = await this.request('/oauth/token', {
      method: 'POST',
      headers: authenticateClient(body, client),
      body,
    });
    return {
      response,
      tokens: response.ok ? await readJson<OAuthTokenSet>(response.clone()) : undefined,
    };
  }
}

export type { McpOAuthClient };

function authenticateClient(body: URLSearchParams, client: OAuthClientCredentials): RequestHeaders {
  const headers: RequestHeaders = { 'Content-Type': FORM_CONTENT_TYPE };
  if (client.tokenEndpointAuthMethod === 'client_secret_post') {
    body.set('client_id', client.clientId);
    if (client.clientSecret) body.set('client_secret', client.clientSecret);
  } else if (client.tokenEndpointAuthMethod === 'client_secret_basic' && client.clientSecret) {
    headers.Authorization = `Basic ${btoa(`${client.clientId}:${client.clientSecret}`)}`;
  } else {
    body.set('client_id', client.clientId);
  }
  return headers;
}

async function createS256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const bytes = new Uint8Array(digest);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function readJson<T>(response: Pick<HarnessResponse, 'json'>): Promise<T> {
  return (await response.json()) as T;
}

function assertStatus(response: Pick<HarnessResponse, 'status'>, expected: number, operation: string): void {
  if (response.status !== expected) {
    throw new Error(`${operation} returned ${response.status}; expected ${expected}`);
  }
}
