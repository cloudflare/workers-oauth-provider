import type { ExecutionContext } from '@cloudflare/workers-types';
import { OAuthProvider, type ClientInfo, type OAuthHelpers, type OAuthProviderOptions } from '../../src/oauth-provider';
import { resourceForRevision, type McpAuthRevision } from '../spec-versions';

export const CONFORMANCE_ORIGIN = 'https://mcp.example.com';
export const MCP_RESOURCE = `${CONFORMANCE_ORIGIN}/mcp`;
export const CLIENT_REDIRECT_URI = 'https://client.example.com/callback';
export const READ_SCOPE = 'mcp:read';
export const WRITE_SCOPE = 'mcp:write';
export const OFFLINE_ACCESS_SCOPE = 'offline_access';

interface StoredValue {
  value: string | ArrayBuffer;
  expiresAt?: number;
}

interface KvPutOptions {
  expiration?: number;
  expirationTtl?: number;
}

interface KvGetOptions {
  type?: 'text' | 'json' | 'arrayBuffer' | 'stream';
}

interface KvListOptions {
  prefix?: string;
  limit?: number;
  cursor?: string;
}

interface KvListResult {
  keys: Array<{ name: string }>;
  list_complete: boolean;
  cursor?: string;
}

/** In-memory KV implementation used only by the black-box conformance server. */
export class ConformanceKV {
  readonly #values = new Map<string, StoredValue>();

  async put(key: string, value: string | ArrayBuffer, options: KvPutOptions = {}): Promise<void> {
    const now = Date.now();
    const expiresAt = options.expirationTtl
      ? now + options.expirationTtl * 1_000
      : options.expiration
        ? options.expiration * 1_000
        : undefined;

    this.#values.set(key, { value, expiresAt });
  }

  async get(key: string, options: KvGetOptions = {}): Promise<unknown> {
    const entry = this.#values.get(key);
    if (!entry) return null;

    if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      this.#values.delete(key);
      return null;
    }

    if (options.type === 'json') {
      const text = typeof entry.value === 'string' ? entry.value : new TextDecoder().decode(entry.value);
      return JSON.parse(text) as unknown;
    }

    if (options.type === 'arrayBuffer') {
      return typeof entry.value === 'string' ? new TextEncoder().encode(entry.value).buffer : entry.value;
    }

    return entry.value;
  }

  async delete(key: string): Promise<void> {
    this.#values.delete(key);
  }

  async list(options: KvListOptions = {}): Promise<KvListResult> {
    const prefix = options.prefix ?? '';
    const limit = options.limit ?? 1_000;
    const offset = options.cursor ? Number.parseInt(options.cursor, 10) : 0;
    const names = [...this.#values.keys()].filter((key) => key.startsWith(prefix)).sort();
    const page = names.slice(offset, offset + limit);
    const nextOffset = offset + page.length;
    const listComplete = nextOffset >= names.length;

    return {
      keys: page.map((name) => ({ name })),
      list_complete: listComplete,
      ...(listComplete ? {} : { cursor: String(nextOffset) }),
    };
  }
}

export interface ConformanceEnv {
  OAUTH_KV: ConformanceKV;
  OAUTH_PROVIDER?: OAuthHelpers;
}

class ConformanceExecutionContext implements ExecutionContext {
  props: Record<string, unknown> = {};

  waitUntil(_promise: Promise<unknown>): void {}

  passThroughOnException(): void {}
}

interface CloudflareGlobal {
  compatibilityFlags?: {
    global_fetch_strictly_public?: boolean;
  };
}

type GlobalWithCloudflare = typeof globalThis & { Cloudflare?: CloudflareGlobal };

export type TokenEndpointAuthMethod = 'none' | 'client_secret_basic' | 'client_secret_post';

export interface OAuthClientCredentials {
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
}

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
  resolveExternalToken?: OAuthProviderOptions<ConformanceEnv>['resolveExternalToken'];
}

/**
 * Public-interface harness for an OAuthProvider configured as an MCP resource
 * server and co-located authorization server.
 */
export class McpOAuthConformanceServer {
  readonly env: ConformanceEnv;
  readonly provider: OAuthProvider<ConformanceEnv>;
  readonly revision: McpAuthRevision;

  readonly #previousCloudflare: CloudflareGlobal | undefined;

  constructor(revision: McpAuthRevision, options: ConformanceServerOptions = {}) {
    this.revision = revision;
    this.env = { OAUTH_KV: new ConformanceKV() };

    const globalObject = globalThis as GlobalWithCloudflare;
    this.#previousCloudflare = globalObject.Cloudflare;
    globalObject.Cloudflare = {
      ...globalObject.Cloudflare,
      compatibilityFlags: {
        ...globalObject.Cloudflare?.compatibilityFlags,
        global_fetch_strictly_public: true,
      },
    };

    const configuredResource = options.resource ?? resourceForRevision(revision);
    const clientRegistrationEndpoint = options.clientRegistration === false ? undefined : '/oauth/register';

    this.provider = new OAuthProvider<ConformanceEnv>({
      apiRoute: ['/mcp', '/other-resource'],
      apiHandler: {
        fetch: (_request, _env, context) =>
          Response.json({ authenticated: true, props: (context as ConformanceExecutionContext).props }),
      },
      defaultHandler: {
        fetch: async (request, env) => {
          const url = new URL(request.url);
          if (url.pathname !== '/authorize') return new Response('Not found', { status: 404 });

          try {
            const helpers = requireHelpers(env);
            const authorizationRequest = await helpers.parseAuthRequest(request);
            const { redirectTo } = await helpers.completeAuthorization({
              request: authorizationRequest,
              userId: 'conformance-user',
              metadata: { suite: 'mcp-auth-conformance' },
              scope: authorizationRequest.scope,
              props: { subject: 'conformance-user' },
            });
            return Response.redirect(redirectTo, 302);
          } catch (error) {
            return Response.json(
              {
                error: 'invalid_request',
                error_description: error instanceof Error ? error.message : String(error),
              },
              { status: 400 }
            );
          }
        },
      },
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      clientRegistrationEndpoint,
      scopesSupported: [READ_SCOPE, WRITE_SCOPE, OFFLINE_ACCESS_SCOPE],
      allowPlainPKCE: false,
      clientIdMetadataDocumentEnabled: options.clientIdMetadataDocuments ?? true,
      ...(configuredResource
        ? {
            resourceMetadata: {
              resource: configuredResource,
              authorization_servers: [CONFORMANCE_ORIGIN],
              scopes_supported: options.resourceScopes ?? [READ_SCOPE],
              bearer_methods_supported: ['header'],
              resource_name: 'MCP auth conformance server',
            },
          }
        : {}),
      ...(options.resolveExternalToken ? { resolveExternalToken: options.resolveExternalToken } : {}),
    });
  }

  dispose(): void {
    (globalThis as GlobalWithCloudflare).Cloudflare = this.#previousCloudflare;
  }

  async request(path: string, init: RequestInit = {}): Promise<Response> {
    const url = path.startsWith('http://') || path.startsWith('https://') ? path : `${CONFORMANCE_ORIGIN}${path}`;
    return this.provider.fetch(new Request(url, init), this.env, new ConformanceExecutionContext());
  }

  async helpers(): Promise<OAuthHelpers> {
    if (!this.env.OAUTH_PROVIDER) await this.request('/');
    return requireHelpers(this.env);
  }

  async createClient(tokenEndpointAuthMethod: TokenEndpointAuthMethod = 'none'): Promise<OAuthClientCredentials> {
    const helpers = await this.helpers();
    const client = await helpers.createClient({
      clientName: 'MCP conformance client',
      redirectUris: [CLIENT_REDIRECT_URI],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      tokenEndpointAuthMethod,
    });

    return credentialsFromClient(client, tokenEndpointAuthMethod);
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

function requireHelpers(env: ConformanceEnv): OAuthHelpers {
  if (!env.OAUTH_PROVIDER) throw new Error('OAuth helpers were not initialized');
  return env.OAUTH_PROVIDER;
}

function credentialsFromClient(
  client: ClientInfo,
  tokenEndpointAuthMethod: TokenEndpointAuthMethod
): OAuthClientCredentials {
  return {
    clientId: client.clientId,
    clientSecret: client.clientSecret,
    redirectUri: CLIENT_REDIRECT_URI,
    tokenEndpointAuthMethod,
  };
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
