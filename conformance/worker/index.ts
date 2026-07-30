import { WorkerEntrypoint } from 'cloudflare:workers';
import {
  ExternalTokenError,
  OAuthProvider,
  getOAuthApi,
  type OAuthHelpers,
  type OAuthProviderOptions,
} from '../../src/oauth-provider';

const CONFIG_HEADER = 'x-mcp-conformance-config';
const CLIENT_REDIRECT_URI = 'https://client.example.com/callback';
const READ_SCOPE = 'mcp:read';
const WRITE_SCOPE = 'mcp:write';
const OFFLINE_ACCESS_SCOPE = 'offline_access';

export interface ConformanceWorkerEnv {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER?: OAuthHelpers;
  PUBLIC_ORIGIN: string;
}

export interface WorkerConfiguration {
  clientRegistration: boolean;
  clientIdMetadataDocuments: boolean;
  resource?: string;
  resourceScopes: string[];
  externalTokenMode?: 'insufficient-scope';
}

export interface WorkerClientCredentials {
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  tokenEndpointAuthMethod: 'none' | 'client_secret_basic' | 'client_secret_post';
}

const apiHandler = {
  fetch: (_request: Request, _env: ConformanceWorkerEnv, ctx: ExecutionContext) =>
    Response.json({ authenticated: true, props: ctx.props }),
};

function decodeConfiguration(request: Request): WorkerConfiguration {
  const encoded = request.headers.get(CONFIG_HEADER);
  if (!encoded) throw new Error(`Missing ${CONFIG_HEADER} header`);
  return JSON.parse(atob(encoded)) as WorkerConfiguration;
}

function createProviderOptions(configuration: WorkerConfiguration): OAuthProviderOptions<ConformanceWorkerEnv> {
  return {
    apiRoute: ['/mcp', '/other-resource'],
    apiHandler,
    defaultHandler: {
      fetch: async (request, env) => {
        if (new URL(request.url).pathname !== '/authorize') {
          return new Response('Not found', { status: 404 });
        }

        try {
          if (!env.OAUTH_PROVIDER) throw new Error('OAuth helpers were not injected');
          const authorizationRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
          const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
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
    clientRegistrationEndpoint: configuration.clientRegistration ? '/oauth/register' : undefined,
    scopesSupported: [READ_SCOPE, WRITE_SCOPE, OFFLINE_ACCESS_SCOPE],
    allowPlainPKCE: false,
    clientIdMetadataDocumentEnabled: configuration.clientIdMetadataDocuments,
    ...(configuration.resource
      ? {
          resourceMetadata: {
            resource: configuration.resource,
            authorization_servers: ['https://mcp.example.com'],
            scopes_supported: configuration.resourceScopes,
            bearer_methods_supported: ['header'],
            resource_name: 'MCP auth conformance server',
          },
        }
      : {}),
    ...(configuration.externalTokenMode === 'insufficient-scope'
      ? {
          resolveExternalToken: async () => {
            throw new ExternalTokenError('insufficient_scope', {
              description: 'A write scope is required',
              statusCode: 403,
              requiredScopes: [READ_SCOPE, WRITE_SCOPE, WRITE_SCOPE],
            });
          },
        }
      : {}),
  };
}

export default class McpOAuthConformanceWorker extends WorkerEntrypoint<ConformanceWorkerEnv> {
  async fetch(request: Request): Promise<Response> {
    const configuration = decodeConfiguration(request);
    // The harness listens over local HTTP. Normalize requests to the public
    // HTTPS origin so metadata matches a deployed Worker.
    const incomingUrl = new URL(request.url);
    const publicRequest = new Request(`${this.env.PUBLIC_ORIGIN}${incomingUrl.pathname}${incomingUrl.search}`, request);
    return new OAuthProvider(createProviderOptions(configuration)).fetch(publicRequest, this.env, this.ctx);
  }

  async createClient(
    configuration: WorkerConfiguration,
    tokenEndpointAuthMethod: WorkerClientCredentials['tokenEndpointAuthMethod']
  ): Promise<WorkerClientCredentials> {
    const client = await getOAuthApi(createProviderOptions(configuration), this.env).createClient({
      clientName: 'MCP conformance client',
      redirectUris: [CLIENT_REDIRECT_URI],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      tokenEndpointAuthMethod,
    });

    return {
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUri: CLIENT_REDIRECT_URI,
      tokenEndpointAuthMethod,
    };
  }
}
