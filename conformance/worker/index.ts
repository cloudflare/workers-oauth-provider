import { WorkerEntrypoint } from 'cloudflare:workers';
import {
  AuthorizationError,
  ExternalTokenError,
  OAuthProvider,
  getOAuthApi,
  type OAuthHelpers,
  type OAuthProviderOptions,
} from '../../src/oauth-provider';
import {
  CLIENT_REDIRECT_URI,
  DENIED_SCOPE,
  INSUFFICIENT_SCOPE_TOKEN,
  OFFLINE_ACCESS_SCOPE,
  READ_SCOPE,
  WRITE_SCOPE,
  type OAuthClientCredentials,
  type TokenEndpointAuthMethod,
  type WorkerConfiguration,
} from '../shared';

export interface ConformanceWorkerEnv {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER?: OAuthHelpers;
}

const apiHandler = {
  fetch: (request: Request, _env: ConformanceWorkerEnv, ctx: ExecutionContext) =>
    Response.json({
      authenticated: true,
      protocolVersion: request.headers.get('MCP-Protocol-Version'),
      props: ctx.props,
    }),
};

function createProviderOptions(configuration: WorkerConfiguration): OAuthProviderOptions<ConformanceWorkerEnv> {
  return {
    apiRoute: ['/mcp', '/other-resource'],
    apiHandler,
    defaultHandler: {
      fetch: async (request, env) => {
        if (new URL(request.url).pathname !== '/authorize') return new Response('Not found', { status: 404 });

        try {
          if (!env.OAUTH_PROVIDER) throw new Error('OAuth helpers were not injected');
          const authorizationRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
          if (authorizationRequest.scope.includes(DENIED_SCOPE)) {
            const redirect = new URL(authorizationRequest.redirectUri);
            redirect.searchParams.set('error', 'access_denied');
            if (authorizationRequest.state) redirect.searchParams.set('state', authorizationRequest.state);
            if (authorizationRequest.issuer) redirect.searchParams.set('iss', authorizationRequest.issuer);
            return Response.redirect(redirect.toString(), 302);
          }

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
              error: error instanceof AuthorizationError ? error.code : 'invalid_request',
              error_description: error instanceof Error ? error.message : String(error),
            },
            { status: 400 }
          );
        }
      },
    },
    authorizeEndpoint: '/authorize',
    tokenEndpoint: '/oauth/token',
    clientRegistrationEndpoint: configuration.dynamicClientRegistration ? '/oauth/register' : undefined,
    scopesSupported: [READ_SCOPE, WRITE_SCOPE, OFFLINE_ACCESS_SCOPE],
    clientIdMetadataDocumentEnabled: true,
    resourceMetadata: {
      ...(configuration.resource ? { resource: configuration.resource } : {}),
      authorization_servers: [configuration.origin],
      scopes_supported: configuration.resourceScopes,
      bearer_methods_supported: ['header'],
      resource_name: 'MCP auth conformance server',
    },
    resolveExternalToken: async ({ token }) => {
      if (token !== INSUFFICIENT_SCOPE_TOKEN) return null;
      throw new ExternalTokenError('insufficient_scope', {
        description: 'A write scope is required',
        statusCode: 403,
        requiredScopes: [READ_SCOPE, WRITE_SCOPE, WRITE_SCOPE],
      });
    },
  };
}

let configuration: WorkerConfiguration | undefined;
let provider: OAuthProvider<ConformanceWorkerEnv> | undefined;

function requireConfiguration(): WorkerConfiguration {
  if (!configuration) throw new Error('Configure the conformance Worker before use');
  return configuration;
}

function requireProvider(): OAuthProvider<ConformanceWorkerEnv> {
  if (!provider) throw new Error('Configure the conformance Worker before use');
  return provider;
}

export default class McpOAuthConformanceWorker extends WorkerEntrypoint<ConformanceWorkerEnv> {
  configure(nextConfiguration: WorkerConfiguration): void {
    configuration = nextConfiguration;
    provider = new OAuthProvider(createProviderOptions(nextConfiguration));
    this.env.OAUTH_PROVIDER = undefined;
  }

  async fetch(request: Request): Promise<Response> {
    // The harness listens over local HTTP. Normalize requests to the public
    // HTTPS origin so metadata matches a deployed Worker.
    const incomingUrl = new URL(request.url);
    const publicRequest = new Request(
      `${requireConfiguration().origin}${incomingUrl.pathname}${incomingUrl.search}`,
      request
    );
    return requireProvider().fetch(publicRequest, this.env, this.ctx);
  }

  async createClient(
    tokenEndpointAuthMethod: TokenEndpointAuthMethod,
    redirectUri = CLIENT_REDIRECT_URI
  ): Promise<OAuthClientCredentials> {
    const client = await getOAuthApi(createProviderOptions(requireConfiguration()), this.env).createClient({
      clientName: 'MCP conformance client',
      redirectUris: [redirectUri],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      tokenEndpointAuthMethod,
    });

    return {
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUri,
      tokenEndpointAuthMethod,
    };
  }
}
