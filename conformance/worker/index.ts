import { WorkerEntrypoint } from 'cloudflare:workers';
import {
  AuthorizationError,
  type AuthorizationServerBinding,
  ExternalTokenError,
  OAuthAuthorizationServer,
  OAuthProvider,
  OAuthResourceServer,
  getOAuthApi,
  insufficientScope,
  type OAuthHelpers,
  type OAuthResourceAuth,
  type OAuthProviderOptions,
} from '../../src/oauth-provider';
import {
  CLIENT_REDIRECT_URI,
  DENIED_SCOPE,
  FOREIGN_AUDIENCE_TOKEN,
  FOREIGN_RESOURCE,
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
  /** This Worker, over a Service Binding, as a separate resource Worker would hold it. */
  AUTH_SERVER: AuthorizationServerBinding<{ subject: string }>;
}

/** What the resource-server probe returns to the test. */
export interface ResourceServerProbe {
  status: number;
  body: { subject?: string; auth?: OAuthResourceAuth } | null;
  challenge: string | null;
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
    apiRoute: ['/mcp'],
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
      resource: configuration.resource,
      authorization_servers: [configuration.origin],
      scopes_supported: configuration.resourceScopes,
      bearer_methods_supported: ['header'],
      resource_name: 'MCP auth conformance server',
    },
    resolveExternalToken: async ({ token }) => {
      // A valid upstream credential issued for another resource: the provider must reject it
      // because its audience is not this server's canonical resource.
      if (token === FOREIGN_AUDIENCE_TOKEN) return { props: { userId: 'foreign-user' }, audience: FOREIGN_RESOURCE };
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
let authorizationServer: OAuthAuthorizationServer<ConformanceWorkerEnv> | undefined;

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
    // The role-based server over the same KV: tokens the combined provider issues are the
    // tokens it validates for a separate resource Worker.
    authorizationServer = new OAuthAuthorizationServer<ConformanceWorkerEnv>({
      issuer: nextConfiguration.origin,
      resources: [nextConfiguration.resource],
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
    });
    this.env.OAUTH_PROVIDER = undefined;
  }

  /** RPC: what a separate resource Worker calls over its Service Binding. */
  validateToken(resource: string, token: string) {
    if (!authorizationServer) throw new Error('Configure the conformance Worker before use');
    return authorizationServer.validateToken(resource, token, this.env);
  }

  /**
   * Run a resource server whose validator is `env.AUTH_SERVER.validateToken`, the detached RPC
   * stub the documentation hands to `OAuthResourceServer`, and report what it answered. The
   * handler echoes `ctx.props` and `ctx.auth`, and refuses a write the token's scopes do not
   * cover with the MCP `insufficient_scope` challenge.
   */
  async probeResourceServerOverBinding(token: string | undefined, method = 'GET'): Promise<ResourceServerProbe> {
    const { origin, resource, resourceScopes } = requireConfiguration();
    const resourceServer = new OAuthResourceServer<ConformanceWorkerEnv, { subject: string }>({
      resourceMetadata: { resource, authorization_servers: [origin], scopes_supported: resourceScopes },
      validateToken: (env) => env.AUTH_SERVER.validateToken,
      handler: {
        fetch: (request, _env, ctx) => {
          if (request.method === 'DELETE' && !ctx.auth.scope.includes(WRITE_SCOPE)) {
            return insufficientScope(ctx.auth, [WRITE_SCOPE]);
          }
          return Response.json({ ...ctx.props, auth: ctx.auth });
        },
      },
    });
    const response = await resourceServer.fetch(
      new Request(resource, { method, headers: token === undefined ? {} : { Authorization: `Bearer ${token}` } }),
      this.env,
      this.ctx
    );
    return {
      status: response.status,
      body: response.status === 200 ? await response.json<{ subject?: string; auth?: OAuthResourceAuth }>() : null,
      challenge: response.headers.get('WWW-Authenticate'),
    };
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
