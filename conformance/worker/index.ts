import { WorkerEntrypoint } from 'cloudflare:workers';
import {
  AuthorizationError,
  createJwtAccessTokens,
  ExternalTokenError,
  OAuthProvider,
  getOAuthApi,
  type OAuthHelpers,
  type OAuthProviderOptions,
  type JwtAccessTokenAlgorithm,
  type JwtAccessTokenPublicKey,
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
      resource: configuration.resource,
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
  /** Exercise signing and verification in real workerd WebCrypto, not Node's test implementation. */
  async roundTripJwt(algorithm: JwtAccessTokenAlgorithm): Promise<{
    header: Record<string, unknown>;
    verified: boolean;
  }> {
    const keyPair = (await crypto.subtle.generateKey(
      algorithm === 'RS256'
        ? {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
          }
        : { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair;
    const publicJwk = {
      ...((await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey),
      kid: `workerd-${algorithm}`,
      alg: algorithm,
      use: 'sig',
      key_ops: ['verify'],
    } satisfies JwtAccessTokenPublicKey;
    const issuer = 'https://auth.workerd.test';
    const audience = 'https://resource.workerd.test/mcp';
    const accessTokens = createJwtAccessTokens<ConformanceWorkerEnv, { secret: string }>({
      issuer,
      jwksUri: `${issuer}/.well-known/jwks.json`,
      keys: () => ({
        current: { kid: publicJwk.kid, alg: algorithm, privateKey: keyPair.privateKey, publicJwk },
      }),
    });
    const now = Math.floor(Date.now() / 1000);
    const issued = await accessTokens.issue({
      props: { secret: 'not-in-the-jwt' },
      userId: 'workerd-user',
      grantId: 'workerd-grant',
      clientId: 'workerd-client',
      scope: ['mcp:read'],
      audience,
      issuedAt: now,
      expiresAt: now + 300,
      env: this.env,
    });
    const encodedHeader = issued.token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/');
    const header = JSON.parse(atob(encodedHeader.padEnd(Math.ceil(encodedHeader.length / 4) * 4, '=')));
    return {
      header,
      verified: (await accessTokens.verify(issued.token, [audience], this.env))?.userId === 'workerd-user',
    };
  }

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
