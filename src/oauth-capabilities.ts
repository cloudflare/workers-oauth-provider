const OAUTH_SCOPE_TOKEN_PATTERN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export type AuthorizationErrorCode =
  | 'invalid_request'
  | 'invalid_target'
  | 'unauthorized_client'
  | 'access_denied'
  | 'unsupported_response_type'
  | 'invalid_scope'
  | 'server_error'
  | 'temporarily_unavailable';

export interface AuthorizationErrorOptions {
  /** Wire-safe OAuth authorization error description. */
  description: string;
  /** Exact registered redirect URI. Present only after client and redirect validation. */
  redirectUri?: string;
  /** Original client state, when supplied. */
  state?: string;
  /** Authorization server issuer for RFC 9207 error responses. */
  issuer?: string;
}

/**
 * Expected authorization-request validation failure. Absence of `redirectUri`
 * means a caller MUST render locally and MUST NOT redirect.
 */
export class AuthorizationError extends Error {
  public readonly code: AuthorizationErrorCode;
  public readonly description: string;
  public readonly redirectUri?: string;
  public readonly state?: string;
  public readonly issuer?: string;

  constructor(code: AuthorizationErrorCode, options: AuthorizationErrorOptions) {
    super(options.description);
    this.name = 'AuthorizationError';
    this.code = code;
    this.description = options.description;
    this.redirectUri = options.redirectUri;
    this.state = options.state;
    this.issuer = options.issuer;
  }
}

/** @internal Attach context after exact client redirect validation succeeds. */
export function withAuthorizationRedirect(
  error: AuthorizationError,
  redirectUri: string,
  state: string | undefined,
  issuer: string
): AuthorizationError {
  return new AuthorizationError(error.code, {
    description: error.description,
    redirectUri,
    state,
    issuer,
  });
}

/** PKCE transformation methods implemented by the authorization server. */
export type PkceCodeChallengeMethod = 'plain' | 'S256';

export interface OAuthServerCapabilities {
  readonly grantTypes: readonly string[];
  readonly responseTypes: readonly string[];
  readonly tokenEndpointAuthMethods: readonly string[];
  readonly codeChallengeMethods: readonly PkceCodeChallengeMethod[];
}

export interface ClientCapabilities {
  readonly grantTypes: readonly string[];
  readonly responseTypes: readonly string[];
  readonly tokenEndpointAuthMethod: string;
}

/** Client-advertised capabilities parsed from OAuth client metadata. */
export interface ClientMetadataCapabilities {
  readonly grantTypes: readonly string[];
  readonly responseTypes: readonly string[];
  readonly tokenEndpointAuthMethod?: string;
  readonly tokenEndpointAuthMethodsSupported?: readonly string[];
}

export function buildOAuthServerCapabilities(options: {
  allowImplicitFlow: boolean;
  allowPlainPKCE: boolean;
  allowTokenExchangeGrant: boolean;
  enterpriseManagedAuthorization: boolean;
}): OAuthServerCapabilities {
  return {
    grantTypes: [
      'authorization_code',
      'refresh_token',
      ...(options.allowImplicitFlow ? ['implicit'] : []),
      ...(options.allowTokenExchangeGrant ? ['urn:ietf:params:oauth:grant-type:token-exchange'] : []),
      ...(options.enterpriseManagedAuthorization ? ['urn:ietf:params:oauth:grant-type:jwt-bearer'] : []),
    ],
    responseTypes: options.allowImplicitFlow ? ['code', 'token'] : ['code'],
    tokenEndpointAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],
    codeChallengeMethods: options.allowPlainPKCE ? ['plain', 'S256'] : ['S256'],
  };
}

export function validateClientCapabilities(server: OAuthServerCapabilities, client: ClientCapabilities): void {
  if (!server.tokenEndpointAuthMethods.includes(client.tokenEndpointAuthMethod)) {
    throw new Error(`Unsupported token_endpoint_auth_method: ${client.tokenEndpointAuthMethod}`);
  }

  const unsupportedGrant = client.grantTypes.find((grantType) => !server.grantTypes.includes(grantType));
  if (unsupportedGrant) throw new Error(`Unsupported grant_type: ${unsupportedGrant}`);

  const unsupportedResponse = client.responseTypes.find((responseType) => !server.responseTypes.includes(responseType));
  if (unsupportedResponse) throw new Error(`Unsupported response_type: ${unsupportedResponse}`);

  if (client.grantTypes.includes('authorization_code') !== client.responseTypes.includes('code')) {
    throw new Error('grant_types authorization_code and response_types code must be registered together');
  }
  if (client.grantTypes.includes('implicit') !== client.responseTypes.includes('token')) {
    throw new Error('grant_types implicit and response_types token must be registered together');
  }
}

const SHARED_SECRET_TOKEN_ENDPOINT_AUTH_METHODS = new Set([
  'client_secret_basic',
  'client_secret_post',
  'client_secret_jwt',
]);

function negotiateTokenEndpointAuthMethod(options: {
  acceptedMethods: readonly string[];
  defaultMethod: string;
  preferredMethod: string | undefined;
  supportedMethods: readonly string[] | undefined;
  context: string;
}): string {
  const { acceptedMethods, defaultMethod, preferredMethod, supportedMethods, context } = options;
  if (preferredMethod !== undefined && supportedMethods !== undefined && !supportedMethods.includes(preferredMethod)) {
    throw new Error('token_endpoint_auth_method must be included in token_endpoint_auth_methods_supported');
  }

  const advertisedMethods = supportedMethods ?? [preferredMethod ?? defaultMethod];
  const effectiveMethod =
    preferredMethod !== undefined && acceptedMethods.includes(preferredMethod)
      ? preferredMethod
      : acceptedMethods.find((method) => advertisedMethods.includes(method));

  if (effectiveMethod !== undefined) return effectiveMethod;

  const advertised = [...new Set([...(preferredMethod === undefined ? [] : [preferredMethod]), ...advertisedMethods])];
  throw new Error(
    `${context} does not support an accepted token endpoint authentication method. ` +
      `Supported methods: ${acceptedMethods.join(', ')}. ` +
      `Client advertised: ${advertised.length > 0 ? advertised.join(', ') : '(none)'}`
  );
}

function negotiateCimdTokenEndpointAuthMethod(
  server: OAuthServerCapabilities,
  preferredMethod: string | undefined,
  supportedMethods: readonly string[] | undefined
): string {
  if (preferredMethod !== undefined && SHARED_SECRET_TOKEN_ENDPOINT_AUTH_METHODS.has(preferredMethod)) {
    throw new Error(`CIMD clients cannot use symmetric token endpoint authentication method: ${preferredMethod}`);
  }

  const acceptedMethods = server.tokenEndpointAuthMethods.filter(
    (method) => !SHARED_SECRET_TOKEN_ENDPOINT_AUTH_METHODS.has(method)
  );
  return negotiateTokenEndpointAuthMethod({
    acceptedMethods,
    defaultMethod: 'none',
    preferredMethod,
    supportedMethods,
    context: 'CIMD client',
  });
}

/**
 * Negotiates choice-valued authentication metadata while keeping DCR grant and
 * response registration strict.
 */
export function negotiateDynamicClientRegistrationCapabilities(
  server: OAuthServerCapabilities,
  client: ClientMetadataCapabilities
): { grantTypes: string[]; responseTypes: string[]; tokenEndpointAuthMethod: string } {
  const effective = {
    grantTypes: [...client.grantTypes],
    responseTypes: [...client.responseTypes],
    tokenEndpointAuthMethod: negotiateTokenEndpointAuthMethod({
      acceptedMethods: server.tokenEndpointAuthMethods,
      defaultMethod: 'client_secret_basic',
      preferredMethod: client.tokenEndpointAuthMethod,
      supportedMethods: client.tokenEndpointAuthMethodsSupported,
      context: 'Client',
    }),
  };

  validateClientCapabilities(server, effective);
  return effective;
}

/**
 * Selects the capabilities from a Client ID Metadata Document that this
 * authorization server supports. CIMD documents may advertise extension
 * capabilities alongside the flow used with this server, so unsupported grant
 * and response types are omitted from the effective client metadata instead of
 * invalidating an otherwise usable client.
 *
 * The effective subset is still checked for grant/response consistency, and
 * token endpoint authentication must have a mutually supported method.
 */
export function negotiateCimdClientCapabilities(
  server: OAuthServerCapabilities,
  client: ClientMetadataCapabilities
): { grantTypes: string[]; responseTypes: string[]; tokenEndpointAuthMethod: string } {
  const effective = {
    grantTypes: client.grantTypes.filter((grantType) => server.grantTypes.includes(grantType)),
    responseTypes: client.responseTypes.filter((responseType) => server.responseTypes.includes(responseType)),
    tokenEndpointAuthMethod: negotiateCimdTokenEndpointAuthMethod(
      server,
      client.tokenEndpointAuthMethod,
      client.tokenEndpointAuthMethodsSupported
    ),
  };

  validateClientCapabilities(server, effective);
  return effective;
}

export function validateAuthorizationResponseType(
  server: OAuthServerCapabilities,
  responseType: string,
  clientResponseTypes: readonly string[] | undefined
): void {
  if (!responseType) {
    throw new AuthorizationError('invalid_request', { description: 'response_type is required' });
  }
  if (!server.responseTypes.includes(responseType)) {
    throw new AuthorizationError('unsupported_response_type', {
      description: `The authorization server does not support response_type ${responseType}`,
    });
  }
  if (!(clientResponseTypes ?? ['code']).includes(responseType)) {
    throw new AuthorizationError('unauthorized_client', {
      description: `The client is not registered for response_type ${responseType}`,
    });
  }
}

/** Parse a PKCE method, applying RFC 7636's default of `plain`. */
export function normalizePkceCodeChallengeMethod(method: string | undefined): PkceCodeChallengeMethod {
  const effectiveMethod = method ?? 'plain';
  if (effectiveMethod !== 'plain' && effectiveMethod !== 'S256') {
    throw new AuthorizationError('invalid_request', {
      description: `Unsupported PKCE code_challenge_method: ${effectiveMethod}`,
    });
  }
  return effectiveMethod;
}

/** Require a syntactically valid PKCE method that the server advertises. */
export function validatePkceCodeChallengeMethod(
  server: OAuthServerCapabilities,
  method: string | undefined
): PkceCodeChallengeMethod {
  const effectiveMethod = normalizePkceCodeChallengeMethod(method);
  if (!server.codeChallengeMethods.includes(effectiveMethod)) {
    throw new AuthorizationError('invalid_request', {
      description: 'The plain PKCE method is not allowed. Use S256 instead.',
    });
  }
  return effectiveMethod;
}

/** Validate authorization-request PKCE against server and client capabilities. */
export function validateAuthorizationPkce(
  server: OAuthServerCapabilities,
  request: {
    readonly responseType: string;
    readonly codeChallenge?: string;
    readonly codeChallengeMethod?: string;
  },
  client: Pick<ClientCapabilities, 'tokenEndpointAuthMethod'>
): void {
  if (request.codeChallenge) {
    validatePkceCodeChallengeMethod(server, request.codeChallengeMethod);
    return;
  }
  if (request.codeChallengeMethod) {
    throw new AuthorizationError('invalid_request', {
      description: 'PKCE code_challenge is required when code_challenge_method is provided.',
    });
  }
  if (request.responseType === 'code' && client.tokenEndpointAuthMethod === 'none') {
    throw new AuthorizationError('invalid_request', {
      description: 'Public clients must use PKCE with the authorization code flow.',
    });
  }
}

export function validateAuthorizationServerScopes(scopes: readonly string[] | undefined): void {
  if (!scopes) return;
  if (scopes.some((scope) => !isValidOAuthScopeToken(scope))) {
    throw new TypeError('scopesSupported must contain valid OAuth scope tokens');
  }
  if (new Set(scopes).size !== scopes.length) {
    throw new TypeError('scopesSupported must not contain duplicate values');
  }
}

export function isValidOAuthScopeToken(scopeToken: string): boolean {
  return OAUTH_SCOPE_TOKEN_PATTERN.test(scopeToken);
}
