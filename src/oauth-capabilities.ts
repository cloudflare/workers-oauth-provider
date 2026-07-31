const OAUTH_SCOPE_TOKEN_PATTERN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

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

export function validateAuthorizationResponseType(
  server: OAuthServerCapabilities,
  responseType: string,
  clientResponseTypes: readonly string[] | undefined
): void {
  if (!responseType) throw new Error('invalid_request: response_type is required');
  if (!server.responseTypes.includes(responseType)) {
    throw new Error(`unsupported_response_type: the authorization server does not support ${responseType}`);
  }
  if (!(clientResponseTypes ?? ['code']).includes(responseType)) {
    throw new Error(`unauthorized_client: the client is not registered for response_type ${responseType}`);
  }
}

/** Parse a PKCE method, applying RFC 7636's default of `plain`. */
export function normalizePkceCodeChallengeMethod(method: string | undefined): PkceCodeChallengeMethod {
  const effectiveMethod = method ?? 'plain';
  if (effectiveMethod !== 'plain' && effectiveMethod !== 'S256') {
    throw new Error(`Unsupported PKCE code_challenge_method: ${effectiveMethod}`);
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
    throw new Error('The plain PKCE method is not allowed. Use S256 instead.');
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
    throw new Error('PKCE code_challenge is required when code_challenge_method is provided.');
  }
  if (request.responseType === 'code' && client.tokenEndpointAuthMethod === 'none') {
    throw new Error('Public clients must use PKCE with the authorization code flow.');
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
