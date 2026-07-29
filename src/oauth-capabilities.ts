const OAUTH_SCOPE_TOKEN_PATTERN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export interface OAuthServerCapabilities {
  readonly grantTypes: readonly string[];
  readonly responseTypes: readonly string[];
  readonly tokenEndpointAuthMethods: readonly string[];
}

export interface ClientCapabilities {
  readonly grantTypes: readonly string[];
  readonly responseTypes: readonly string[];
  readonly tokenEndpointAuthMethod: string;
}

export function buildOAuthServerCapabilities(options: {
  allowImplicitFlow: boolean;
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
