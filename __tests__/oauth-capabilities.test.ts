import { describe, expect, it } from 'vitest';

import {
  buildOAuthServerCapabilities,
  validateAuthorizationServerScopes,
  validateClientCapabilities,
} from '../src/oauth-capabilities';

const defaults = buildOAuthServerCapabilities({
  allowImplicitFlow: false,
  allowTokenExchangeGrant: false,
  enterpriseManagedAuthorization: false,
});

describe('OAuth server capabilities', () => {
  it('derives advertised capabilities from enabled provider features', () => {
    const enabled = buildOAuthServerCapabilities({
      allowImplicitFlow: true,
      allowTokenExchangeGrant: true,
      enterpriseManagedAuthorization: true,
    });

    expect(defaults).toEqual({
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      tokenEndpointAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],
    });
    expect(enabled.grantTypes).toEqual([
      'authorization_code',
      'refresh_token',
      'implicit',
      'urn:ietf:params:oauth:grant-type:token-exchange',
      'urn:ietf:params:oauth:grant-type:jwt-bearer',
    ]);
    expect(enabled.responseTypes).toEqual(['code', 'token']);
  });

  it.each([
    [
      'unsupported authentication method',
      { tokenEndpointAuthMethod: 'private_key_jwt', grantTypes: ['authorization_code'], responseTypes: ['code'] },
    ],
    ['unsupported grant', { tokenEndpointAuthMethod: 'none', grantTypes: ['password'], responseTypes: [] }],
    ['unsupported response', { tokenEndpointAuthMethod: 'none', grantTypes: [], responseTypes: ['id_token'] }],
    [
      'inconsistent code registration',
      { tokenEndpointAuthMethod: 'none', grantTypes: ['authorization_code'], responseTypes: [] },
    ],
  ])('rejects %s', (_label, client) => {
    expect(() => validateClientCapabilities(defaults, client)).toThrow();
  });

  it('accepts capabilities that the server advertises', () => {
    expect(() =>
      validateClientCapabilities(defaults, {
        tokenEndpointAuthMethod: 'client_secret_basic',
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
      })
    ).not.toThrow();
  });
});

describe('authorization server scopes', () => {
  it('accepts distinct OAuth scope tokens', () => {
    expect(() => validateAuthorizationServerScopes(['read', 'account:write'])).not.toThrow();
  });

  it.each([[['']], [['scope with spaces']], [['read', 'read']]])('rejects invalid scope configuration %j', (scopes) => {
    expect(() => validateAuthorizationServerScopes(scopes)).toThrow();
  });
});
