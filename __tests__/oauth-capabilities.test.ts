import { describe, expect, it } from 'vitest';

import {
  buildOAuthServerCapabilities,
  normalizePkceCodeChallengeMethod,
  validateAuthorizationPkce,
  validateAuthorizationResponseType,
  validatePkceCodeChallengeMethod,
  validateAuthorizationServerScopes,
  validateClientCapabilities,
} from '../src/oauth-capabilities';

const defaults = buildOAuthServerCapabilities({
  allowImplicitFlow: false,
  allowPlainPKCE: false,
  allowTokenExchangeGrant: false,
  enterpriseManagedAuthorization: false,
});

const withPlainPkce = buildOAuthServerCapabilities({
  allowImplicitFlow: false,
  allowPlainPKCE: true,
  allowTokenExchangeGrant: false,
  enterpriseManagedAuthorization: false,
});

describe('OAuth server capabilities', () => {
  it('derives advertised capabilities from enabled provider features', () => {
    const enabled = buildOAuthServerCapabilities({
      allowImplicitFlow: true,
      allowPlainPKCE: true,
      allowTokenExchangeGrant: true,
      enterpriseManagedAuthorization: true,
    });

    expect(defaults).toEqual({
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      tokenEndpointAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],
      codeChallengeMethods: ['S256'],
    });
    expect(enabled.grantTypes).toEqual([
      'authorization_code',
      'refresh_token',
      'implicit',
      'urn:ietf:params:oauth:grant-type:token-exchange',
      'urn:ietf:params:oauth:grant-type:jwt-bearer',
    ]);
    expect(enabled.responseTypes).toEqual(['code', 'token']);
    expect(enabled.codeChallengeMethods).toEqual(['plain', 'S256']);
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

  it.each([
    ['', ['code'], 'invalid_request'],
    ['token', ['code', 'token'], 'unsupported_response_type'],
    ['code', ['token'], 'unauthorized_client'],
  ])('rejects response type %j against client %j', (responseType, clientResponseTypes, error) => {
    expect(() => validateAuthorizationResponseType(defaults, responseType, clientResponseTypes)).toThrow(error);
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

describe('PKCE capabilities', () => {
  it.each([
    ['S256', 'S256'],
    [undefined, 'plain'],
  ] as const)('resolves method %j when advertised', (method, expected) => {
    expect(normalizePkceCodeChallengeMethod(method)).toBe(expected);
  });

  it('rejects unknown methods', () => {
    expect(() => normalizePkceCodeChallengeMethod('S512')).toThrow('Unsupported PKCE code_challenge_method');
  });

  it('rejects known methods that are not advertised', () => {
    expect(() => validatePkceCodeChallengeMethod(defaults, 'plain')).toThrow('plain PKCE method is not allowed');
  });

  it('requires PKCE for public authorization-code clients', () => {
    expect(() =>
      validateAuthorizationPkce(
        defaults,
        { responseType: 'code', codeChallengeMethod: 'S256' },
        { tokenEndpointAuthMethod: 'none' }
      )
    ).toThrow('Public clients must use PKCE');
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
