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
      validateAuthorizationPkce(defaults, { responseType: 'code' }, { tokenEndpointAuthMethod: 'none' })
    ).toThrow('Public clients must use PKCE');
  });

  it('allows confidential clients to omit PKCE', () => {
    expect(() =>
      validateAuthorizationPkce(defaults, { responseType: 'code' }, { tokenEndpointAuthMethod: 'client_secret_basic' })
    ).not.toThrow();
  });

  it('allows non-code response types to omit PKCE', () => {
    expect(() =>
      validateAuthorizationPkce(defaults, { responseType: 'token' }, { tokenEndpointAuthMethod: 'none' })
    ).not.toThrow();
  });

  it('rejects plain PKCE by default when a challenge is supplied', () => {
    expect(() =>
      validateAuthorizationPkce(
        defaults,
        { responseType: 'code', codeChallenge: 'legacy-verifier', codeChallengeMethod: 'plain' },
        { tokenEndpointAuthMethod: 'client_secret_basic' }
      )
    ).toThrow('plain PKCE method is not allowed');
  });

  it('applies the RFC 7636 plain default when a challenge omits its method', () => {
    expect(() =>
      validateAuthorizationPkce(
        defaults,
        { responseType: 'code', codeChallenge: 'legacy-verifier' },
        { tokenEndpointAuthMethod: 'client_secret_basic' }
      )
    ).toThrow('plain PKCE method is not allowed');
  });

  it.each([
    ['S256-only', defaults],
    ['plain-compatible', withPlainPkce],
  ])('accepts S256 under the %s policy', (_label, server) => {
    expect(() =>
      validateAuthorizationPkce(
        server,
        { responseType: 'code', codeChallenge: 's256-challenge', codeChallengeMethod: 'S256' },
        { tokenEndpointAuthMethod: 'client_secret_basic' }
      )
    ).not.toThrow();
  });

  it.each([
    ['an explicit plain method', { codeChallenge: 'legacy-verifier', codeChallengeMethod: 'plain' }],
    ['an omitted method', { codeChallenge: 'legacy-verifier' }],
  ])('accepts legacy plain PKCE with %s only when advertised', (_label, request) => {
    expect(() =>
      validateAuthorizationPkce(
        withPlainPkce,
        { responseType: 'code', ...request },
        { tokenEndpointAuthMethod: 'client_secret_basic' }
      )
    ).not.toThrow();
  });

  it('rejects a method without a challenge', () => {
    expect(() =>
      validateAuthorizationPkce(
        defaults,
        { responseType: 'code', codeChallengeMethod: 'S256' },
        { tokenEndpointAuthMethod: 'client_secret_basic' }
      )
    ).toThrow('code_challenge is required');
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
