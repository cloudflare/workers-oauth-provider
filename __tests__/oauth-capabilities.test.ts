import { describe, expect, it } from 'vitest';

import {
  AuthorizationError,
  buildOAuthServerCapabilities,
  negotiateCimdClientCapabilities,
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
  ])('rejects response type %j against client %j', (responseType, clientResponseTypes, code) => {
    try {
      validateAuthorizationResponseType(defaults, responseType, clientResponseTypes);
      throw new Error('Expected AuthorizationError');
    } catch (error) {
      expect(error).toBeInstanceOf(AuthorizationError);
      expect(error).toMatchObject({ code });
    }
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

  it('negotiates a supported CIMD subset from additional advertised capabilities', () => {
    expect(
      negotiateCimdClientCapabilities(defaults, {
        tokenEndpointAuthMethod: 'none',
        grantTypes: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
        responseTypes: ['code', 'id_token'],
      })
    ).toEqual({
      tokenEndpointAuthMethod: 'none',
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
    });
  });

  it('does not enable capabilities that a CIMD client omitted', () => {
    expect(
      negotiateCimdClientCapabilities(defaults, {
        tokenEndpointAuthMethod: 'none',
        grantTypes: ['urn:example:unsupported-grant'],
        responseTypes: ['id_token'],
      })
    ).toEqual({
      tokenEndpointAuthMethod: 'none',
      grantTypes: [],
      responseTypes: [],
    });
  });

  it('retains JWT bearer when enterprise-managed authorization is enabled', () => {
    const withEnterpriseManagedAuthorization = buildOAuthServerCapabilities({
      allowImplicitFlow: false,
      allowPlainPKCE: false,
      allowTokenExchangeGrant: false,
      enterpriseManagedAuthorization: true,
    });

    expect(
      negotiateCimdClientCapabilities(withEnterpriseManagedAuthorization, {
        tokenEndpointAuthMethod: 'none',
        grantTypes: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
        responseTypes: ['code'],
      })
    ).toEqual({
      tokenEndpointAuthMethod: 'none',
      grantTypes: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
      responseTypes: ['code'],
    });
  });

  it('rejects an inconsistent effective CIMD capability subset', () => {
    expect(() =>
      negotiateCimdClientCapabilities(defaults, {
        tokenEndpointAuthMethod: 'none',
        grantTypes: ['authorization_code', 'urn:example:unsupported-grant'],
        responseTypes: ['id_token'],
      })
    ).toThrow('grant_types authorization_code and response_types code must be registered together');
  });
});

describe('CIMD token endpoint authentication negotiation', () => {
  function negotiateAuthMethod(preferred?: string, choices?: string[]): string {
    return negotiateCimdClientCapabilities(defaults, {
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      tokenEndpointAuthMethod: preferred,
      tokenEndpointAuthMethodsSupported: choices,
    }).tokenEndpointAuthMethod;
  }

  it.each([
    ['defaults an omitted method', undefined, undefined, 'none'],
    ['keeps an implemented preference', 'none', undefined, 'none'],
    ['selects an implemented choice', undefined, ['private_key_jwt', 'none'], 'none'],
    ['falls back from an unsupported preference', 'private_key_jwt', ['none', 'private_key_jwt'], 'none'],
  ])('%s', (_label, preferred, choices, expected) => {
    expect(negotiateAuthMethod(preferred, choices)).toBe(expected);
  });

  it.each([
    ['an unsupported preference without choices', 'private_key_jwt', undefined],
    ['unsupported choices without a preference', undefined, ['private_key_jwt']],
    ['an empty choice list', undefined, []],
  ])('rejects %s', (_label, preferred, choices) => {
    expect(() => negotiateAuthMethod(preferred, choices)).toThrow(
      'CIMD client does not support an accepted token endpoint authentication method'
    );
  });

  it('rejects symmetric secret methods', () => {
    expect(() => negotiateAuthMethod('client_secret_post', ['client_secret_post'])).toThrow(
      'CIMD clients cannot use symmetric token endpoint authentication method'
    );
  });

  it('rejects a preferred method omitted from the corresponding choices', () => {
    expect(() => negotiateAuthMethod('none', ['private_key_jwt'])).toThrow(
      'token_endpoint_auth_method must be included in token_endpoint_auth_methods_supported'
    );
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
