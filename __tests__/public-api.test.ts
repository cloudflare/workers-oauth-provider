import { describe, expect, it } from 'vitest';
import * as pkg from '../src/oauth-provider';

describe('public API', () => {
  it('exports exactly the documented runtime values', () => {
    // Adding a runtime export is an API decision: update this list on purpose, never by accident.
    expect(Object.keys(pkg).sort()).toEqual([
      'AuthorizationError',
      'CimdFetchError',
      'ExternalTokenError',
      'GrantType',
      'OAuthAuthorizationServer',
      'OAuthError',
      'OAuthProvider',
      'OAuthResourceServer',
      'authorizationErrorRedirect',
      'default',
      'getOAuthApi',
      'insufficientScope',
    ]);
  });
});
