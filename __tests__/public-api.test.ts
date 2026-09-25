/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest';
import * as pkg from '../src/oauth-provider';

// Adding a runtime export is an API decision: update this list on purpose, never by accident.
const RUNTIME_EXPORTS = [
  'AuthorizationError',
  'CimdFetchError',
  'ExternalTokenError',
  'GrantType',
  'OAuthAuthorizationServer',
  'OAuthError',
  'OAuthProvider',
  'OAuthResourceServer',
  'authorizationErrorRedirect',
  'createJwtAccessTokenValidator',
  'default',
  'getOAuthApi',
  'insufficientScope',
];

// The built bundle, when there is one: an empty record in a checkout that hasn't run the build.
const bundles = import.meta.glob('../dist/oauth-provider.js');

describe('public API', () => {
  it('the source entry exports exactly the documented runtime values', () => {
    expect(Object.keys(pkg).sort()).toEqual(RUNTIME_EXPORTS);
  });

  // What consumers load. CI builds before testing; a fresh local checkout without a build skips this.
  it.skipIf(Object.keys(bundles).length === 0)('the published bundle exports the same values', async () => {
    const published = (await Object.values(bundles)[0]()) as Record<string, unknown>;
    expect(Object.keys(published).sort()).toEqual(RUNTIME_EXPORTS);
  });
});
