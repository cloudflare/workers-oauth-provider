# @cloudflare/workers-oauth-provider

## 0.2.4

### Patch Changes

- [#136](https://github.com/cloudflare/workers-oauth-provider/pull/136) [`a8c5936`](https://github.com/cloudflare/workers-oauth-provider/commit/a8c593674b1d3dac497803758a00e880b2215f32) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Add `/.well-known/oauth-protected-resource` endpoint (RFC 9728) for OAuth 2.0 Protected Resource Metadata discovery, as required by the MCP authorization specification. The endpoint is always served with sensible defaults (request origin as resource and authorization server), and can be customized via the new `resourceMetadata` option.

- [#151](https://github.com/cloudflare/workers-oauth-provider/pull/151) [`dbb150e`](https://github.com/cloudflare/workers-oauth-provider/commit/dbb150edb8655f779b0af9e0d2cce1f36bfadf37) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Add `allowPlainPKCE` option to enforce S256-only PKCE as recommended by OAuth 2.1. When set to false, the plain PKCE method is rejected and only S256 is accepted. Defaults to true for backward compatibility.

- [#140](https://github.com/cloudflare/workers-oauth-provider/pull/140) [`65d5cfa`](https://github.com/cloudflare/workers-oauth-provider/commit/65d5cfa9d4e1fc52a03fcba6fc0c4539a73c296d) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Fix apiHandler route matching when set to '/' to use exact match instead of prefix match, preventing it from matching all routes and breaking OAuth endpoints

- [#150](https://github.com/cloudflare/workers-oauth-provider/pull/150) [`734738c`](https://github.com/cloudflare/workers-oauth-provider/commit/734738cb519a74474435b5b911ad3c83b1f2bb73) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Fix TypeScript types by making OAuthProviderOptions generic over Env, eliminating the need for @ts-expect-error workarounds when using typed environments

- [#145](https://github.com/cloudflare/workers-oauth-provider/pull/145) [`6ce5c10`](https://github.com/cloudflare/workers-oauth-provider/commit/6ce5c10826d8746bb339cf80b15f95c33fb45e99) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Add RFC 8252 Section 7.3 compliance: allow any port for loopback redirect URIs (127.x.x.x, ::1) to support native apps that use ephemeral ports

- [#143](https://github.com/cloudflare/workers-oauth-provider/pull/143) [`8909060`](https://github.com/cloudflare/workers-oauth-provider/commit/890906003b8a8a249cddea731af3ee0997fbfe73) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Include `resource_metadata` URL in `WWW-Authenticate` headers on 401 responses per RFC 9728 §5.1, enabling clients to discover the protected resource metadata endpoint directly from authentication challenges.

## 0.2.3

### Patch Changes

- [#117](https://github.com/cloudflare/workers-oauth-provider/pull/117) [`b2c5877`](https://github.com/cloudflare/workers-oauth-provider/commit/b2c5877617809107ea4759b22c4994f0711affe4) Thanks [@DeanMauro](https://github.com/DeanMauro)! - Add `getOAuthApi` helper function to access OAuthHelpers outside of the `fetch` method. This enables OAuth functionality in worker RPC methods and other entry points.

- [#109](https://github.com/cloudflare/workers-oauth-provider/pull/109) [`9f118f3`](https://github.com/cloudflare/workers-oauth-provider/commit/9f118f36c4f0aba8a56c9179844ca47d5b37387a) Thanks [@bokhi](https://github.com/bokhi)! - fix: path-aware audience validation for RFC 8707 resource indicators. Include request pathname in `resourceServer` computation for both internal and external token validation. Replace strict equality in `audienceMatches()` with origin + path-prefix matching on path boundaries. Origin-only audiences (e.g. `https://example.com`) still match any path (backward compatible). Path-aware audiences (e.g. `https://example.com/api`) match the exact path and sub-paths (`/api/users`) but not partial matches (`/api-v2`).

- [#120](https://github.com/cloudflare/workers-oauth-provider/pull/120) [`155c410`](https://github.com/cloudflare/workers-oauth-provider/commit/155c4108c781ab767d048b75eae9e9afdb0eb4d9) Thanks [@DeanMauro](https://github.com/DeanMauro)! - Add OAuth 2.0 Token Exchange (RFC 8693) support. Clients can exchange an existing access token for a new one with narrowed scopes, a different audience, or a shorter TTL — without requiring the user to re-authorize. Gated behind the `allowTokenExchangeGrant` option (default `false`). Also adds scope downscoping (RFC 6749 Section 3.3) to authorization code and refresh token flows.

## 0.2.2

### Patch Changes

- [#129](https://github.com/cloudflare/workers-oauth-provider/pull/129) [`1e14e05`](https://github.com/cloudflare/workers-oauth-provider/commit/1e14e05e1d2521914dc829d4f33f7887dfa732ce) Thanks [@threepointone](https://github.com/threepointone)! - feat: add Client ID Metadata Document (CIMD) support

  (by @mattzcarey in https://github.com/cloudflare/workers-oauth-provider/issues/112)

  CIMD support allows clients to use HTTPS URLs as client_id values that
  point to metadata documents.

  When a client_id is an HTTPS URL with a non-root path, the provider
  fetches and validates the metadata document instead of looking up in KV
  storage. Added validation to ensure client_id in the document matches
  the URL and redirect_uris are present.

  matches the new authorization spec for MCP

  https://modelcontextprotocol.io/specification/draft/basic/authorization

## 0.2.1

### Patch Changes

- [#127](https://github.com/cloudflare/workers-oauth-provider/pull/127) [`11fd839`](https://github.com/cloudflare/workers-oauth-provider/commit/11fd839e269c888d1a1fb2753b9bf415d4d7038b) Thanks [@threepointone](https://github.com/threepointone)! - feat: add Client ID Metadata Document (CIMD) support

  (by @mattzcarey in https://github.com/cloudflare/workers-oauth-provider/issues/112)

  CIMD support allows clients to use HTTPS URLs as client_id values that
  point to metadata documents.

  When a client_id is an HTTPS URL with a non-root path, the provider
  fetches and validates the metadata document instead of looking up in KV
  storage. Added validation to ensure client_id in the document matches
  the URL and redirect_uris are present.

  matches the new authorization spec for MCP

  https://modelcontextprotocol.io/specification/draft/basic/authorization

## 0.1.1

### Patch Changes

- [#114](https://github.com/cloudflare/workers-oauth-provider/pull/114) [`768cd6c`](https://github.com/cloudflare/workers-oauth-provider/commit/768cd6c9d34488f653a678b08f33070b31c071e5) Thanks [@DeanMauro](https://github.com/DeanMauro)! - adds a method `decodeToken` that retrieves a granted access token from the KV and returns the user-defined props attached to it. This permits token decoding outside of a fetch call, e.g. an RPC call from another worker.

## 0.1.0

### Minor Changes

- [#103](https://github.com/cloudflare/workers-oauth-provider/pull/103) [`818a557`](https://github.com/cloudflare/workers-oauth-provider/commit/818a557a0042b99282397cbaf12bff84487a737a) Thanks [@mattzcarey](https://github.com/mattzcarey)! - feat: add audience validation for OAuth tokens per RFC 7519

## 0.0.13

### Patch Changes

- [#98](https://github.com/cloudflare/workers-oauth-provider/pull/98) [`0982a1c`](https://github.com/cloudflare/workers-oauth-provider/commit/0982a1c61e2aab25cddd929738d1f3d94be08e7a) Thanks [@threepointone](https://github.com/threepointone)! - Enhance redirect URI scheme validation for security

  Added a robust helper to validate redirect URI schemes, preventing dangerous pseudo-schemes (e.g., javascript:, data:, vbscript:) with normalization and case-insensitive checks. Expanded test coverage to include bypass attempts using mixed case, whitespace, control characters, and edge cases to ensure comprehensive protection against XSS and related attacks.

## 0.0.12

### Patch Changes

- [#92](https://github.com/cloudflare/workers-oauth-provider/pull/92) [`5a59d78`](https://github.com/cloudflare/workers-oauth-provider/commit/5a59d780ee1285546216b21265ff9c7c8435a2ba) Thanks [@roerohan](https://github.com/roerohan)! - fix: open redirect vulnerability in completeAuthorization

## 0.0.11

### Patch Changes

- [#78](https://github.com/cloudflare/workers-oauth-provider/pull/78) [`32560d1`](https://github.com/cloudflare/workers-oauth-provider/commit/32560d1e45fd74db8129b5d10d668a82deaff7f2) Thanks [@rc4](https://github.com/rc4)! - Use rejection sampling to avoid bias in `generateRandomString()`

## 0.0.10

### Patch Changes

- [#87](https://github.com/cloudflare/workers-oauth-provider/pull/87) [`1804446`](https://github.com/cloudflare/workers-oauth-provider/commit/1804446ba6d17fa7e6395e47a4fecef374d7e1bd) Thanks [@threepointone](https://github.com/threepointone)! - explicitly block javascript: (and other suspicious protocols) in redirect uris

  In https://github.com/cloudflare/workers-oauth-provider/pull/80, we blocked redirects that didn't start with http:// or https:// to prevent xss attacks with javascript: URIs. However this blocked redirects to custom apps like cursor:// et al. This patch now explicitly blocks javascript: (and other suspicious protocols) in redirect uris.

## 0.0.9

### Patch Changes

- [#81](https://github.com/cloudflare/workers-oauth-provider/pull/81) [`d18b865`](https://github.com/cloudflare/workers-oauth-provider/commit/d18b865bb21a669993424da89ebca47d391644ba) Thanks [@deathbyknowledge](https://github.com/deathbyknowledge)! - Add resolveExternalToken to support external token auth flows

  Adds resolveExternalToken to support auth for external tokens. The callback only runs IF internal auth check fails. E.g. a canonical OAuth server is used by multiple services, allowing server-server communication with the same token.

## 0.0.8

### Patch Changes

- [#74](https://github.com/cloudflare/workers-oauth-provider/pull/74) [`9d4b595`](https://github.com/cloudflare/workers-oauth-provider/commit/9d4b595f63d2aebd5700e4021967b98173cd3755) Thanks [@ghostwriternr](https://github.com/ghostwriternr)! - Add configurable refresh token expiration
  - New `refreshTokenTTL` option to set global expiration for refresh tokens
  - Support for per-token TTL override via `tokenExchangeCallback`
  - Expired tokens return `invalid_grant` error, forcing reauthentication
  - Backward compatible: tokens without TTL never expire

## 0.0.7

### Patch Changes

- [#62](https://github.com/cloudflare/workers-oauth-provider/pull/62) [`239e753`](https://github.com/cloudflare/workers-oauth-provider/commit/239e753b83091a32327f3b2a093e306bb6ee8498) Thanks [@whoiskatrin](https://github.com/whoiskatrin)! - token revocation endpoint support

- [#76](https://github.com/cloudflare/workers-oauth-provider/pull/76) [`0b064bf`](https://github.com/cloudflare/workers-oauth-provider/commit/0b064bf087df3722760bc1d328fbe4c869bb626f) Thanks [@ghostwriternr](https://github.com/ghostwriternr)! - Fix token revocation returning HTTP 500 instead of 200

- [#80](https://github.com/cloudflare/workers-oauth-provider/pull/80) [`9587b58`](https://github.com/cloudflare/workers-oauth-provider/commit/9587b5821a37a92d5bb86299afbce1958ee46a54) Thanks [@threepointone](https://github.com/threepointone)! - block javascript: redirect URIs

## 0.0.6

### Patch Changes

- [#52](https://github.com/cloudflare/workers-oauth-provider/pull/52) [`fe6b721`](https://github.com/cloudflare/workers-oauth-provider/commit/fe6b721520ed21e82cbea451f7afbedfa70b1a12) Thanks [@cnallam](https://github.com/cnallam)! - Fix for the Missing Validation for ClientId
