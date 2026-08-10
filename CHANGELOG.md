# @cloudflare/workers-oauth-provider

## 0.10.3

### Patch Changes

- [#299](https://github.com/cloudflare/workers-oauth-provider/pull/299) [`dc63ec8`](https://github.com/cloudflare/workers-oauth-provider/commit/dc63ec8664c2f6c4e0f02fefebcb2a873b91ed0a) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Scope default grant revocation to the authorizing redirect URI for Client ID Metadata Document clients. A CIMD client_id is the metadata document URL shared by every installation of the client, so `completeAuthorization()`'s default revocation logged the user out of all their other devices; it now revokes only grants created from the same redirect URI. Grants now record the redirect URI that created them, and grants created before this release are never auto-revoked by CIMD clients. Revocation for pre-registered and dynamically registered clients is unchanged.

## 0.10.2

### Patch Changes

- [#295](https://github.com/cloudflare/workers-oauth-provider/pull/295) [`3a41fd7`](https://github.com/cloudflare/workers-oauth-provider/commit/3a41fd7fc23bafc905548d2e587a4bb1c231320e) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Fix client authentication method negotiation so ChatGPT can prefer `private_key_jwt` while offering the provider's supported `none` alternative.

  DCR and CIMD now use one typed client metadata parser aligned with draft-ietf-oauth-client-id-metadata-document-00 (the revision pinned by MCP 2026-07-28) and OpenID Connect RP Metadata Choices 1.0. The CIMD resolver validates cross-field choices and prohibited credentials, rejects unsafe document URLs, applies response-size and timeout limits to the complete fetch, caches only validated documents with a 7-day lifetime cap, and recovers from a cached document that stops validating by re-resolving from origin in the same request.

## 0.10.1

### Patch Changes

- [#287](https://github.com/cloudflare/workers-oauth-provider/pull/287) [`30b1f4f`](https://github.com/cloudflare/workers-oauth-provider/commit/30b1f4f4853cad79cb2ba162dc9101b6cea46aa3) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Preserve Basic and POST authentication interoperability for legacy and defaulted confidential clients while enforcing explicitly selected methods.

- [#285](https://github.com/cloudflare/workers-oauth-provider/pull/285) [`737dfa2`](https://github.com/cloudflare/workers-oauth-provider/commit/737dfa2c3ab4b76506c375535e1192a2c6ef6d72) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Negotiate Client ID Metadata Document grant and response types with the authorization server's supported capabilities instead of rejecting documents that advertise additional values.

- [#288](https://github.com/cloudflare/workers-oauth-provider/pull/288) [`7a6baf9`](https://github.com/cloudflare/workers-oauth-provider/commit/7a6baf9b32345c9ffa2eb4e43be8968900da98af) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Restore v0.8.2-compatible resource handling for grants without a stored RFC 8707 resource. Configured canonical resources are defaulted and inherited, bound grants reject explicit mismatches, and an unconfigured legacy grant can issue an unbound token or use an explicit token-request resource without persisting a new grant binding.

  Deprecate `resourceMatchOriginOnly` without changing its behavior.

## 0.10.0

### Minor Changes

- [#283](https://github.com/cloudflare/workers-oauth-provider/pull/283) [`b36f841`](https://github.com/cloudflare/workers-oauth-provider/commit/b36f841fb4d94de55c50ae73a70c1bb549275ae6) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Export `AuthorizationError` and throw it from `parseAuthRequest()` for expected authorization-request validation failures. Errors carry a validated redirect URI, original state, and issuer only after exact client redirect validation succeeds, allowing applications to distinguish safe OAuth error redirects from failures that must be rendered locally.

## 0.9.1

### Patch Changes

- [#280](https://github.com/cloudflare/workers-oauth-provider/pull/280) [`43b9fa4`](https://github.com/cloudflare/workers-oauth-provider/commit/43b9fa49b37777c0264db4cd8cd0469fe01ff13c) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Stop returning `registration_client_uri` from dynamic client registration. The provider implements RFC 7591 registration but not the RFC 7592 client configuration endpoint previously advertised by this field.

## 0.9.0

### Minor Changes

- [#253](https://github.com/cloudflare/workers-oauth-provider/pull/253) [`f4e026c`](https://github.com/cloudflare/workers-oauth-provider/commit/f4e026c3aba40f4c3cfad0576d3fb2b5489d8ee1) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Reject authorization-code requests from public clients that omit PKCE. OAuth 2.1 requires authorization servers to enforce `code_challenge` for clients that cannot authenticate at the token endpoint.

- [#248](https://github.com/cloudflare/workers-oauth-provider/pull/248) [`194154e`](https://github.com/cloudflare/workers-oauth-provider/commit/194154e2429d3dafb77617638fb9faa6daa2a331) Thanks [@ksinder](https://github.com/ksinder)! - Report CIMD metadata fetch failures instead of treating them as unknown clients.
  A failed Client ID Metadata Document fetch previously became a `null` client
  lookup, so a network problem (timeout, WAF block, upstream outage) was
  indistinguishable from an unregistered client — at the token endpoint, in the
  `onError` hook, and for `OAuthHelpers` callers. The fetch failure now throws a
  new exported `CimdFetchError` carrying the metadata URL, stable
  `metadata_resolution_failed` reason, and underlying diagnostic detail. The
  token endpoint still returns the same generic `invalid_client` / "Client not
  found" response, but reports the failure through the `onError` hook's
  `internal` field (category `client-id-metadata-document`) together with a new
  optional `request` field. Breaking for callers of `OAuthHelpers.lookupClient`
  (and methods built on it) that relied on `null` for CIMD fetch failures: catch
  `CimdFetchError` to restore the old behavior.

- [#259](https://github.com/cloudflare/workers-oauth-provider/pull/259) [`71ec864`](https://github.com/cloudflare/workers-oauth-provider/commit/71ec86465217725e76b2f57271719dd50aaaad7a) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Enable RFC 9207 authorization response issuer identification. Authorization server metadata advertises support, parsed requests carry the expected issuer for application-owned terminal error responses, and successful code and implicit redirects include `iss`.

- [#255](https://github.com/cloudflare/workers-oauth-provider/pull/255) [`5cc336c`](https://github.com/cloudflare/workers-oauth-provider/commit/5cc336c36b1170eab45378ca2e74e5520604ba38) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Validate protected resource metadata at construction time. Reject empty or invalid authorization server issuer lists, invalid resource and scope values, and bearer presentation methods the provider does not implement instead of publishing unusable or misleading RFC 9728 metadata.

- [#277](https://github.com/cloudflare/workers-oauth-provider/pull/277) [`9e88aa4`](https://github.com/cloudflare/workers-oauth-provider/commit/9e88aa4e625cdeda40de4ca56aadc22575d37e1a) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Require S256 PKCE by default. Authorization servers now advertise only `S256` and reject PKCE challenges that use `plain` or omit `code_challenge_method` unless `allowPlainPKCE: true` is configured for legacy compatibility. Confidential clients may continue to omit PKCE entirely.

- [#260](https://github.com/cloudflare/workers-oauth-provider/pull/260) [`248a9e7`](https://github.com/cloudflare/workers-oauth-provider/commit/248a9e76707804a9cd39b02870c7eb809062dbcd) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Separate authorization-server and protected-resource scope configuration. Explicit `resourceMetadata.scopes_supported` values become baseline Bearer challenge guidance, operation-specific `requiredScopes` takes precedence, and `offline_access` is omitted from provider-generated resource-facing scope lists. Deployments relying on the old `scopesSupported` fallback must configure protected-resource scopes explicitly.

- [#251](https://github.com/cloudflare/workers-oauth-provider/pull/251) [`98d642f`](https://github.com/cloudflare/workers-oauth-provider/commit/98d642f1d2f866663aba6b2a935727bbcca0b6d3) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Add an exported `ExternalTokenError` for intentional structured errors from `resolveExternalToken`. Existing callbacks keep their previous behavior: returning `{ props, audience? }` authenticates, returning `null` returns a generic `401 invalid_token`, and every other thrown value, including `OAuthError`, propagates as an unexpected failure. Standard bearer-token `ExternalTokenError` failures receive `WWW-Authenticate` challenges, `requiredScopes` supplies step-up guidance, callback headers are preserved, and browser clients can read `WWW-Authenticate` and `Retry-After` through CORS.

- [#256](https://github.com/cloudflare/workers-oauth-provider/pull/256) [`510b20c`](https://github.com/cloudflare/workers-oauth-provider/commit/510b20c66a7b9679c73a249ef5e7117aecd9a41a) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Use `resourceMetadata.resource` as the strict RFC 8707 resource policy. Configured deployments now require that exact resource throughout authorization, token issuance, and access-token validation. Unconfigured deployments remain interoperable by inheriting requested resources and defaulting omitted authorization resources to the request origin.

- [#273](https://github.com/cloudflare/workers-oauth-provider/pull/273) [`cd5e96a`](https://github.com/cloudflare/workers-oauth-provider/commit/cd5e96a08e4cae3eff1f0f35572e5ca895a3e064) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Validate configured scopes and registered OAuth client capabilities. Dynamic registration now applies RFC 7591 defaults, rejects unsupported or inconsistent authentication, grant, and response types before storage, and applies the same capability checks to CIMD metadata.

### Patch Changes

- [#254](https://github.com/cloudflare/workers-oauth-provider/pull/254) [`79270da`](https://github.com/cloudflare/workers-oauth-provider/commit/79270dacb1b006b4ec0b4ebb68f61cd2dd22e60f) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Tighten Client ID Metadata Document validation by requiring a non-empty `client_name` and accepting only the currently implemented public-client authentication method, `none`. Support OpenID RP Metadata Choices by selecting `none` from `token_endpoint_auth_methods_supported`, including ChatGPT-style documents that also advertise `private_key_jwt`.

- [#273](https://github.com/cloudflare/workers-oauth-provider/pull/273) [`cd5e96a`](https://github.com/cloudflare/workers-oauth-provider/commit/cd5e96a08e4cae3eff1f0f35572e5ca895a3e064) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Fail closed when ID-JAG assertions contain unsupported `authorization_details` or `cnf` authorization constraints. These claims now produce a generic `invalid_grant` response before replay reservation, mapping, or token storage.

- [#258](https://github.com/cloudflare/workers-oauth-provider/pull/258) [`8883c0a`](https://github.com/cloudflare/workers-oauth-provider/commit/8883c0ab9dedada1ebd10d198e7c2a657519dd5e) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Validate refresh-token `resource` parameters before invoking callbacks, rotating refresh tokens, or writing grant state. Invalid or out-of-grant resource requests now return `invalid_target` without mutating the authorization grant.

- [#247](https://github.com/cloudflare/workers-oauth-provider/pull/247) [`9d045d2`](https://github.com/cloudflare/workers-oauth-provider/commit/9d045d2f4feb0693bd5917fcc620f7527b935d94) Thanks [@agent-think](https://github.com/apps/agent-think)! - Return RFC-compliant `401 invalid_client` responses for malformed HTTP Basic client credentials, recognize the Basic scheme case-insensitively, and include the required Basic challenge on authentication failures.

- [#252](https://github.com/cloudflare/workers-oauth-provider/pull/252) [`fdba134`](https://github.com/cloudflare/workers-oauth-provider/commit/fdba1340c9331f1e8dbe1533e66ec6cbc125ac44) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Return a bare RFC 6750 bearer challenge when protected resource requests omit credentials or use an unsupported authorization scheme. These responses no longer mislabel absent credentials as `invalid_token` or include OAuth error details.

- [#273](https://github.com/cloudflare/workers-oauth-provider/pull/273) [`cd5e96a`](https://github.com/cloudflare/workers-oauth-provider/commit/cd5e96a08e4cae3eff1f0f35572e5ca895a3e064) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Require ID-JAG assertions to identify exactly one authorization server audience. Multi-element, duplicate, empty, malformed, and mismatched audience arrays are now rejected before authorization state is written.

- [#275](https://github.com/cloudflare/workers-oauth-provider/pull/275) [`ee5b487`](https://github.com/cloudflare/workers-oauth-provider/commit/ee5b487d356872cf9872e0caaa857c48dc58b2bc) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Reject unsupported PKCE `code_challenge_method` values instead of treating them as `plain`. Discovery and request validation now share one PKCE capability policy, `completeAuthorization()` revalidates reconstructed requests, and token exchange fails closed for malformed grants created by older versions.

- [#276](https://github.com/cloudflare/workers-oauth-provider/pull/276) [`94cc3db`](https://github.com/cloudflare/workers-oauth-provider/commit/94cc3dbd9fb97eab79af8cad10db539af8396aea) Thanks [@agent-think](https://github.com/apps/agent-think)! - Enforce each client's registered `token_endpoint_auth_method` when authenticating token and revocation endpoint requests.

- [#271](https://github.com/cloudflare/workers-oauth-provider/pull/271) [`0fa9bd5`](https://github.com/cloudflare/workers-oauth-provider/commit/0fa9bd5b4fca287fa1be6f7e4d53f0f397953637) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Replace internal `env: any` parameters with typed shapes. Internal provider methods now take `Env & ProviderEnv` (where `ProviderEnv` declares the required `OAUTH_KV: KVNamespace` binding), `ResolveExternalTokenInput` threads the `Env` generic through to the `resolveExternalToken` callback, and `OAuthHelpersImpl` is generic over `Env`. No runtime behavior change.

- [#273](https://github.com/cloudflare/workers-oauth-provider/pull/273) [`cd5e96a`](https://github.com/cloudflare/workers-oauth-provider/commit/cd5e96a08e4cae3eff1f0f35572e5ca895a3e064) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Validate authorization response types in both `parseAuthRequest()` and `completeAuthorization()`. Missing, unsupported, and client-disallowed values are rejected after client and redirect URI validation but before grant creation or existing-grant revocation.

## 0.8.3

### Patch Changes

- [#240](https://github.com/cloudflare/workers-oauth-provider/pull/240) [`0061270`](https://github.com/cloudflare/workers-oauth-provider/commit/0061270c4a18b1d81dad87a6521a4c00f934c91e) Thanks [@agent-think](https://github.com/apps/agent-think)! - Fix worker crash (HTTP 500) when the `/token` request sends a malformed
  `Content-Type` header. The endpoint previously used a loose `includes()` check,
  so a header such as `application/json, application/x-www-form-urlencoded` passed
  validation and then caused `request.formData()` to throw. The media type is now
  parsed strictly (parameters are stripped and the exact media type is compared),
  and form parsing is guarded so invalid bodies return a `400 invalid_request`
  instead of crashing the worker.

- [#246](https://github.com/cloudflare/workers-oauth-provider/pull/246) [`771a207`](https://github.com/cloudflare/workers-oauth-provider/commit/771a207ad507c05d63885989dd0d318894a0ec8d) Thanks [@agent-think](https://github.com/apps/agent-think)! - Validate the RFC 8707 resource parameter before consuming an authorization code, so a token request rejected with `invalid_target` can be retried with an allowed resource.

- [#249](https://github.com/cloudflare/workers-oauth-provider/pull/249) [`f0f5dc0`](https://github.com/cloudflare/workers-oauth-provider/commit/f0f5dc08fef813ecaa8f9111750438ef449c26da) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Preserve a subject access token's scope when issuing tokens through OAuth 2.0 Token Exchange.

## 0.8.2

### Patch Changes

- [#241](https://github.com/cloudflare/workers-oauth-provider/pull/241) [`76d2fcd`](https://github.com/cloudflare/workers-oauth-provider/commit/76d2fcd7911015acb561d9e59ac76dc61a577951) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Allow EMA ID-JAG assertions to omit the optional `resource` claim, falling back to the provider's configured protected resource.

## 0.8.1

### Patch Changes

- [#234](https://github.com/cloudflare/workers-oauth-provider/pull/234) [`7b4ba3a`](https://github.com/cloudflare/workers-oauth-provider/commit/7b4ba3ad6a7854a0225c4f17f0fdb2297370c2be) Thanks [@threepointone](https://github.com/threepointone)! - Fix uncaught 500 when refreshing a near-expiry grant. A refresh arriving in the final
  <60s of a grant's life previously passed the expiry check and then crashed with
  "KV PUT failed: 400 Invalid expiration" because Cloudflare KV rejects absolute
  expirations less than 60 seconds in the future. Such grants are now treated as expired
  (returning `invalid_grant`).

  The refresh handler also re-checks expiry after the `tokenExchangeCallback` runs, so a
  slow callback (e.g. an upstream network refresh) that pushes the grant under the 60-second
  threshold mid-request is rejected cleanly instead of crashing when writing the rotated
  grant or the new access token (whose TTL is clamped to the grant's remaining lifetime).
  As defense-in-depth, `saveGrantWithTTL` also clamps the absolute expiration to KV's
  60-second minimum (plus a small margin so writes stay storable under clock skew / write latency).

  The token exchange grant (RFC 8693) shared the same root cause: the issued token's TTL is
  clamped to the subject token's remaining lifetime, so a subject token in its final <60s (or
  a `expires_in`/`accessTokenTTL` below 60) produced an unstorable token. The exchange now
  rejects a subject token with under 60s remaining (`invalid_grant`) and a requested lifetime
  below 60s (`invalid_request`) instead of crashing.

  More broadly, any access token lifetime below KV's 60-second minimum is now caught instead of
  crashing with an opaque KV 400:
  - `accessTokenTTL` is validated at `OAuthProvider` construction (must be an integer of at
    least 60 seconds).
  - A `tokenExchangeCallback` returning an `accessTokenTTL` below 60 on the authorization code
    or refresh grant is rejected with `invalid_request`.
  - The enterprise-managed authorization (ID-JAG) grant rejects a mapper-supplied access token
    TTL below 60 (`invalid_grant`, "Invalid access token TTL").

## 0.8.0

### Minor Changes

- [#228](https://github.com/cloudflare/workers-oauth-provider/pull/228) [`d3d1c10`](https://github.com/cloudflare/workers-oauth-provider/commit/d3d1c104440192a4d7f72c8bb6b9f39e0bcb2a9d) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Simplify `clientRegistrationCallback` to be an allow-or-reject policy hook. Returning `undefined` allows registration; returning an object rejects registration with optional `code`, `description`, and `status`. Metadata override behavior has been removed.

- [#184](https://github.com/cloudflare/workers-oauth-provider/pull/184) [`917fe92`](https://github.com/cloudflare/workers-oauth-provider/commit/917fe92d0c21906ba34a2b805925ee13ff54b7a5) Thanks [@Talador12](https://github.com/Talador12)! - Add `clientRegistrationCallback` for validating or rejecting dynamic client registrations before storage. Return `undefined`/nothing to allow registration, or return an object to reject it. Closes #162.
  - Default rejection error follows RFC 7591 §3.2.2 (`invalid_client_metadata` / 400). Callbacks rejecting for non-metadata reasons (missing IAT, untrusted origin) should override `code` and `status` explicitly.
  - The `request` passed to the callback is cloned before the library reads the body, so callbacks may consume the body (e.g. to verify a signature over the raw bytes).
  - Callback exceptions are caught and surfaced as `500 server_error`.
  - `software_statement` (RFC 7591 §3.1.1) JWTs are not processed by the library; callbacks wishing to honor them must verify the JWT and apply its claims themselves.

### Patch Changes

- [#231](https://github.com/cloudflare/workers-oauth-provider/pull/231) [`624fc56`](https://github.com/cloudflare/workers-oauth-provider/commit/624fc56e184c86d5e70f89763458e3ab95c40f41) Thanks [@william-canva](https://github.com/william-canva)! - Bound the KV page size used when revoking existing grants during authorization.

- [#224](https://github.com/cloudflare/workers-oauth-provider/pull/224) [`46cf9b6`](https://github.com/cloudflare/workers-oauth-provider/commit/46cf9b6a5c2656782a6ba36f433a8435171cae01) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Add `Cache-Control: no-store` and `Pragma: no-cache` to OAuth responses that carry tokens, credentials, or OAuth state, matching the response examples in RFC 6749 §5.1/§5.2: token endpoint responses (success and error), dynamic client registration responses carrying `client_secret`, and EMA JWT-bearer token responses.

- [#207](https://github.com/cloudflare/workers-oauth-provider/pull/207) [`fd6e40b`](https://github.com/cloudflare/workers-oauth-provider/commit/fd6e40b41cc9dbb448a346ef72414aa6824828e5) Thanks [@EfeDurmaz16](https://github.com/EfeDurmaz16)! - Tighten token endpoint client authentication parsing for RFC 6749 compliance.

- [#187](https://github.com/cloudflare/workers-oauth-provider/pull/187) [`a1534c4`](https://github.com/cloudflare/workers-oauth-provider/commit/a1534c4baf67364ebd3b481cf075b32e5a523c8d) Thanks [@Talador12](https://github.com/Talador12)! - Advertise `fragment` in `response_modes_supported` when `allowImplicitFlow` enables the implicit `token` response type. RFC 8414 §2 requires authorization server metadata to list supported response modes; RFC 6749 §4.2.2 delivers implicit-flow access tokens through the redirect URI fragment.

- [#188](https://github.com/cloudflare/workers-oauth-provider/pull/188) [`64aa241`](https://github.com/cloudflare/workers-oauth-provider/commit/64aa241a8959012c5de0cafe8546788b858469e7) Thanks [@Talador12](https://github.com/Talador12)! - Verify client ownership on token revocation (RFC 7009 §2.1) and honor `token_type_hint` for lookup ordering. Previously any client could revoke any other client's tokens.

- [#225](https://github.com/cloudflare/workers-oauth-provider/pull/225) [`601f042`](https://github.com/cloudflare/workers-oauth-provider/commit/601f0426367c63b50602443d8721719dd36673aa) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Validate the authorization code and requesting client before acting on a grant during the authorization code exchange.

  The `/token` authorization code grant now verifies the submitted code against the stored code hash and confirms the requesting client matches the grant's client before any single-use replay handling runs. The auth code hash is retained after exchange so that a replayed code can be verified rather than acted upon based on its `userId:grantId` prefix alone. This ensures a code that does not match the one issued for a grant has no effect on that grant.

## 0.7.2

### Patch Changes

- [#222](https://github.com/cloudflare/workers-oauth-provider/pull/222) [`45397d8`](https://github.com/cloudflare/workers-oauth-provider/commit/45397d8aa57ac0d82c9031e9e0aad588e2e4c1f4) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Add an opt-in `allowPublicClients` flag to `enterpriseManagedAuthorization`.

  By default the enterprise-managed authorization (ID-JAG) grant requires client authentication, so public clients (`token_endpoint_auth_method: 'none'`) are rejected. Setting `allowPublicClients: true` also accepts public clients on this grant — for example clients registered via a Client ID Metadata Document (CIMD), which are always public and cannot present a client secret. The default remains `false`, preserving existing behavior.

## 0.7.1

### Patch Changes

- [#221](https://github.com/cloudflare/workers-oauth-provider/pull/221) [`8e3f08c`](https://github.com/cloudflare/workers-oauth-provider/commit/8e3f08c83e37d5db2bb2a630481408a49006ba10) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Preserve RFC 7591 §2.2 internationalized client metadata variants.

  Localized variants of the human-readable client metadata fields — expressed
  with a `#<BCP 47 language tag>` suffix on the member name (e.g.
  `client_name#ja`, `tos_uri#fr`) — were previously dropped during client
  registration. They are now captured for `client_name`, `client_uri`,
  `logo_uri`, `tos_uri`, and `policy_uri`, stored on the client record under a
  new optional `i18n` map (keyed by the raw `field#tag` name), and echoed back in
  the registration response alongside their canonical fields. The same handling
  applies to Client ID Metadata Document ingestion.

  Localized values are validated with the same rules as their canonical field:
  URI variants must be absolute `http:` or `https:` URLs, and all variants must
  be strings. Fields that are not part of RFC 7591 §2.2 (such as `jwks_uri` and
  `redirect_uris`) are not collected.

- [#218](https://github.com/cloudflare/workers-oauth-provider/pull/218) [`1f8737d`](https://github.com/cloudflare/workers-oauth-provider/commit/1f8737d93f9b5e907e4f2f346a3649fbb416593b) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Validate the URI scheme of client metadata fields during client registration.

  The `client_uri`, `logo_uri`, `policy_uri`, `tos_uri`, and `jwks_uri` fields
  were previously only checked to be strings. They are now required to be
  absolute `http:` or `https:` URLs, consistent with how `redirect_uris` are
  already validated. Registration (and Client ID Metadata Document ingestion)
  now rejects values using other schemes with an `invalid_client_metadata`
  error.

  These fields are commonly surfaced in consent UIs (for example as link or
  image targets), so restricting them to standard web URLs avoids non-http(s)
  schemes flowing through to consumers.

## 0.7.0

### Minor Changes

- [#208](https://github.com/cloudflare/workers-oauth-provider/pull/208) [`c59c37b`](https://github.com/cloudflare/workers-oauth-provider/commit/c59c37bf1ae35dff274d6110c87a56a531659dad) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Experimentally support MCP Enterprise-Managed Authorization ID-JAG assertions through the JWT bearer grant.

- [#206](https://github.com/cloudflare/workers-oauth-provider/pull/206) [`13ff269`](https://github.com/cloudflare/workers-oauth-provider/commit/13ff2695b8e3d16655cb8ec76f9afedd4978b0a0) Thanks [@itsandy-canva](https://github.com/itsandy-canva)! - Expose `grantId` to `tokenExchangeCallback` via `TokenExchangeCallbackOptions`.

  Implementations of `tokenExchangeCallback` already received `userId` and
  `clientId`, but had no way to identify which specific grant the library was
  operating on. This made it impossible to surgically revoke a single grant from
  the callback (e.g. on a terminal upstream refresh failure) — implementations had
  to either sweep all grants for a `(userId, clientId)` pair (racy under
  concurrent refreshes) or maintain their own out-of-band mapping.

  `grantId` is now provided alongside `userId` so callbacks can pass them
  directly to `OAuthHelpers.revokeGrant`. Populated for all three grant types
  (`authorization_code`, `refresh_token`, `token_exchange`). Stable across
  refreshes for the lifetime of the grant.

## 0.6.0

### Minor Changes

- [#199](https://github.com/cloudflare/workers-oauth-provider/pull/199) [`bf7d91e`](https://github.com/cloudflare/workers-oauth-provider/commit/bf7d91e5197fd24ccac935037547faebcf572476) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Convert `OAuthError` thrown from `tokenExchangeCallback` into structured
  `/token` responses and convert token storage KV rate limits into retryable OAuth errors.

  Previously, an error thrown from `tokenExchangeCallback` during the
  `authorization_code` or `refresh_token` grant flows would bubble up as an
  unhandled exception and be served as `500 Internal Server Error`. This forced
  clients to keep retrying with the same dead refresh token, producing
  "refresh-token retry storms" against upstream providers.

  The provider now catches `OAuthError` thrown from the callback (or any code
  it calls — errors propagate naturally up through deep call stacks) and
  returns a standard `{ error, error_description }` response with the supplied
  status code and headers. KV `429 Too Many Requests` write failures while issuing
  tokens are also returned as `temporarily_unavailable` with `Retry-After: 30`,
  so transient storage pressure does not leak Worker `500` responses from the
  token endpoint.

  ```ts
  import { OAuthError } from '@cloudflare/workers-oauth-provider';

  tokenExchangeCallback: async (options) => {
    if (options.grantType === 'refresh_token') {
      // `refreshUpstream` may throw `OAuthError` from any depth.
      return { newProps: await refreshUpstream(options.props) };
    }
  };

  async function refreshUpstream(props) {
    const res = await fetch(/* upstream token endpoint */);
    if (res.status === 401) {
      throw new OAuthError('invalid_grant', {
        description: 'upstream refresh token is invalid',
      });
    }
    if (res.status === 429) {
      throw new OAuthError('temporarily_unavailable', {
        description: 'upstream rate limited',
        statusCode: 429,
        headers: { 'Retry-After': res.headers.get('retry-after') ?? '60' },
      });
    }
    return await res.json();
  }
  ```

  `OAuthError(code, options)` takes:
  - `code` (positional, required) — the OAuth error code returned in the
    `error` field. For standard codes, this package exports the
    `OAuthTokenErrorCode` type.
  - `options.description` — human-readable text returned in `error_description`.
  - `options.statusCode` — HTTP status code (default `400`).
  - `options.headers` — additional response headers. Set `Retry-After` here
    for transient failures so well-behaved clients back off; per RFC 7231
    §7.1.3 the value may be either seconds or an HTTP-date. No implicit
    default — if you don't set it, no `Retry-After` is sent.

  Throwing this package's `OAuthError` class is the supported form. Anything
  else — plain `Error`, plain objects with a `code` field, app-local OAuth
  error classes, etc. — continues to surface as `500 Internal Server Error`
  so unexpected failures stay visible. The provider does not
  catch-everything-and-return-400.

  The exported `OAuthError` class supersedes the previously-internal one: the
  constructor signature is now `(code, options)` rather than `(code, message)`.
  Internal call sites are updated; `description` now lives alongside
  `statusCode` and `headers` in the options object.

  **New exports:** `OAuthError` (class), `OAuthErrorOptions` (interface),
  `OAuthTokenErrorCode` (type union of registered codes).

## 0.5.0

### Minor Changes

- [#182](https://github.com/cloudflare/workers-oauth-provider/pull/182) [`251d641`](https://github.com/cloudflare/workers-oauth-provider/commit/251d6412e746c7abcfcac662112e0d08a9976f7c) Thanks [@threepointone](https://github.com/threepointone)! - Prevent unbounded KV namespace growth with TTL defaults, cascade deletes, and garbage collection.

  **Default TTLs to prevent unbounded storage growth:**
  - `refreshTokenTTL` now defaults to 30 days (previously infinite). Grants auto-expire via KV TTL. Set to `undefined` explicitly to restore the previous behavior of never expiring.
  - `clientRegistrationTTL` (new option) defaults to 90 days. Dynamically registered clients (DCR) auto-expire. Clients created via `OAuthHelpers.createClient()` are not affected. Set to `undefined` for clients that never expire.

  **`deleteClient()` now cascades to grants and tokens:**

  Previously, deleting a client only removed the `client:{id}` record, leaving all associated grants and tokens orphaned in KV. Now `deleteClient()` scans all grants, revokes those belonging to the deleted client (which also deletes their tokens), and then deletes the client record.

  **New `purgeExpiredData()` method for scheduled garbage collection:**

  Defense-in-depth cleanup method designed to be called from a Cron Trigger. Processes records in configurable batches (default: 50) to stay within Cloudflare's subrequest limits. Performs two sweep phases: (1) grant sweep removes orphaned grants (client deleted) and expired grants, (2) token sweep removes orphaned tokens (grant deleted). Safe for CIMD clients — grants with URL-based client IDs are never incorrectly treated as orphaned. Available on both `OAuthHelpers` (via `env.OAUTH_PROVIDER.purgeExpiredData()`) and directly on `OAuthProvider` (via `oauthProvider.purgeExpiredData(env)`) for use in scheduled handlers without a request context.

  **New exports:** `PurgeOptions`, `PurgeResult`

## 0.4.0

### Minor Changes

- [#179](https://github.com/cloudflare/workers-oauth-provider/pull/179) [`57cdbe9`](https://github.com/cloudflare/workers-oauth-provider/commit/57cdbe916c3ddd9ae6caedbaea76f0f1436242df) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Path-aware resource URIs (RFC 9728):
  - Support path-suffixed well-known URLs for OAuth Protected Resource Metadata (RFC 9728 §3.1). Resources with path components (e.g. `https://example.com/mcp`) now correctly serve metadata at `/.well-known/oauth-protected-resource/mcp` and return the derived resource identifier in the `resource` field.
  - Include the request path in the `resource_metadata` URL within `WWW-Authenticate` headers (RFC 9728 §5.1). API endpoints with path components now advertise the correct path-suffixed metadata URL so clients can discover the resource-specific metadata.
  - Add `resourceMatchOriginOnly` option for seamless migration. When enabled, resource downscoping validation compares only the origin (scheme + host + port) instead of exact URI matching, allowing grants issued before v0.4.0 (with origin-only resources) to work with path-aware resource requests without invalidating existing refresh tokens.

## 0.3.3

### Patch Changes

- [#176](https://github.com/cloudflare/workers-oauth-provider/pull/176) [`38d1e6b`](https://github.com/cloudflare/workers-oauth-provider/commit/38d1e6b3ce555577c0b1bd45daabd6baa5748b0e) Thanks [@threepointone](https://github.com/threepointone)! - Reverting 0.3.2

## 0.3.2

### Patch Changes

- [#173](https://github.com/cloudflare/workers-oauth-provider/pull/173) [`1fe656e`](https://github.com/cloudflare/workers-oauth-provider/commit/1fe656e896e4253b15b873ce46bdd8cca7e69998) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Support path-suffixed well-known URLs for OAuth Protected Resource Metadata (RFC 9728 §3.1). Resources with path components (e.g. `https://example.com/mcp`) now correctly serve metadata at `/.well-known/oauth-protected-resource/mcp` and return the derived resource identifier in the `resource` field.

- [#174](https://github.com/cloudflare/workers-oauth-provider/pull/174) [`ac120ff`](https://github.com/cloudflare/workers-oauth-provider/commit/ac120ff26b8de627230b778a258ef1dac5bf9266) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Include the request path in the `resource_metadata` URL within `WWW-Authenticate` headers (RFC 9728 §5.1). API endpoints with path components (e.g. `/mcp`) now advertise the correct path-suffixed metadata URL so clients can discover the resource-specific metadata.

## 0.3.1

### Patch Changes

- [#169](https://github.com/cloudflare/workers-oauth-provider/pull/169) [`46629cc`](https://github.com/cloudflare/workers-oauth-provider/commit/46629cc7d7c1e47a7b2c3dc6d9f6ac7f8963a81e) Thanks [@rlucioni](https://github.com/rlucioni)! - Allow any port for localhost redirect URIs to support native apps that use localhost with ephemeral ports like Claude Code

## 0.3.0

### Minor Changes

- [#158](https://github.com/cloudflare/workers-oauth-provider/pull/158) [`b26f7ff`](https://github.com/cloudflare/workers-oauth-provider/commit/b26f7ff7320a2f60f6b033b6990ceb14e72b0262) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Add `clientIdMetadataDocumentEnabled` option to make CIMD (Client ID Metadata Document) support explicitly opt-in. Previously, CIMD auto-enabled when the `global_fetch_strictly_public` compatibility flag was present, which could cause crashes for servers where URL-shaped client_ids hit bot-protected endpoints. When not enabled (the default), URL-formatted client_ids now fall through to standard KV lookup instead of throwing.

- [#144](https://github.com/cloudflare/workers-oauth-provider/pull/144) [`49a1d24`](https://github.com/cloudflare/workers-oauth-provider/commit/49a1d24b298984b623eec6d780eb6c9bf2fd01bb) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Add `revokeExistingGrants` option to `completeAuthorization()` that revokes existing grants for the same user+client after creating a new one. Defaults to `true`, fixing infinite re-auth loops when props change between authorizations (issue #34). Set to `false` to allow multiple concurrent grants per user+client.

  Revoke tokens and grant when an authorization code is reused, per RFC 6749 §10.5. This prevents authorization code replay attacks by invalidating all tokens issued from the first exchange.

  **Breaking behavior change:** Previously, re-authorizing the same user+client created an additional grant, leaving old tokens valid. Now, old grants are revoked by default. If your application relies on multiple concurrent grants per user+client, set `revokeExistingGrants: false` to preserve the old behavior.

### Patch Changes

- [#164](https://github.com/cloudflare/workers-oauth-provider/pull/164) [`4b640a3`](https://github.com/cloudflare/workers-oauth-provider/commit/4b640a31c7af021d03f430363499d0f2e6a241df) Thanks [@pnguyen-atlassian](https://github.com/pnguyen-atlassian)! - Include `client_secret_expires_at` and `client_secret_issued_at` in dynamic client registration responses when a `client_secret` is issued, per RFC 7591 §3.2.1.

- [#165](https://github.com/cloudflare/workers-oauth-provider/pull/165) [`9cce070`](https://github.com/cloudflare/workers-oauth-provider/commit/9cce0707653e465e4066b97fd3d14ec9d889b504) Thanks [@mattzcarey](https://github.com/mattzcarey)! - Use `Promise.allSettled` instead of `Promise.all` for best-effort grant revocation in `completeAuthorization()`, ensuring all grants are attempted even if one fails.

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
