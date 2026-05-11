# Enterprise-Managed Authorization Implementation Plan

## Summary

Add opt-in support for the MCP Enterprise-Managed Authorization extension in `@cloudflare/workers-oauth-provider`, then expose the capability through Cloudflare Agents SDK for developers building authenticated MCP servers and agents.

The extension enables an enterprise IdP to authorize MCP client access centrally. The MCP client obtains an Identity Assertion JWT Authorization Grant, or ID-JAG, from the enterprise IdP and exchanges that JWT at the MCP Authorization Server for a normal MCP access token.

This should be implemented as an explicit, experimental opt-in until the MCP extension and the underlying IETF Identity Assertion Authorization Grant draft are stable.

## References

- MCP Enterprise-Managed Authorization extension: `https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization`
- Extension draft spec: `https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/draft/enterprise-managed-authorization.mdx`
- MCP authorization spec: `https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization`
- OAuth JWT Bearer Assertion Profiles: RFC 7521 and RFC 7523
- OAuth Token Exchange: RFC 8693
- OAuth Resource Indicators: RFC 8707
- OAuth Protected Resource Metadata: RFC 9728
- JSON Web Token Best Current Practices: RFC 8725

## Current State

`workers-oauth-provider` already has several required building blocks:

- OAuth authorization code and refresh token grant support.
- Optional RFC 8693 token exchange support for exchanging internal access tokens.
- RFC 8707 resource/audience storage and validation.
- RFC 9728 protected resource metadata endpoint and `WWW-Authenticate` challenges.
- Dynamic Client Registration and Client ID Metadata Document support.
- Encrypted token props and hashed opaque token storage.

Missing pieces:

- JWT bearer grant support at the token endpoint.
- ID-JAG validation against enterprise IdP JWKS.
- Trusted issuer configuration.
- Replay protection for ID-JAG `jti` values.
- Claim-to-user and claim-to-props mapping hooks.
- Authorization server metadata advertising for the new grant type.
- MCP extension capability declaration in Agents SDK server initialization.
- Agents SDK client-side support for requesting ID-JAGs from enterprise IdPs.

## Goals

- Let a Workers-based MCP Authorization Server accept valid enterprise IdP-issued ID-JAG assertions.
- Issue normal `workers-oauth-provider` opaque access tokens after successful ID-JAG validation.
- Preserve the existing token storage security model.
- Require explicit opt-in and trusted issuer configuration.
- Provide application hooks for user identity, permissions, and props mapping.
- Make it straightforward for Cloudflare Agents SDK MCP servers to advertise and require the extension.

## Non-Goals

- Do not make enterprise-managed authorization the default.
- Do not implement enterprise IdP policy management.
- Do not implement a full OpenID Connect client for end-user login inside `workers-oauth-provider`.
- Do not accept arbitrary JWT issuers.
- Do not add refresh token issuance for ID-JAG grants by default.
- Do not replace the existing authorization code flow.

## Proposed Provider API

Add an option to `OAuthProviderOptions`:

```ts
new OAuthProvider({
  // Existing options...
  enterpriseManagedAuthorization: {
    enabled: true,
    trustedIssuers: [
      {
        issuer: 'https://acme.idp.example',
        jwksUri: 'https://acme.idp.example/.well-known/jwks.json',
        algorithms: ['RS256', 'ES256'],
        audience: 'https://auth.example.com',
      },
    ],
    async mapClaims({ claims, clientInfo, resource, requestedScope }) {
      return {
        userId: `${claims.iss}:${claims.sub}`,
        scope: requestedScope,
        metadata: {
          enterpriseIssuer: claims.iss,
          enterpriseSubject: claims.sub,
        },
        props: {
          enterprise: true,
          issuer: claims.iss,
          subject: claims.sub,
          email: claims.email,
        },
      };
    },
  },
});
```

Proposed exported types:

```ts
export interface EnterpriseManagedAuthorizationOptions {
  enabled?: boolean;
  trustedIssuers: EnterpriseTrustedIssuer[];
  mapClaims: EnterpriseClaimsMapper;
  jwksCacheTtl?: number;
  clockSkewSeconds?: number;
  assertionReplayTtl?: number;
}

export interface EnterpriseTrustedIssuer {
  issuer: string;
  jwksUri: string;
  algorithms?: string[];
  audience?: string;
}

export interface EnterpriseClaimsMapperInput {
  claims: EnterpriseIdJagClaims;
  clientInfo: ClientInfo;
  resource: string;
  requestedScope: string[];
  env: unknown;
}

export interface EnterpriseClaimsMapperResult {
  userId: string;
  scope: string[];
  metadata?: unknown;
  props: unknown;
  accessTokenTTL?: number;
}

export type EnterpriseClaimsMapper = (
  input: EnterpriseClaimsMapperInput
) => Promise<EnterpriseClaimsMapperResult | null> | EnterpriseClaimsMapperResult | null;
```

`mapClaims()` returning `null` denies issuance with `invalid_grant`.

## Token Endpoint Flow

Support this request when enterprise-managed authorization is enabled:

```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <client credentials>

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=<id-jag-jwt>
```

Processing sequence:

1. Parse and authenticate the OAuth client using existing token endpoint client authentication.
2. Dispatch `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` to a new handler.
3. Parse the JWT header and payload without trusting claims yet.
4. Validate header `typ` is `oauth-id-jag+jwt`.
5. Validate `alg` is allowed and not `none`.
6. Resolve trusted issuer by `iss`.
7. Fetch or read cached JWKS for the issuer.
8. Verify the JWT signature with WebCrypto.
9. Validate required claims.
10. Check `jti` replay protection in KV.
11. Call `mapClaims()`.
12. Create a grant record and access token using existing encrypted props flow.
13. Return a standard OAuth access token response.

Response shape:

```json
{
  "access_token": "opaque-workers-oauth-provider-token",
  "token_type": "bearer",
  "expires_in": 300,
  "scope": "chat.read chat.history",
  "resource": "https://mcp.example.com/mcp"
}
```

## ID-JAG Validation Rules

Required JWT header validation:

- `typ` MUST be `oauth-id-jag+jwt`.
- `alg` MUST be an asymmetric signing algorithm from the trusted issuer config.
- `kid` SHOULD be present when the issuer JWKS contains multiple keys.
- `alg=none` MUST be rejected.

Required claim validation:

- `iss` MUST exactly match a configured trusted issuer.
- `sub` MUST be present and non-empty.
- `aud` MUST match this authorization server issuer.
- `resource` MUST be a valid absolute URI without a fragment.
- `client_id` MUST equal the authenticated OAuth client ID.
- `jti` MUST be present and unique until assertion expiry.
- `exp` MUST be present and in the future, allowing configured clock skew.
- `iat` MUST be present and not unreasonably far in the future.
- `scope`, when present, MUST be parsed as a space-separated scope string.

Recommended additional validation:

- Reject assertions with very long lifetimes, even if `exp` is valid.
- Limit accepted JWT size.
- Limit JWKS response size.
- Require HTTPS JWKS URIs.
- Reject duplicate critical claims if JSON parsing behavior permits detection.

## JWT and JWKS Implementation

Use WebCrypto to avoid runtime dependencies if practical.

Supported algorithms for an initial release:

- `RS256`
- `ES256`

Potential follow-up algorithms:

- `RS384`
- `RS512`
- `ES384`
- `EdDSA`, if Workers WebCrypto support is sufficient.

JWKS behavior:

- Fetch from configured `jwksUri` only.
- Require HTTPS.
- Enforce timeout and size limits.
- Cache in memory per isolate for a short TTL.
- Optionally cache in KV for cross-isolate reuse if needed later.
- On unknown `kid`, refresh JWKS once before failing.

If implementing robust JOSE support becomes too complex, evaluate adding a small audited dependency, but that requires an explicit dependency decision because this package currently has zero runtime dependencies.

## Replay Protection

Store each accepted assertion `jti` in KV:

```txt
enterprise-jti:<sha256(issuer + "\n" + jti)> -> expiresAt
```

KV TTL:

- Minimum of assertion remaining lifetime and configured `assertionReplayTtl`.
- Default should be bounded, for example 5 minutes or the assertion expiration, whichever is smaller.

Behavior:

- If key already exists, reject with `invalid_grant`.
- Store the replay key before issuing the access token.
- If token issuance fails after storing replay key, keep the replay key. This is safer than allowing assertion reuse.

## Grant and Token Storage

Use existing grant and token structures where possible.

Recommended grant characteristics:

- `clientId` from the authenticated OAuth client.
- `userId` from `mapClaims()`.
- `scope` from `mapClaims()`, downscoped from the ID-JAG scope when present.
- `metadata` from `mapClaims()`.
- `encryptedProps` from existing `encryptProps()`.
- `resource` from ID-JAG `resource`.
- No authorization code fields.
- No refresh token fields by default.
- `expiresAt` matching the issued access token expiration, unless a future refresh strategy is explicitly added.

Access token TTL:

- Default to the provider `accessTokenTTL`.
- Clamp to the assertion remaining lifetime.
- Allow `mapClaims()` to return a shorter `accessTokenTTL`.

Refresh tokens:

- Do not issue by default for JWT bearer assertions.
- If added later, require revalidation against the enterprise IdP or a fresh ID-JAG exchange.

## Authorization Server Metadata

When enabled, include the JWT bearer grant in `grant_types_supported`:

```json
{
  "grant_types_supported": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
}
```

Consider exposing extension-specific metadata only if the MCP extension specifies a stable field. Until then, avoid inventing public metadata fields unless needed for interoperability.

## Protected Resource Metadata

The extension guide says MCP servers should declare the extension in authorization metadata. There is not yet a stable field in the draft for OAuth protected resource metadata.

Plan:

- Add a generic opt-in `resourceMetadata.extensions` field only if the extension spec formalizes it.
- Otherwise, keep OAuth metadata standards-compliant and let the MCP initialize capability advertise the extension.
- Continue using existing `authorization_servers`, `scopes_supported`, and `resource` fields.

## Error Handling

Use OAuth token endpoint errors:

- `invalid_request` for missing `assertion` or malformed request.
- `unsupported_grant_type` when the feature is disabled.
- `invalid_grant` for invalid, expired, replayed, or unauthorized assertions.
- `invalid_client` for client authentication failures.
- `invalid_target` for invalid or unacceptable `resource`.

Avoid leaking detailed JWT validation failures in `error_description`. Log details server-side through existing `onError` or a new internal diagnostic path.

## Provider Implementation Tasks

1. Add constants and types.
   - Add `GrantType.JWT_BEARER`.
   - Add ID-JAG token type constants.
   - Add enterprise option interfaces.
   - Add JSDoc for public interfaces.

2. Validate constructor options.
   - Require at least one trusted issuer when enabled.
   - Require `mapClaims` when enabled.
   - Validate issuer and JWKS URLs.
   - Validate allowed algorithms.

3. Update metadata.
   - Advertise JWT bearer grant only when enabled.
   - Ensure existing metadata remains unchanged by default.

4. Add token endpoint dispatch.
   - Route `urn:ietf:params:oauth:grant-type:jwt-bearer` to `handleJwtBearerGrant()`.
   - Reject when disabled.

5. Implement JWT parsing helpers.
   - Base64url decode.
   - JSON parse with size limits.
   - Header and claim shape validation.

6. Implement JWKS verification.
   - Fetch JWKS with timeout and size limits.
   - Cache JWKS.
   - Select key by `kid` and `alg`.
   - Verify signature with WebCrypto.

7. Implement ID-JAG claim validation.
   - Validate issuer, audience, client, resource, time, `jti`, and scope.
   - Clamp TTL to assertion lifetime.

8. Implement replay protection.
   - Hash issuer and `jti`.
   - Store replay marker in KV with TTL.
   - Reject duplicate markers.

9. Implement token issuance.
   - Call `mapClaims()`.
   - Downscope callback scopes against assertion scopes when present.
   - Create grant and access token.
   - Return standard OAuth token response.

10. Update documentation.

- README feature section.
- Security notes.
- Example enterprise configuration.
- Explain that IdP setup is external.

11. Add tests.

- Unit tests for JWT parsing and claim validation.
- Integration tests for token endpoint flow.
- Regression tests proving default behavior is unchanged.

## Provider Test Plan

Positive tests:

- Accept a valid ID-JAG and issue an access token.
- Set `ctx.props` from mapped claims when the access token is used.
- Clamp access token TTL to assertion expiration.
- Respect scopes from the assertion.
- Respect scope reductions from `mapClaims()`.
- Validate audience/resource when calling the MCP endpoint.

Negative tests:

- Feature disabled returns `unsupported_grant_type`.
- Missing `assertion` returns `invalid_request`.
- Malformed JWT returns `invalid_grant`.
- Wrong `typ` returns `invalid_grant`.
- Unsupported `alg` returns `invalid_grant`.
- Bad signature returns `invalid_grant`.
- Unknown issuer returns `invalid_grant`.
- Wrong `aud` returns `invalid_grant`.
- Wrong `client_id` returns `invalid_grant`.
- Invalid `resource` returns `invalid_target` or `invalid_grant` depending on validation phase.
- Expired assertion returns `invalid_grant`.
- Future `iat` outside skew returns `invalid_grant`.
- Replayed `jti` returns `invalid_grant`.
- `mapClaims()` returning `null` returns `invalid_grant`.
- Public client behavior is explicit and tested.

Security tests:

- Reject `alg=none`.
- Reject key confusion between RSA and EC keys.
- Reject JWKS over non-HTTPS.
- Enforce JWT size limit.
- Enforce JWKS size limit.
- Refresh JWKS once on unknown `kid`.

## Agents SDK Server Integration

For developers building MCP servers with Agents SDK:

1. Add a documented OAuthProvider configuration example using `enterpriseManagedAuthorization`.
2. Add a helper or recipe for declaring the extension in MCP server capabilities:

```json
{
  "capabilities": {
    "extensions": {
      "io.modelcontextprotocol/enterprise-managed-authorization": {}
    }
  }
}
```

3. Ensure `createMcpHandler()` continues to pass `ctx.props` into `getMcpAuthContext()`.
4. Document that enterprise identity claims are available through `getMcpAuthContext()` after mapping.
5. Add an authenticated MCP worker example using an enterprise IdP test fixture.

Potential ergonomic API:

```ts
createMcpHandler(server, {
  authContext: undefined,
  extensions: {
    enterpriseManagedAuthorization: true,
  },
});
```

Only add SDK API if the MCP TypeScript SDK exposes stable extension capability hooks. Otherwise, document how to set capabilities directly on the MCP server.

## Agents SDK Client Integration

Agents SDK can also act as an MCP client. Full enterprise-managed support on that side is larger.

Required client-side capabilities:

- Store organization IdP configuration.
- Authenticate the user to the enterprise IdP.
- Store the resulting identity assertion securely.
- Request an ID-JAG from the IdP using RFC 8693 token exchange.
- Send the ID-JAG to the MCP Authorization Server using JWT bearer grant.
- Store the resulting MCP access token using existing MCP client token storage.
- Avoid redirecting users to the MCP server authorization endpoint when enterprise-managed auth is required.

Client token exchange request to IdP:

```http
POST /oauth2/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&requested_token_type=urn:ietf:params:oauth:token-type:id-jag
&audience=https://auth.example.com
&resource=https://mcp.example.com/mcp
&subject_token=<id-token-or-saml-assertion>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
```

Client token exchange request to MCP Authorization Server:

```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=<id-jag-jwt>
```

## Agents SDK Client Rollout Strategy

Start with server-side support only:

1. `workers-oauth-provider` accepts ID-JAG and issues MCP access tokens.
2. Agents SDK MCP servers can advertise the extension and consume mapped auth context.
3. Examples show how an enterprise-compatible MCP client would call the flow.

Then add client-side support:

1. Add organization-level IdP config types.
2. Extend `DurableObjectOAuthClientProvider` or add a parallel enterprise provider.
3. Add ID-JAG token exchange support.
4. Add discovery and negotiation behavior once client implementations converge.

## Security Review Focus

- JWT algorithm confusion.
- JWKS SSRF and response size abuse.
- Assertion replay.
- Issuer and tenant confusion for multi-tenant IdPs.
- Incorrect `aud` matching.
- Incorrect `client_id` binding.
- Resource/audience mismatch.
- Scope escalation through `mapClaims()`.
- Leaking identity claims into unencrypted grant metadata.
- Refresh token semantics and enterprise revocation expectations.
- Public client authentication expectations.

## Open Questions

- Should public clients with `token_endpoint_auth_method=none` be allowed to use JWT bearer enterprise grants, or should enterprise mode require confidential clients by default?
- Should `audience` default to the authorization server issuer origin or the full configured issuer URL?
- Should JWKS cache be memory-only, KV-backed, or both?
- Should the provider expose a dedicated enterprise audit callback for accepted and rejected assertions?
- Should `mapClaims()` receive raw headers for tenant-specific key or policy decisions?
- Should the first release support only `RS256` to minimize crypto surface?
- Should the Agents SDK expose extension capabilities directly, or rely on MCP SDK primitives?

## Milestones

### Milestone 1: Provider Core

- Add opt-in options and metadata advertising.
- Add JWT bearer grant dispatch.
- Add JWT verification and claim validation.
- Add replay protection.
- Issue access tokens with mapped props.
- Add comprehensive tests.

### Milestone 2: Provider Documentation and Example

- Document enterprise-managed authorization configuration.
- Add a Workers example with a test JWKS.
- Document security guidance and limitations.

### Milestone 3: Agents SDK Server Support

- Add docs for declaring MCP extension capability.
- Add authenticated MCP worker example.
- Confirm mapped props are available through `getMcpAuthContext()`.

### Milestone 4: Agents SDK Client Support

- Add enterprise IdP configuration model.
- Add ID-JAG request flow.
- Add JWT bearer exchange flow.
- Add token storage and refresh/reacquisition behavior.

## Release Strategy

- Release as experimental and opt-in.
- Use a minor version for `workers-oauth-provider` because this adds public API and OAuth behavior.
- Do not change existing OAuth flows by default.
- Add a changeset describing enterprise-managed authorization support.
- Mark Agents SDK client-side support separately if it lands later.

## Minimal First Implementation

The smallest useful provider-side implementation is:

1. Configured trusted issuer with `jwksUri`.
2. `RS256` verification only.
3. JWT bearer grant support.
4. Required claim validation.
5. KV replay protection.
6. `mapClaims()` hook.
7. Opaque access token issuance without refresh tokens.
8. Tests and docs.

That would allow enterprise-compatible MCP clients to use Workers-hosted MCP authorization servers while keeping the existing authorization code flow unchanged.
