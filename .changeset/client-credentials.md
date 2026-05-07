---
'@cloudflare/workers-oauth-provider': minor
---

Add `client_credentials` grant type for M2M auth (RFC 6749 §4.4). Enable with `allowClientCredentialsGrant: true`. Confidential clients only, no refresh token issued.

- M2M grants set `userId === clientId` and store an explicit `type: 'client_credentials'` discriminator on the `Grant` record. API handlers should detect M2M structurally via the grant's `type` field or `props.clientId`, not by inspecting `userId`.
- The `Grant` interface gains an optional `type: GrantType` field. Existing grants without a `type` field are treated as `authorization_code` for backward compatibility.
- Token responses set both `Cache-Control: no-store` and `Pragma: no-cache` per RFC 6749 §5.1.
- The `resource` parameter (RFC 8707) is honored to bind tokens to a specific resource server — required for MCP-targeting deployments, where MCP servers MUST validate token audience.
- `tokenExchangeCallback` fires for `client_credentials` with `grantType: 'client_credentials'`, allowing implementers to override scope, TTL, or props.
