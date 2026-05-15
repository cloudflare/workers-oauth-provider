# MCP Enterprise-Managed Authorization — Canonical Specification

Source: <https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/draft/enterprise-managed-authorization.mdx>
Status: **draft**
MCP extension URI: `io.modelcontextprotocol/enterprise-managed-authorization`

Companion explainer page: <https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization>
Original SEP: <https://modelcontextprotocol.io/seps/990-enable-enterprise-idp-policy-controls-during-mcp-o>

---

## 1. Scope

This specification defines how to apply the **Identity Assertion Authorization Grant** ("Identity and Authorization Chaining Across Domains") within enterprise deployments where both MCP Client and MCP Server leverage single sign-on through an enterprise Identity Provider.

**Benefits:**
- End users avoid manual authorization for each MCP Server connection.
- Enterprise admins gain visibility and control over MCP Server usage via the IdP.
- MCP clients obtain access tokens automatically without user interaction.
- Token renewal happens transparently.

## 2. Roles

| Role | Definition |
|------|-----------|
| Resource Application | The MCP Server (MRS in diagrams). |
| Identity Provider (IdP) | Authenticates the user; issues both ID Tokens and ID-JAGs. |
| Authorization Server (AS / MAS) | Issues access tokens for the MCP Server. **This is what `workers-oauth-provider` provides.** |
| Client | The MCP Client. |
| ID Token | OpenID Connect security token with user authentication claims. |
| Subject Token | Identity assertion (OIDC ID Token or SAML) representing the user. |
| JAG | JWT Authorization Grant per RFC 7523. |
| **ID-JAG** | Identity Assertion JWT Authorization Grant — the EMA-specific JWT signed by the IdP. |

## 3. Flow Overview

```
sequenceDiagram
    participant UA as Browser
    participant C as MCP Client
    participant IdP as Identity Provider
    participant MAS as MCP Authorization Server
    participant MRS as MCP Resource Server

    C-->>UA: Redirect to IdP
    UA->>IdP: Redirect to IdP
    Note over IdP: User Logs In
    IdP-->>UA: IdP Authorization Code
    UA->>C: IdP Authorization Code
    C->>IdP: Token Request with IdP Authorization Code
    IdP-->>C: ID Token

    note over C: User is logged in to MCP Client. Client stores ID Token.

    C->>IdP: Exchange ID Token for ID-JAG (RFC 8693)
    note over IdP: Evaluate Policy
    IdP-->>C: Responds with ID-JAG
    C->>MAS: Token Request with ID-JAG (RFC 7523)
    note over MAS: Validate ID-JAG
    MAS-->>C: MCP Access Token

    loop
        C->>MRS: Call MCP API with Access Token
        MRS-->>C: MCP Response with Data
    end
```

**Three logical steps:**
1. **SSO** — user authenticates via OIDC or SAML; client receives Identity Assertion.
2. **Token Exchange (RFC 8693)** — client exchanges the Identity Assertion at the **IdP** for an ID-JAG. (Performed by the *client*, not by us.)
3. **JWT Authorization Grant (RFC 7523)** — client presents the ID-JAG at the **AS** token endpoint. (This is what we implement.)

## 4. Step 2 — Token Exchange at the IdP (NOT our endpoint)

> *Documented here for context; this happens at the IdP, not the MCP AS.*

### 4.1 Request

```
POST /oauth2/token HTTP/1.1
Host: acme.idp.example
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&requested_token_type=urn:ietf:params:oauth:token-type:id-jag
&audience=https://auth.chat.example/
&resource=https://mcp.chat.example/
&scope=chat.read+chat.history
&subject_token=eyJraWQiOi...
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&client_id=2ec954a1d60620116d36d9ceb7
&client_secret=...
```

| Parameter | Required | Meaning |
|-----------|----------|---------|
| `grant_type` | REQUIRED | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `requested_token_type` | REQUIRED | `urn:ietf:params:oauth:token-type:id-jag` |
| `audience` | REQUIRED | Issuer URL of MCP Authorization Server |
| `resource` | REQUIRED | RFC 9728 resource identifier of MCP server |
| `scope` | OPTIONAL | Space-separated scopes at MCP server |
| `subject_token` | REQUIRED | The Identity Assertion (ID Token or SAML) |
| `subject_token_type` | REQUIRED | `urn:ietf:params:oauth:token-type:id_token` or `…:saml2` |

**IdP processing:**
- MUST validate the Subject Token.
- MUST validate that the Subject Token's `aud` matches `client_id`.
- Evaluates administrator-defined policy.
- May enforce step-up auth based on auth context.

### 4.2 Successful Response

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "access_token": "eyJhbGciOi...",
  "token_type": "N_A",
  "scope": "chat.read chat.history",
  "expires_in": 300
}
```

| Field | Status | Notes |
|-------|--------|-------|
| `issued_token_type` | REQUIRED | `urn:ietf:params:oauth:token-type:id-jag` |
| `access_token` | REQUIRED | The ID-JAG JWT (parameter name is misleading — RFC 8693 §2.2.1) |
| `token_type` | REQUIRED | `N_A` — the ID-JAG is not an OAuth access token |
| `scope` | conditional | OPTIONAL if identical to requested, else REQUIRED |
| `expires_in` | RECOMMENDED | Lifetime in seconds |

### 4.3 Error Response (RFC 6749 §5.2)

```
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_grant",
  "error_description": "Audience validation failed"
}
```

## 5. The ID-JAG (the JWT we validate)

### 5.1 JOSE Header

The `typ` header parameter **MUST** be `oauth-id-jag+jwt`.

### 5.2 Claims

| Claim | Required | Description | Ref |
|-------|----------|-------------|-----|
| `iss` | REQUIRED | IdP issuer URL | RFC 7519 §4.1.1 |
| `sub` | REQUIRED | Subject identifier (user ID) at MCP Server | RFC 7519 §4.1.2 |
| `aud` | REQUIRED | Authorization Server Issuer URL | RFC 7519 §4.1.3 |
| `resource` | REQUIRED | Resource identifier of MCP Server | RFC 9728 §1.2 |
| `client_id` | REQUIRED | MCP Client identifier registered at AS | RFC 8693 §4.3 |
| `jti` | REQUIRED | Unique JWT ID | RFC 7519 §4.1.7 |
| `exp` | REQUIRED | Expiration time (Unix seconds) | RFC 7519 §4.1.4 |
| `iat` | REQUIRED | Issued-at time (Unix seconds) | RFC 7519 §4.1.6 |
| `scope` | OPTIONAL | Space-separated scopes | RFC 6749 §3.3 |

**Additional claims:** IdP MAY add additional claims as necessary (e.g., `email` for account linking).

### 5.3 Example (claims, decoded)

```jsonc
// Header
{ "typ": "oauth-id-jag+jwt" }
// Payload
{
  "jti": "9e43f81b64a33f20116179",
  "iss": "https://acme.idp.example",
  "sub": "U019488227",
  "aud": "https://auth.chat.example/",
  "resource": "https://mcp.chat.example/",
  "client_id": "f53f191f9311af35",
  "exp": 1311281970,
  "iat": 1311280970,
  "scope": "chat.read chat.history"
}
```

## 6. Step 3 — Access Token Request at the AS (OUR ENDPOINT)

### 6.1 Request

```
POST /oauth2/token HTTP/1.1
Host: auth.chat.example
Authorization: Basic yZS1yYW5kb20tc2VjcmV0...

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
assertion=eyJhbGciOiJIUzI1NiIsI...
```

| Parameter | Required | Meaning |
|-----------|----------|---------|
| `grant_type` | REQUIRED | `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523 §4.1) |
| `assertion` | REQUIRED | The ID-JAG JWT |

**Client authentication:** MCP Client authenticates with credentials registered at the AS.

**Dynamic Client Registration:** If the MCP Client has not yet registered at the AS, it MAY perform RFC 7591 DCR at this stage. *(The PR #203 implementation does not require DCR; existing static / DCR'd clients can use jwt-bearer if they have `tokenEndpointAuthMethod !== 'none'`.)*

### 6.2 Processing Rules

All of **RFC 7521 §5.2** applies (assertion framework MUSTs), plus:

- Validate JWT `typ` is `oauth-id-jag+jwt` per **RFC 8725**.
- The assertion's `aud` claim **MUST** identify the AS Issuer URL.
- The assertion's `client_id` claim **MUST** match the authenticated client.

### 6.3 Successful Response (OAuth 2.0 Token Response)

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "token_type": "Bearer",
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "expires_in": 86400,
  "scope": "chat.read chat.history"
}
```

## 7. Security Considerations

### 7.1 Client Registration

- IdP policy typically permits only pre-registered clients for user sign-in.
- MCP Client MUST be pre-registered with the enterprise IdP for SSO.
- MCP Client MUST also be pre-registered with the AS.

**Client ID mapping:** For the IdP to include the correct `client_id` in the ID-JAG, the IdP must be aware of the MCP Client's `client_id` at the MCP Server. This mapping occurs **outside the protocol** — during feature configuration in the IdP admin console.

### 7.2 Enterprise Policy Enforcement

The IdP enforces:
- Which users can use which MCP clients with which MCP servers.
- Scope granularity per user group.

Example: Engineering group gets read-only access from AI code editor → source-control MCP server; marketing group gets read-write access to internal docs MCP.

## 8. Summary of Responsibilities

### IdP
- Validate Subject Token.
- Verify token audience matches requesting `client_id`.
- Evaluate administrator policies.
- Create and sign ID-JAG with required claims.
- Support RFC 8693 Token Exchange endpoint.

### MCP Client
- Obtain and store ID Token from IdP.
- Request ID-JAG via RFC 8693 Token Exchange.
- Submit ID-JAG to AS via RFC 7523 JWT Bearer Grant.
- Use resulting access token for MCP Server requests.

### MCP Authorization Server (us)
- Validate ID-JAG JWT signature and claims.
- Verify `aud` matches issuer URL.
- Verify `client_id` in JWT matches authenticated client.
- Issue access token with appropriate scope.

## 9. Open Questions (worth surfacing on PR #203)

1. **Refresh tokens** — the spec is silent. PR #203 omits them. Should EMA grants be refreshable? If so, by re-presenting the ID-JAG (which is short-lived) or by issuing an opaque refresh token tied to the grant?
2. **Resource binding** — the ID-JAG's `resource` MUST point to one MCP server. What if the AS fronts multiple? The PR handles this via `resourceMatches(claims.resource, configuredResource, …)`.
3. **AS metadata for EMA-only servers** — RFC 9728 does not define a "this resource is EMA-only" field. The spec relies on `grant_types_supported` to omit `authorization_code`. PR #203 keeps `authorization_code` advertised even when EMA is on.
4. **Account linking** — `sub` is opaque to the AS; `iss+sub` is unique. The IdP MAY include `email`. PR #203's `mapClaims` callback gives deployers full freedom but no built-in linking helper.
