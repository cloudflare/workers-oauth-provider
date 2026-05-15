# EMA Flow — From the AS's Perspective

This is what `workers-oauth-provider` actually has to do on the wire.

The other parties (IdP, MCP Client) are documented for context, but the AS's job is just **steps 6–11 below**.

## Full sequence (with the AS highlighted)

```
┌─────────┐         ┌──────────┐         ┌─────────┐         ┌──────────────┐         ┌─────────────┐
│ Browser │         │ MCP Cli  │         │   IdP   │         │  AS (us)     │         │ MCP Server  │
└────┬────┘         └────┬─────┘         └────┬────┘         └──────┬───────┘         └──────┬──────┘
     │                   │                    │                     │                        │
     │  ① redirect to IdP                     │                     │                        │
     │ ◀─────────────────┤                    │                     │                        │
     │ ② OIDC /authorize                      │                     │                        │
     │ ────────────────────────────────────▶  │                     │                        │
     │ ③ code via redirect                    │                     │                        │
     │ ◀───────────────────────────────────── │                     │                        │
     │                   │                    │                     │                        │
     │                   │ ④ POST /token (code) │                   │                        │
     │                   │ ─────────────────▶ │                     │                        │
     │                   │ ID Token           │                     │                        │
     │                   │ ◀───────────────── │                     │                        │
     │                   │                    │                     │                        │
     │                   │ ⑤ POST /token (RFC 8693 exchange)        │                        │
     │                   │ ─────────────────▶ │                     │                        │
     │                   │ ID-JAG             │                     │                        │
     │                   │ ◀───────────────── │                     │                        │
     │                   │                    │                     │                        │
     │                   │ ⑥ POST /token (RFC 7523 jwt-bearer) ────▶│                        │
     │                   │                    │                     │                        │
     │                   │                    │ ⑦ GET jwks_uri      │                        │
     │                   │                    │ ◀───────────────── ─│                        │
     │                   │                    │ JWKS                │                        │
     │                   │                    │ ──────────────────▶ │                        │
     │                   │                    │                     │                        │
     │                   │                    │              ⑧ verify signature              │
     │                   │                    │              ⑨ validate claims               │
     │                   │                    │              ⑩ replay-check jti              │
     │                   │                    │              ⑪ mint access token             │
     │                   │                    │                     │                        │
     │                   │ ⑫ access_token (Bearer) ◀────────────────│                        │
     │                   │                    │                     │                        │
     │                   │ ⑬ MCP API + Authorization: Bearer …      │                        │
     │                   │ ─────────────────────────────────────────────────────────────────▶│
     │                   │ MCP response                                                      │
     │                   │ ◀───────────────────────────────────────────────────────────────── │
```

## The AS's responsibilities (steps 6–11)

### ① Receive token request (step 6)

```
POST /oauth2/token HTTP/1.1
Host: as.example.com
Authorization: Basic Y2xpZW50OnNlY3JldA==
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
&assertion=<ID-JAG>
&scope=<optional>
&resource=<optional, RFC 8707>
```

**Pre-checks** (before touching the JWT):
- Authenticate the client via standard mechanisms (basic auth, client_secret_post). PR #203 also rejects `tokenEndpointAuthMethod === 'none'` clients for EMA.
- Reject if EMA isn't enabled in config.
- Reject if `assertion` missing or empty.
- Reject if `assertion` exceeds size cap.

### ② JWT structural parse (step 7 pre-work)

- Split on `.`, expect 3 non-empty parts.
- Base64url-decode header → JSON object.
- Base64url-decode payload → JSON object.
- Build the signing input (`header.payload`) as a `Uint8Array`.
- Base64url-decode signature.

### ③ JOSE header validation

- `typ` MUST equal `oauth-id-jag+jwt` (RFC 8725 §3.11).
- `alg` MUST be in the AS's global allowlist (e.g. `{RS256, ES256}`).
- `alg` MUST be in the matched trusted issuer's `algorithms` allowlist.

### ④ Issuer trust check

- Read `iss` claim.
- Look up `iss` in the trusted-issuer registry (`trustedIssuers` config).
- Reject if not found.

### ⑤ Key resolution + signature verification (step 7+8)

- Fetch the issuer's JWKS (with caching).
- Filter keys: `kid` match (if header has one); `use=sig`; `key_ops` includes `verify`; `kty` consistent with `alg`.
- If no key matched AND there was a `kid`, force-refresh the JWKS once and retry (handles key rotation).
- Import the JWK via WebCrypto, verify the signature.
- Reject on any failure.

### ⑥ Claim validation (step 9)

Required claims:
- `iss` (string) — already used above.
- `sub` (string).
- `aud` (string or array of strings) — MUST contain the AS's expected audience (either the per-issuer override or the AS's issuer URL).
- `resource` (string, RFC 8707 valid) — MUST match the AS's configured resource (modulo `resourceMatchOriginOnly`).
- `client_id` (string) — MUST equal the authenticated client's `clientId`.
- `jti` (string).
- `exp` (integer Unix seconds) — MUST be in the future.
- `iat` (integer Unix seconds) — MUST NOT be more than `clockSkewSeconds` in the future.

Bounds checks:
- `exp - iat <= maxAssertionLifetime + clockSkewSeconds` (rejects long-lived assertions).

Optional:
- `scope` (space-separated, RFC 6749 §3.3 grammar).
- Additional claims are preserved and forwarded to the `mapClaims` callback.

### ⑦ Replay protection (step 10)

- Compute `hash(iss || "\n" || jti)`.
- KV `get` — if present, reject as replay.
- KV `put` with TTL = `exp - now` (so the marker self-expires).
- **Known gap**: KV is not CAS, so two concurrent requests can both see "no marker" and both succeed. Documented in the PR; acceptable for best-effort but not strict-once semantics.

### ⑧ Authorization (`mapClaims` callback, step 11 prep)

- Compute `requestedScope` = intersection of (body.scope ∪ default) and ID-JAG scope.
- Invoke deployer's `mapClaims({ claims, clientInfo, resource, requestedScope, env })`.
- The callback returns `{ userId, scope, props, metadata?, accessTokenTTL? }` or `null` to deny.
- Validate the result shape (userId non-empty, no `:` separator, scope is array of valid tokens, props defined).

### ⑨ Token issuance (step 11)

- `tokenScopes` = `downscope(mapper.scope, assertion.scope)` — never grant more than the IdP authorized.
- `accessTokenTTL` = `min(config.accessTokenTTL, assertion.exp - now, mapper.accessTokenTTL?)`.
- Generate `grantId`, encrypt `props` (existing machinery), persist a `Grant` row keyed by `grant:userId:grantId` with TTL.
- Mint an opaque access token via existing `createAccessToken` (audience = `resource`).

### ⑩ Response

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "...",
  "token_type": "bearer",
  "expires_in": 3600,
  "scope": "chat.read chat.history",
  "resource": "https://mcp.chat.example/"
}
```

*(Note: PR #203 returns `token_type: "bearer"` (lowercase). RFC 6749 §5.1 says "Bearer" — case-insensitive per RFC 6750. Pre-existing behavior in this repo, not an EMA-specific issue.)*

## What we DO NOT do

- We do **not** implement the RFC 8693 token-exchange endpoint for EMA (that's the IdP's job in step 5).
- We do **not** redirect the user anywhere (no `/authorize` involvement for EMA).
- We do **not** issue refresh tokens for EMA grants (PR #203 omits this; the spec is silent).
- We do **not** verify the user's Identity Assertion ourselves (we trust the IdP, which already did this in step 5).
- We do **not** require PKCE (RFC 7636 does not apply to jwt-bearer).

## Configuration shape (current PR)

```ts
new OAuthProvider({
  // existing options …
  enterpriseManagedAuthorization: {
    enabled: true,
    trustedIssuers: [
      {
        issuer: 'https://acme.idp.example',
        jwksUri: 'https://acme.idp.example/.well-known/jwks.json',
        algorithms: ['RS256', 'ES256'],   // optional, defaults to ['RS256']
        audience: 'https://auth.chat.example/',  // optional, defaults to AS issuer
      },
    ],
    async mapClaims({ claims, clientInfo, resource, requestedScope, env }) {
      // deployer-controlled: turn IdP claims into local user/props
      return {
        userId: claims.sub,
        scope: requestedScope,
        props: { email: claims.email },
      };
    },
    jwksCacheTtl: 300,          // optional
    clockSkewSeconds: 60,       // optional
    maxAssertionLifetime: 300,  // optional
  },
});
```

The shape is reasonable; my structural critique below is about how it's *implemented*, not how it's *exposed*.
