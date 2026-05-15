# RFC Reference for MCP Enterprise-Managed Authorization

Implementer-focused notes for an OAuth Authorization Server that issues access tokens in exchange for an ID-JAG signed by an enterprise IdP. Order is rough dependency order: format primitives first, then grant mechanics, then metadata.

---

## RFC 6749 — OAuth 2.0 Core (token endpoint + errors only)

Link: <https://datatracker.ietf.org/doc/html/rfc6749>

**Purpose.** Defines the OAuth 2.0 framework. For EMA you only need the token endpoint and the error response shape — ID-JAG is an *extension grant* (§4.5) plugged into this endpoint.

**Sections directly relevant to EMA.**
- §3.2 Token Endpoint — `POST` only, `application/x-www-form-urlencoded`, TLS required, params in body.
- §3.3 Scope — space-delimited, case-sensitive; AS MAY narrow requested scope and MUST echo the resulting `scope` if different.
- §4.5 Extension Grants — the mechanism that lets `urn:ietf:params:oauth:grant-type:jwt-bearer` and `…:token-exchange` exist.
- §5.1 Successful Response — `200 OK` + `application/json` + `Cache-Control: no-store` + `Pragma: no-cache`.
- §5.2 Error Response — `400 Bad Request` + `application/json`; `invalid_client` returns `401` (and `WWW-Authenticate` if HTTP auth was used).

**Normative MUSTs that matter to EMA.**
- AS MUST require TLS at the token endpoint.
- AS MUST return `Cache-Control: no-store` and `Pragma: no-cache` on token responses (both success and error).
- AS MUST authenticate confidential clients; public clients MUST be identified.
- On any failure to validate the grant, AS MUST return an error response with one of the codes below.

**Concrete values defined here.**
- Success response fields: `access_token` (REQUIRED), `token_type` (REQUIRED), `expires_in` (RECOMMENDED), `refresh_token` (OPTIONAL), `scope` (conditional).
- Error response fields: `error` (REQUIRED), `error_description`, `error_uri`.
- Standard error codes: `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`.

**Pitfalls.**
- Don't return `403`/`500` for grant validation failures — invalid ID-JAGs are `400 invalid_grant`, not server errors.
- `invalid_client` is the only code that returns `401`; mixing this up confuses clients that distinguish credential vs. grant failures.
- `error_description` MUST be ASCII printable — no JSON, no newlines.

---

## RFC 7519 — JSON Web Token (JWT)

Link: <https://datatracker.ietf.org/doc/html/rfc7519>

**Purpose.** The wire format for ID-JAGs. Defines registered claims and the JOSE header.

**Sections directly relevant to EMA.**
- §4.1 Registered Claim Names — `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`.
- §5.1 `typ` Header Parameter — application-level media type marker (EMA uses `oauth-id-jag+jwt`).
- §7.2 JWT Validation — the 10-step decode/parse/verify pipeline; failure of any step ⇒ reject.

**Claim semantics implementers MUST internalize.**

| Claim | Type | EMA meaning |
|---|---|---|
| `iss` | StringOrURI | The enterprise IdP. The AS uses this to look up the IdP's signing keys (JWKS) and to confirm the IdP is trusted for this client. |
| `sub` | StringOrURI | The end user being asserted, scoped to the IdP. Must be locally unique within `iss` or globally unique. |
| `aud` | StringOrURI or array | The AS's own identifier (issuer URL). If `aud` doesn't contain this AS's identity, AS MUST reject. |
| `exp` | NumericDate (sec since epoch) | Current time MUST be strictly before `exp`. Small clock skew leeway permitted (≤ a few minutes). |
| `nbf` | NumericDate | If present, current time MUST be ≥ `nbf`. |
| `iat` | NumericDate | Issuance time; AS MAY reject "unreasonably old" assertions. |
| `jti` | case-sensitive string | Unique ID; collision probability MUST be negligible. Used for replay prevention. |

**Normative MUSTs.**
- `aud` validation: "If the principal processing the claim does not identify itself with a value in the 'aud' claim when this claim is present, then the JWT MUST be rejected."
- `exp` validation: "current date/time MUST be before the expiration date/time listed in the 'exp' claim."
- If §7.2 validation fails at any step, AS MUST reject.
- After successful validation, "unless the algorithms used in the JWT are acceptable to the application, it SHOULD reject the JWT" (algorithm allowlist).
- `jti` collisions MUST be prevented across multiple issuers if applicable.

**Concrete values.**
- `typ` is OPTIONAL per RFC 7519 but RECOMMENDED per RFC 8725 §3.11 (see below) — and is REQUIRED in practice for ID-JAG (`oauth-id-jag+jwt`).
- `NumericDate` = JSON number of seconds since 1970-01-01T00:00:00Z (NOT milliseconds, NOT ISO 8601 string).

**Pitfalls.**
- `aud` may be a string OR an array of strings. Verifiers must handle both shapes.
- `exp`/`nbf`/`iat` are seconds, not milliseconds — a common JS bug.
- `iss` and `aud` comparison is exact string match (per RFC 3986 §6.2.1 unless profile specifies). Don't normalize URLs (trailing slash matters).
- `typ` is ignored by the JOSE layer — the *application* must check it.

---

## RFC 7521 — Assertion Framework

Link: <https://datatracker.ietf.org/doc/html/rfc7521>

**Purpose.** Abstract framework for using assertions (SAML, JWT, etc.) as either authorization grants or client authentication credentials. RFC 7523 specializes this to JWT.

**Sections directly relevant to EMA.**
- §4.1 Assertion as Authorization Grant — parameter shape: `grant_type` + `assertion` + optional `scope`.
- §4.2 Assertion for Client Authentication — `client_assertion_type` + `client_assertion`.
- §5.2 General Assertion Format and Processing Rules — the abstract MUST-list.
- §6 Security Considerations — audience restriction, replay protection.

**§5.2 processing rules the AS MUST enforce.**
1. Assertion MUST contain an Issuer; Issuer identifies the entity that issued the assertion as recognized by the AS.
2. Assertion MUST contain a Subject — the authorized accessor (for grants) or the `client_id` (for client auth).
3. Assertion MUST contain an Audience identifying the AS. AS MUST reject if its own identity is not in the audience.
4. Assertion MUST contain an Expires At. AS MUST reject expired assertions (clock-skew leeway allowed).
5. AS MUST reject assertions with invalid signature/MAC.
6. AS MAY reject assertions with unreasonably distant expiration.

**Normative MUSTs.**
- All six items above are MUSTs (except item 6 which is MAY).
- §4.1: `scope` requested via assertion MUST NOT exceed the originally granted scope.
- §6: AS SHOULD implement replay protection using `jti` (or assertion ID) + window enforced by `iat`/`exp`.

**Pitfalls.**
- The framework is profile-agnostic — actual checks (`iss` ↔ JWKS lookup, exact format of `sub`, etc.) come from the JWT profile (RFC 7523). Don't try to implement §5.2 in isolation.
- "Issuer recognized by the AS" implies a *trust registry* — the AS must know which `iss` values are accepted. For EMA this is the per-client IdP mapping.

---

## RFC 7523 — JWT Bearer Grant (CENTRAL)

Link: <https://datatracker.ietf.org/doc/html/rfc7523>

**Purpose.** Profiles the assertion framework for JWT. Defines the exact grant type that EMA uses on the token endpoint when the client redeems an ID-JAG for an access token.

**Sections directly relevant to EMA.**
- §2.1 Using JWTs as Authorization Grants — the wire format.
- §3 JWT Format and Processing Requirements — the 10-rule validator.
- §3.1 (within §3) — error path: failures yield `invalid_grant`.
- §4 — JWT-based client authentication.
- §5 Interoperability — out-of-band agreements; mandatory algorithm.

**§2.1 request format (the request EMA's token endpoint receives).**

```
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
&assertion=<ID-JAG JWT>
&scope=<optional>
```

- `grant_type` (REQUIRED) = `urn:ietf:params:oauth:grant-type:jwt-bearer`
- `assertion` (REQUIRED) = a single JWT. "MUST contain a single JWT."
- `scope` (OPTIONAL) — must not exceed what the JWT authorizes.
- Client authentication is OPTIONAL on this grant; if credentials are presented, AS MUST validate them.

**§3 validation rules (the 10 things AS MUST do on the ID-JAG).**
1. JWT MUST contain `iss` — unique identifier of the issuer; AS uses simple string compare (RFC 3986 §6.2.1).
2. JWT MUST contain `sub` identifying the principal (resource owner / delegated user).
3. JWT MUST contain `aud` containing this AS's identity. AS MUST reject otherwise. Token endpoint URL is a valid audience value.
4. JWT MUST contain `exp` in the future (modulo skew). AS MUST reject expired JWTs.
5. JWT MAY contain `nbf` — if present, current time MUST be ≥ `nbf`.
6. JWT MAY contain `iat`; AS may reject overly old assertions.
7. JWT MAY contain `jti`; AS SHOULD use it for replay prevention.
8. JWT MAY contain other claims (e.g., `client_id`, `act`, custom `oauth-id-jag` claims).
9. JWT MUST be signed or MACed. AS MUST reject invalid signatures.
10. AS MUST reject if invalid "in all other respects" per RFC 7519.

**§4 client authentication via JWT.**
When the same JWT-bearer mechanism is used for *client auth* (not the grant), parameters are:
- `client_assertion_type` = `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
- `client_assertion` = a single JWT; MUST NOT contain more than one.
- In this mode `sub` MUST equal the `client_id`.

EMA may legitimately use *both* in one request: the ID-JAG carried in `assertion` (subject = end user), and a client JWT in `client_assertion` (subject = client_id).

**Errors.** Validation failure ⇒ `400` + `{"error":"invalid_grant", "error_description":"..."}`.

**Concrete values.**
- `urn:ietf:params:oauth:grant-type:jwt-bearer`
- `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
- Mandatory-to-implement signing alg: **RS256**.

**Pitfalls.**
- The JWT-bearer grant is **not** the same as the token-exchange grant. EMA uses jwt-bearer on the *AS endpoint*; token-exchange happens at the *IdP* in step 2.
- `sub` in the ID-JAG is the end user, NOT the client. Mixing this up with §4 client-assertion semantics is the most common bug.
- "Simple string match" on `iss`/`aud` means `https://idp.example.com` and `https://idp.example.com/` are different audiences. Document the exact string.
- A confidential client identified by `client_id` in the form-encoded body still requires the AS to confirm that the ID-JAG's `iss` is trusted *for that client* — otherwise any IdP could mint a token for any client.

---

## RFC 8693 — OAuth 2.0 Token Exchange (the OTHER half of EMA)

Link: <https://datatracker.ietf.org/doc/html/rfc8693>

**Purpose.** Generalized cross-domain token exchange. **In EMA this happens at the IdP** (step 2), not at our AS. Our AS does NOT implement an RFC 8693 token-exchange endpoint for EMA; it implements RFC 7523 jwt-bearer.

**Sections directly relevant to EMA's context.**
- §2.1 Request — params and `grant_type` (used by clients against the IdP).
- §2.2 Response — `issued_token_type` + `token_type`.
- §2.2.1 — successful response fields (incl. `N_A`).
- §3 Token Type Identifiers — URIs for `jwt`, `access_token`, `id_token`, etc.
- §4.3 `client_id` claim — records the OAuth client.

**§2.1 request parameters (sent to IdP in step 2).**

| Parameter | Status | EMA usage |
|---|---|---|
| `grant_type` | REQUIRED | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | REQUIRED | The user's Identity Assertion (ID Token or SAML) |
| `subject_token_type` | REQUIRED | `urn:ietf:params:oauth:token-type:id_token` or `…:saml2` |
| `requested_token_type` | REQUIRED for EMA | `urn:ietf:params:oauth:token-type:id-jag` |
| `audience` | REQUIRED | The AS's issuer URL |
| `resource` | REQUIRED | The MCP server URL (RFC 8707) |
| `scope` | OPTIONAL | Requested scopes |

**§2.2 response (returned from IdP, consumed by client).**
- `access_token` (REQUIRED) — actually the ID-JAG.
- `issued_token_type` (REQUIRED) — `urn:ietf:params:oauth:token-type:id-jag`.
- `token_type` (REQUIRED) — `N_A` (because the ID-JAG is not an OAuth access token).
- `expires_in` (RECOMMENDED).
- `scope` (REQUIRED if differs from requested).

**§4.3 `client_id` claim** — records the OAuth client that requested the token. The ID-JAG includes this so the AS knows which client made the request, distinct from the user (`sub`).

**Pitfalls (for context).**
- "Token type" (`Bearer` vs `N_A`) and "token type identifier" (`urn:ietf:params:oauth:token-type:access_token`) are different namespaces. `token_type` is how to *use* it; `issued_token_type`/`subject_token_type` are *what it is*.

---

## RFC 8725 — JWT Best Current Practices

Link: <https://datatracker.ietf.org/doc/html/rfc8725>

**Purpose.** Hardening rules for JWT verifiers. Directly applicable to ID-JAG validation; §3.11 is the basis for `typ=oauth-id-jag+jwt`.

**Sections directly relevant to EMA.**
- §2.1–§2.8 Threats — algorithm substitution, `alg=none`, key confusion, cross-JWT confusion.
- §3.1 Perform Algorithm Verification — enforce expected `alg`.
- §3.2 Use Appropriate Algorithms — restrict alg set; reject `none` by default.
- §3.3 Validate All Cryptographic Operations — reject the entire JWT if any op fails.
- §3.8 Validate Issuer and Subject — bind cryptographic key to claimed `iss`.
- §3.9 Use and Validate Audience — `aud` required and validated.
- §3.10 Do Not Trust Received Claims — re-derive locally where possible.
- §3.11 Use Explicit Typing — `typ` with application-specific media type.
- §3.12 Use Mutually Exclusive Validation Rules — separate different JWT kinds.

**§3.11 — explicit typing rule for ID-JAG.**
- Format: `<token-kind>+jwt`, no `application/` prefix (e.g., `oauth-id-jag+jwt`, parallel to `at+jwt` in RFC 9068).
- Validator MUST check `typ` and reject any value other than the expected ID-JAG type.

**Normative requirements that apply to ID-JAG validators.**
- The AS MUST enforce a strict allowlist of `alg` values for ID-JAGs (e.g., {`RS256`, `ES256`, `PS256`, `EdDSA`}). Reject `none` by default.
- MUST verify `alg` header matches the algorithm used cryptographically (block alg-swap attacks).
- MUST reject the JWT if any cryptographic operation fails.
- SHOULD use one or more of: distinct `typ`, distinct `aud`, distinct required claims, distinct keys per JWT kind, to prevent cross-JWT confusion.
- MUST validate `aud` and reject if absent or not addressed to this verifier.
- MUST validate that the verification key actually belongs to the claimed `iss` (typically by fetching the IdP's JWKS from a URL bound to `iss`, not from a claim inside the JWT).

**Pitfalls.**
- The infamous `alg:none` and `RS256→HS256` attacks: a verifier that trusts `alg` from the header alone, or uses public RSA keys as HMAC secrets, is exploitable. Use a library that takes the expected alg as input.
- `kid` in the header is a hint, not a security boundary — never look up keys based on a `kid` from an *untrusted* origin without first resolving `iss` to a JWKS URI you trust.
- "Cross-JWT confusion": without `typ`, an ID-JAG could be re-presented as a different JWT type. The `typ=oauth-id-jag+jwt` check is what stops this.

---

## RFC 9728 — OAuth Protected Resource Metadata

Link: <https://datatracker.ietf.org/doc/html/rfc9728>

**Purpose.** Lets a Protected Resource (the MCP server) advertise its OAuth requirements. For EMA, this is how an MCP server signals it accepts tokens minted via the ID-JAG flow.

**Sections directly relevant to EMA.**
- §2 Metadata Parameters.
- §3 Discovery URL — `/.well-known/oauth-protected-resource`.

**Key fields (§2).**

| Field | EMA usage |
|---|---|
| `resource` | The MCP server's canonical resource identifier (HTTPS URL, no fragment). Used as `aud` of issued tokens and as `resource` claim in the ID-JAG. |
| `authorization_servers` | Array of issuer identifiers — for EMA, the AS that mints access tokens from ID-JAGs. |
| `scopes_supported` | Scopes the MCP server understands. |
| `bearer_methods_supported` | Typically `["header"]`. |

**EMA-specific signaling.**
RFC 9728 does *not* define a "this resource is EMA-only" field. In practice EMA-only resources signal this by:
1. Listing only EMA-aware authorization servers in `authorization_servers`.
2. Letting the AS's metadata (RFC 8414) advertise `urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types_supported` while *not* advertising `authorization_code`.

**Normative MUSTs.**
- `resource` MUST be an HTTPS URL with no fragment.
- The returned `resource` MUST match the request URL.

---

## RFC 8414 — OAuth Authorization Server Metadata

Link: <https://datatracker.ietf.org/doc/html/rfc8414>

**Purpose.** Lets the AS advertise its own endpoints and capabilities. For EMA, the AS must advertise that it supports the jwt-bearer grant.

**Sections directly relevant to EMA.**
- §2 Metadata Fields.
- §3 Discovery URL — `/.well-known/oauth-authorization-server`.

**Fields an EMA AS MUST or SHOULD set.**

| Field | Value/notes |
|---|---|
| `issuer` | REQUIRED. HTTPS URL identifying this AS; appears in `aud` of received ID-JAGs. |
| `token_endpoint` | REQUIRED. |
| `grant_types_supported` | MUST include `urn:ietf:params:oauth:grant-type:jwt-bearer` for EMA. |
| `scopes_supported` | RECOMMENDED. |
| `token_endpoint_auth_methods_supported` | E.g. `client_secret_basic`, `client_secret_post`, `none`. |

**Pitfalls.**
- `issuer` is matched exactly. `https://as.example.com` vs `https://as.example.com/` are different issuers and will cause `aud` mismatches.
- If `grant_types_supported` is absent, RFC 8414 defaults it to `["authorization_code", "implicit"]` — wrong for an EMA-aware AS. Always set it explicitly.

---

## RFC 7591 — Dynamic Client Registration (DCR)

Link: <https://datatracker.ietf.org/doc/html/rfc7591>

**Purpose.** Lets clients self-register at the AS. Relevant to EMA because the spec says clients MAY DCR at first contact.

**Sections directly relevant to EMA.**
- §2 Client Metadata.
- §3 Registration Endpoint.
- §3.2.1 Successful Response.
- §3.2.2 Error Responses.

**Client metadata fields that matter for EMA.**

| Field | EMA usage |
|---|---|
| `grant_types` | MUST include `urn:ietf:params:oauth:grant-type:jwt-bearer` |
| `token_endpoint_auth_method` | `client_secret_basic`, `client_secret_post`, or `none`. PR #203 rejects `none` for EMA. |

**EMA-specific considerations.**
- DCR alone cannot establish IdP-to-client trust. The AS needs an out-of-band binding between `client_id` and the allowed `iss` of incoming ID-JAGs. The current PR sidesteps this by trusting the global `trustedIssuers` config and checking `claims.client_id === clientInfo.clientId`.

---

## RFC 8707 — Resource Indicators

Link: <https://datatracker.ietf.org/doc/html/rfc8707>

**Purpose.** Defines the `resource` parameter. EMA uses it twice: as a token-exchange request parameter at the IdP, and as a claim inside the ID-JAG.

**Format rules.**
- MUST be an absolute URI (RFC 3986 §4.3).
- MUST NOT include a fragment.
- SHOULD use HTTPS scheme.
- Path components ARE allowed and encouraged for specificity.

**EMA usage.**
- Inside the ID-JAG: the IdP includes the resource the user was authorized to access (so the AS can confirm the requested `resource` is within scope).
- Issued access token `aud` reflects this resource.

---

## RFC 7517 + RFC 7518 — JWK / JWA (key formats and algorithms)

Links:
- <https://datatracker.ietf.org/doc/html/rfc7517>
- <https://datatracker.ietf.org/doc/html/rfc7518>

**Purpose.** Define the wire format of cryptographic keys (RFC 7517) and the algorithm identifiers used in `alg` headers (RFC 7518). EMA verifiers must fetch the IdP's JWKS and pick the right key.

**RFC 7517 §4 — JWK parameters used by an ID-JAG verifier.**

| Parameter | Use |
|---|---|
| `kty` | REQUIRED. `"RSA"` or `"EC"` (for `RS256`/`ES256`/`PS256`). |
| `use` | `"sig"` (signature) — filter out encryption-only keys. |
| `key_ops` | Permitted ops; `"verify"` is what you want. |
| `alg` | If present, narrows which alg this key may be used with. |
| `kid` | Key ID; matched against the JWT header `kid`. |

**RFC 7518 §3.1 — JWS algorithms relevant to ID-JAG.**

| `alg` | Algorithm | Recommendation |
|---|---|---|
| `RS256` | RSASSA-PKCS1-v1_5 + SHA-256 | Recommended (mandatory for RFC 7523 implementations) |
| `ES256` | ECDSA P-256 + SHA-256 | Recommended+ |
| `PS256` | RSASSA-PSS + SHA-256 | Optional |
| `EdDSA` | Ed25519/Ed448 | Optional |
| `none` | No signature | MUST NOT be accepted |

**EMA verifier workflow.**
1. Validate `iss` of incoming ID-JAG is in your IdP trust registry.
2. Fetch IdP's JWKS URL.
3. From `jwks.keys`, pick the JWK matching `header.kid` (and if `use`/`alg` present, matching those).
4. Verify the signature using the algorithm from `header.alg`, ensuring it's in your allowlist.
5. Cache JWKS with bounded TTL; refresh on unknown `kid` (with rate limit).

**Pitfalls.**
- Never trust `header.alg` to choose the key type.
- Polling JWKS on every request kills the IdP; cache and rotate based on `Cache-Control` headers.
- A `kid` collision across different `iss` values is possible — always scope the JWKS to the trusted `iss`.

---

## RFC 7636 — PKCE (does NOT apply to jwt-bearer)

Link: <https://datatracker.ietf.org/doc/html/rfc7636>

**Purpose.** Mitigates authorization-code interception on the *authorization code* grant for public clients.

**Does PKCE apply to ID-JAG?** **No.**

- PKCE binds an authorization request to a token request via a verifier/challenge round-trip across the authorization endpoint and token endpoint. The jwt-bearer grant makes no authorization-endpoint round-trip; the client presents the assertion *directly* to the token endpoint.
- The interception attack PKCE prevents (a stolen `code` value) has no analogue in jwt-bearer — there is no `code`. The ID-JAG is itself the bearer credential, secured by signature, audience binding, and `exp`/`jti`.

**Implication for EMA.**
- Do NOT require `code_challenge_methods_supported` for an EMA-only AS.
- Do NOT accept `code_verifier` on jwt-bearer requests.
- If your AS supports both authorization_code and jwt-bearer, PKCE applies only to the former.

---

## RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens (parallel pattern)

Link: <https://datatracker.ietf.org/doc/html/rfc9068>

**Purpose.** Standardizes JWT-formatted access tokens. *Not* an ID-JAG. Included here only because ID-JAG's `typ=oauth-id-jag+jwt` follows the same explicit-typing pattern as `typ=at+jwt` defined here.

**The pattern (parallel to ID-JAG).**

| RFC 9068 access token | EMA ID-JAG |
|---|---|
| `typ=at+jwt` | `typ=oauth-id-jag+jwt` |
| Issued by AS, consumed by Resource Server | Issued by IdP, consumed by AS |
| Required: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id` | Required: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, `resource` |
| Purpose of explicit `typ`: prevent confusion with OIDC ID tokens | Purpose of explicit `typ`: prevent confusion with access tokens / ID tokens / other JWT-bearer assertions |

---

## Quick-reference: link block

```
RFC 6749 (OAuth 2.0):              https://datatracker.ietf.org/doc/html/rfc6749
RFC 7519 (JWT):                    https://datatracker.ietf.org/doc/html/rfc7519
RFC 7521 (Assertion Framework):    https://datatracker.ietf.org/doc/html/rfc7521
RFC 7523 (JWT Bearer Grant):       https://datatracker.ietf.org/doc/html/rfc7523
RFC 8693 (Token Exchange):         https://datatracker.ietf.org/doc/html/rfc8693
RFC 8725 (JWT BCP):                https://datatracker.ietf.org/doc/html/rfc8725
RFC 9728 (Protected Resource Md):  https://datatracker.ietf.org/doc/html/rfc9728
RFC 8414 (AS Metadata):            https://datatracker.ietf.org/doc/html/rfc8414
RFC 7591 (Dynamic Client Reg):     https://datatracker.ietf.org/doc/html/rfc7591
RFC 8707 (Resource Indicators):    https://datatracker.ietf.org/doc/html/rfc8707
RFC 7517 (JWK):                    https://datatracker.ietf.org/doc/html/rfc7517
RFC 7518 (JWA):                    https://datatracker.ietf.org/doc/html/rfc7518
RFC 7636 (PKCE):                   https://datatracker.ietf.org/doc/html/rfc7636
RFC 9068 (JWT Access Tokens):      https://datatracker.ietf.org/doc/html/rfc9068
```

---

## Cross-cutting MUST checklist for our EMA token endpoint

When the AS receives a token request with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and an ID-JAG in `assertion`:

1. **Transport**: TLS only (RFC 6749 §3.2).
2. **Form parse**: `application/x-www-form-urlencoded`, exactly one `assertion` parameter.
3. **Size guard**: cap the assertion length before parsing.
4. **JOSE parse**: 3-segment JWS, base64url-decode header.
5. **Header checks**:
   - `typ == "oauth-id-jag+jwt"` (RFC 8725 §3.11; reject otherwise).
   - `alg` in your allowlist; `alg != "none"`.
6. **Resolve issuer**: Look up `payload.iss` in the AS's IdP trust registry; reject if unknown (RFC 7523 §3 rule 1).
7. **Resolve key**: Fetch IdP JWKS (RFC 7517/§5), match by `kid`; ensure `use=sig` and `alg` compatible.
8. **Verify signature** (RFC 7523 §3 rule 9).
9. **Validate claims**:
   - `aud` contains this AS's identity (RFC 7523 §3 rule 3; reject otherwise).
   - `exp` is in the future, modulo small skew (RFC 7523 §3 rule 4).
   - `iat` not unreasonably old (and not too far in the future, modulo skew).
   - `sub` present.
   - `jti` — store with TTL = `exp - now`; reject on replay (RFC 7523 §3 rule 7).
   - `client_id` claim matches authenticated `client_id`.
   - `resource` is a valid RFC 8707 URI.
10. **Resource binding**: verify `resource` matches the AS's configured resource.
11. **Scope**: requested `scope` MUST NOT exceed what the ID-JAG implies (RFC 7521 §4.1).
12. **Issue access token**: `200 OK` + `Cache-Control: no-store` + `Pragma: no-cache` + JSON containing `access_token`, `token_type` (`Bearer`), `expires_in`, `scope`, `resource`.
13. **On failure**: `400` + `{"error":"invalid_grant", "error_description":"<reason>"}` (RFC 7523 §3.1); use `invalid_target` for bad `resource` (RFC 8707).

---

## Where each MUST lives in PR #203 (mapping)

| Check | PR #203 location |
|-------|------------------|
| TLS | Inherited from Workers runtime |
| Form parse | `parseRequestBody` (pre-existing) |
| Size guard | `oauth-provider.ts:2924` (`ENTERPRISE_MAX_JWT_BYTES`) |
| JOSE parse | `parseJwt` at line 3180 |
| `typ` check | `validateEnterpriseAssertion` line 3046 |
| `alg` allowlist | line 3055 (`ENTERPRISE_SUPPORTED_JWT_ALGORITHMS`) + per-issuer `algorithms` line 3068 |
| IdP trust registry | `trustedIssuers.find` line 3060 (linear scan) |
| JWKS fetch | `fetchEnterpriseJwks` line 3228 |
| Signature verify | `verifyEnterpriseJwtSignature` line 3198 |
| `aud` check | `validateEnterpriseClaims` line 3113 |
| `exp` check | line 3140 |
| `iat` skew check | line 3144 |
| Max lifetime check | line 3148 |
| `jti` replay | `storeEnterpriseAssertionJti` line 3299 (KV-based, non-atomic) |
| `client_id` match | line 3119 |
| `resource` URI valid | line 3123 (`validateResourceUri`) |
| Resource matches AS config | line 3127 (`resourceMatches`) |
| Scope downscoping | line 2974 (`downscope`) |
| Response shape | line 3021 |
