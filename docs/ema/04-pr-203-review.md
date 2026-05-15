# Structural Review — PR cloudflare/workers-oauth-provider#203

**Target:** `experiment/enterprise-managed-authorization` branch, commits `82ff083` + `5312e11`.
**Scope:** 1 changeset, 4 files, **+1639 / −2**.
**Files touched:**
- `src/oauth-provider.ts` +824
- `__tests__/oauth-provider.test.ts` +750
- `README.md` +60
- `.changeset/enterprise-managed-authorization.md` +5

The author explicitly flags this as "**not intended to be merged**" — an experiment to scope the work. That's the right framing for what's here. The protocol is correct; the structure isn't shippable.

## 1. What works

The implementation gets the protocol right:
- `typ=oauth-id-jag+jwt` enforced — RFC 8725 §3.11 ✓
- `alg=none` rejected — RFC 8725 §3.2 ✓
- WebCrypto-based signature verification with `RS256` and `ES256` ✓
- JWKS fetched with timeout + size cap + `cacheEverything` ✓
- Per-issuer `algorithms` allowlist on top of the global one ✓
- `aud` accepts both string and array forms — RFC 7519 §4.1.3 ✓
- `client_id` claim cross-checked against authenticated client ✓
- `resource` validated as RFC 8707 URI and matched against AS config ✓
- `exp` / `iat` / `maxAssertionLifetime` bounded with skew ✓
- JTI replay via KV with TTL = `exp - now` ✓ (known race)
- `mapClaims` hook gives deployers full control over user/props mapping ✓
- Comprehensive tests (~750 lines) cover the happy path and a wide set of failure modes ✓

The functional surface is solid. The problems are all structural.

## 2. Structural problems

### 2.1 EMA smeared across the monolith

The new code adds **13 private methods** and a stateful `Map` field to `OAuthProviderImpl`:

| Method | Line | What it does |
|--------|------|--------------|
| `validateEnterpriseManagedAuthorizationOptions` | 1455 | Config validation |
| `handleJwtBearerGrant` | 2905 | The 128-line god-method (see §2.4) |
| `validateEnterpriseAssertion` | 3037 | Parse + typ/alg + issuer + sig + claims + jti |
| `validateEnterpriseClaims` | 3091 | Claim-level validation |
| `getEnterpriseRequestedScopes` | 3160 | Scope param parsing |
| `parseJwt` | 3180 | Generic JWT parser |
| `verifyEnterpriseJwtSignature` | 3198 | Signature verification |
| `fetchEnterpriseJwks` | 3228 | JWKS HTTP fetch + cache |
| `selectJwk` | 3277 | Key picker |
| `storeEnterpriseAssertionJti` | 3299 | KV replay marker |
| `getRequiredClaimString` | 3313 | Claim helper |
| `getRequiredAudienceClaim` | 3321 | Audience claim helper |
| `getRequiredNumericDateClaim` | 3332 | Numeric date helper |

Plus a `jwksCache: Map<string, CachedJwks>` instance field (line 1335).

**Why this is wrong:** Almost none of these methods need `this`. They take config and inputs, produce outputs. They're pure functions or thin I/O wrappers wearing class-method clothing. The `OAuthProviderImpl` class is already 2,800 lines doing five other jobs; piling EMA onto it just makes it harder to audit.

**Counter-argument: AGENTS.md says "single-file architecture is intentional for security review."**
This holds, but "single file" ≠ "one giant class". You can have one file with clearly demarcated regions of pure functions + a thin orchestrator on the class. That's what this restructure proposes.

### 2.2 Constants 2,700 lines away from their use

```ts
// Used at line 3046
const ENTERPRISE_ID_JAG_JWT_TYPE = 'oauth-id-jag+jwt';

// Used at line 2924
const ENTERPRISE_MAX_JWT_BYTES = 16 * 1024;

// ... defined at lines 4142–4182
```

Constants live in the module footer. Reading a method, you don't see the magic numbers it depends on. Co-locate.

### 2.3 Error handling: throw-based + lossy

Every validation failure does:

```ts
throw new OAuthError('invalid_grant', 'Invalid assertion');
```

The string `'Invalid assertion'` appears **18 times** in the EMA code path. That's intentional for wire-level security (don't leak which check failed to an attacker probing the IdP), but two problems:

1. **Internally lossy** — when a deployer's `onError` callback fires, they have no idea *why* validation failed. Was it bad `typ`? Bad `aud`? Expired? Replay? They get one generic message.
2. **Defensive over-broad catch** in `handleJwtBearerGrant` (line 2933):

```ts
try {
  validated = await this.validateEnterpriseAssertion(...);
  requestedScope = this.getEnterpriseRequestedScopes(...);
} catch (error) {
  if (error instanceof OAuthError) {
    return this.createErrorResponse(error.code, error.message);
  }
  return this.createErrorResponse('invalid_grant', 'Invalid assertion');
}
```

The else-branch swallows programming errors (TypeErrors, null derefs, etc.) and converts them to 400 invalid_grant. A bug masquerades as a malformed assertion. **This is exactly the kind of defensive `catch` that hides defects in production.**

**Effectful fix:** Validators return a tagged Result type (e.g. `{ ok: true, value } | { ok: false, reason: 'invalid_typ' | 'invalid_alg' | 'issuer_not_trusted' | 'sig_failed' | 'aud_mismatch' | 'expired' | 'replayed' | … }`). The orchestrator translates `reason` to wire-level `{error, error_description}` AND emits the rich `reason` to the deployer-supplied `onError` hook for diagnostics. Bugs throw as before — bugs and validation failures are different things.

### 2.4 `handleJwtBearerGrant` does too much (128 lines)

The flow inside this single method:
1. EMA-enabled gate (3 lines).
2. Client auth method check (6 lines).
3. `assertion` presence + size check (8 lines).
4. Validate assertion + parse scope (10 lines, behind a try/catch).
5. Invoke `mapClaims` (8 lines).
6. Validate `mapperResult` shape — userId, scope, props (20 lines).
7. Downscope scopes (4 lines).
8. Compute access token TTL with clamps (12 lines).
9. Create grant, encrypt props, save (15 lines).
10. Create access token (12 lines).
11. Build response (10 lines).

Eleven concerns in one method. "One function does one thing" → split into:
- `parseEmaTokenRequest(body, clientInfo)` → `Result<EmaRequest, OAuthError>`
- `authorizeEmaRequest(req, validatedAssertion, mapClaims, env)` → `Result<EmaAuthorization, OAuthError>`
- `issueEmaAccessToken(authz, config, env)` → `Result<TokenResponse, OAuthError>`
- `handleJwtBearerGrant` becomes pipeline composition.

### 2.5 `mapperResult` validation as inline branches

```ts
if (typeof mapperResult.userId !== 'string' ||
    mapperResult.userId.length === 0 ||
    mapperResult.userId.includes(':')) {
  return this.createErrorResponse('invalid_grant', 'Invalid mapped user');
}
```

The `.includes(':')` is a **leaky abstraction**: it exists because the opaque token format internal to this library uses `userId:grantId:secret` separators. Authorization-code grants don't impose this restriction on userId at this point — it's silently inherited. Either:
- (a) hoist this constraint to the type-level (typed `OpaqueUserId` with brand) and validate at the seams, OR
- (b) escape/percent-encode in the token serializer so the constraint disappears.

The current PR pushes the constraint into EMA-specific code, making EMA look stricter than other grants.

### 2.6 In-memory JWKS cache is per-isolate state

```ts
private jwksCache: Map<string, CachedJwks> = new Map();
```

Workers spin up many isolates. This cache is per-isolate. The fetch already uses `cf: { cacheEverything: true }`, which gives you a real edge cache. The `Map` adds little — just deduplicates within one isolate's hot path.

Worse: it makes the function non-pure. Two requests in the same isolate share state; tests have to reset it.

**Effectful fix:** Lift the cache to a `JwksProvider` interface:
```ts
interface JwksProvider {
  fetch(issuer: TrustedIssuer, opts: { forceRefresh: boolean }): Promise<JsonWebKeySet>;
}
```
- Default impl uses `fetch()` + the `cf.cacheEverything` flag (no Map).
- Tests inject a stub.
- Future implementations can use Cache API or KV.

### 2.7 JTI store is hardcoded to `env.OAUTH_KV`

```ts
const existing = await env.OAUTH_KV.get(key);
if (existing) throw ...
await env.OAUTH_KV.put(key, '1', { expirationTtl: ttl });
```

Same shape problem. KV is read-then-write, not CAS. Author acknowledges this in the PR body. **Effectful fix:** `JtiStore` interface with the default KV implementation. Anyone needing strict-once semantics plugs in a DO-backed store. Keeps the interface stable.

### 2.8 `enabled?: boolean` is a footgun

```ts
enterpriseManagedAuthorization: {
  enabled: true,  // ← required for it to actually do anything
  trustedIssuers: [...],
  mapClaims: ...
}
```

If a deployer copies the config and forgets `enabled: true`, the entire EMA setup is **silently inert**. The token endpoint returns `unsupported_grant_type` despite full configuration.

**Fix:** Remove the field. The mere presence of `enterpriseManagedAuthorization` (with valid `trustedIssuers` + `mapClaims`) enables it. Validate at construction.

### 2.9 Metadata advertisement gating

```ts
if (this.options.enterpriseManagedAuthorization?.enabled) {
  grantTypesSupported.push(GrantType.JWT_BEARER);
}
```

But the dispatcher itself does NOT gate on `enabled`:
```ts
} else if (grantType === GrantType.JWT_BEARER) {
  return this.handleJwtBearerGrant(body, clientInfo, env, requestUrl);
}
```

The gate happens *inside* `handleJwtBearerGrant`. Compare to TOKEN_EXCHANGE which gates at dispatch:
```ts
} else if (grantType === GrantType.TOKEN_EXCHANGE && this.options.allowTokenExchangeGrant) {
```

Inconsistent. Either both gate at dispatch or both gate inside. Functionally equivalent today, but the latter is a sharp edge.

### 2.10 Audience normalization mismatch

`validateEnterpriseClaims` (line 3113):
```ts
const expectedAudience = trustedIssuer.audience ?? this.getAuthorizationServerIssuer(requestUrl);
```

Then a strict `includes` check on `audiences`. But `getAuthorizationServerIssuer(requestUrl)` returns `new URL(...).origin` — no trailing slash. If a deployer's IdP issues ID-JAGs with `aud=https://auth.example.com/`, validation fails.

The MCP spec example explicitly uses `https://auth.chat.example/` (trailing slash). Real-world IdPs frequently include trailing slashes for issuer URLs.

**Fix options:**
- Document strict-match and require deployers to set `audience` explicitly with whatever shape their IdP uses.
- Or normalize both sides (which then conflicts with RFC 3986 §6.2.1 "simple string comparison").

The current code silently picks the strict-match option. Worth surfacing.

### 2.11 `tokenEndpointAuthMethod === 'none'` rejection

```ts
if (clientInfo.tokenEndpointAuthMethod === 'none') {
  return this.createErrorResponse(
    'invalid_client',
    'Enterprise-managed authorization requires client authentication',
    401
  );
}
```

This is a **policy choice**, not a spec requirement. RFC 7523 §2.1 makes client auth OPTIONAL for jwt-bearer. The author is being conservative; defensible but worth documenting.

**Fix:** Add a comment citing the policy decision, and possibly an option to relax it for trusted deployments. (Workers running pure server-to-server MCP probably want this.)

### 2.12 Tests live in `__tests__/oauth-provider.test.ts` (the 10k-line monolith)

The new tests are a `describe('Enterprise-Managed Authorization JWT Bearer Grant', () => { ... })` block at line 2652 in an already-10k-line file. They're well-written but inherit the same monolithic problem. AGENTS.md doesn't explicitly require single-file tests, so splitting them is more clearly an improvement than splitting `src/`.

### 2.13 `parseJwt` is generic but named on the class

The method `parseJwt` (line 3180) is a generic JOSE-compact-parser. Nothing about it is EMA-specific. It's stuck on the `Impl` class purely by accident. The repo already has bits and pieces of JWT-adjacent code (token generation, hashing). Worth extracting as a free function and reusing.

## 3. Critical security observations (not structural — fix these even if not restructuring)

### 3.1 Resource binding is best-effort

If `resourceMetadata?.resource` is unset, `validateEnterpriseClaims` only checks that `claims.resource` is a valid URI — not that it matches anything. A deployer who forgets to set `resourceMetadata` accepts ID-JAGs for any resource. This isn't catastrophic (the IdP already constrained it), but defense-in-depth suggests **requiring** `resourceMetadata.resource` when EMA is enabled. **Add to `validateEnterpriseManagedAuthorizationOptions`.**

### 3.2 No `kid`-less rotation handling

In `verifyEnterpriseJwtSignature`:
```ts
if (!jwk && kid) {
  jwks = await this.fetchEnterpriseJwks(trustedIssuer, true);
  jwk = this.selectJwk(jwks, alg, kid);
}
```

Force-refresh only if there *was* a `kid` that didn't match. If the IdP rotated keys and the JWT has no `kid` (some IdPs do this), `selectJwk` returns `undefined` (because "no kid + multiple keys" returns undefined per line 3293), and we never refresh. Edge-case, but worth a TODO at minimum.

### 3.3 `signature` parameter logged via OAuthError

`OAuthError`'s `message` field becomes `error_description`. The PR consistently uses `'Invalid assertion'` strings, which is correct. But any future change that includes raw JWT bytes in an error message would leak — worth a comment.

### 3.4 No rate-limit on JWKS fetch

If an attacker sends 1000 ID-JAGs with random `kid` values, each triggers a force-refresh of JWKS (one per request). The IdP gets DoS'd. `cf.cacheEverything` mitigates this somewhat at the edge, but per-isolate refresh logic isn't rate-limited.

**Fix:** Add a per-issuer cool-down on force-refresh (e.g., max 1 refresh per 30s per issuer per isolate). Cheap to implement, eliminates the attack.

## 4. What I'm not worried about

- The cryptographic primitives are right (WebCrypto handles the heavy lifting; no homegrown code).
- The KV-based JTI race is acknowledged and is the appropriate trade-off for a default implementation.
- The `mapClaims` hook is well-shaped; deployers can deny by returning `null`.
- The test coverage is broad.

## 5. Summary scorecard

| Dimension | Grade | Why |
|-----------|-------|-----|
| Protocol correctness | A | All major MUSTs enforced; the few gaps are documented or minor. |
| Security | B+ | Strong defaults; the JWKS rate-limit and required-resource gaps lower the score. |
| Code organization | C− | EMA smeared across the monolith; god-method; constants far from use. |
| Effectful style | F | Throw-based control flow with lossy error info; no Result types. |
| Testability of internals | D | Pure-function logic trapped on a class; cannot unit-test without the whole AS. |
| DRY | B | Claim helpers are reused; `parseJwt` is generic but mis-located. |
| Production-ready | C | Functional, but the structure makes future maintenance painful. |

The next doc proposes a concrete restructure.
