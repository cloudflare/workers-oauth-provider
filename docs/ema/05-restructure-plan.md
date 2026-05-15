# Proposed Restructure — Effectful, DRY, Concern-Split

A concrete plan for restructuring PR #203's EMA implementation. **Design philosophy first; then concrete code shape; then migration steps.**

## 0. Constraints we honor

1. **Single source file `src/oauth-provider.ts`** stays. AGENTS.md is explicit that one file aids security review. Restructure *within* the file using clearly demarcated regions.
2. **No new dependencies.** No `effect`, no `neverthrow`, no `zod`. Hand-rolled Result type. The repo's `package.json` keeps zero runtime deps (only `cloudflare:workers`).
3. **Backwards compatibility.** Public API (`OAuthProviderOptions.enterpriseManagedAuthorization`) keeps the same shape minus the `enabled` flag (which is a footgun — see review §2.8).
4. **Tests stay green.** The 750-line test block is the contract.

## 1. Effect-style: what we mean in this codebase

We're not adopting the Effect library. We adopt **two patterns** from it:

### 1.1 Tagged Result type

```ts
type Result<T, E> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };

const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });
const err = <E>(error: E): Result<never, E> => ({ ok: false, error });
```

That's the whole library. Two helpers, no chaining magic. If we need `andThen`, write it inline:

```ts
const r1 = parseHeader(jwt);
if (!r1.ok) return r1;
const r2 = validateAlg(r1.value, allowList);
if (!r2.ok) return r2;
// ...
```

This is verbose but **transparent** — exactly what security reviewers want. No hidden control flow.

### 1.2 Tagged error union (the "what went wrong" enum)

```ts
type EmaValidationError =
  | { reason: 'invalid_typ' }
  | { reason: 'invalid_alg'; alg: string }
  | { reason: 'issuer_not_trusted'; iss: string }
  | { reason: 'jwks_fetch_failed'; status?: number }
  | { reason: 'no_matching_key'; kid?: string }
  | { reason: 'signature_failed' }
  | { reason: 'invalid_claim'; claim: string }
  | { reason: 'aud_mismatch'; expected: string; got: string | string[] }
  | { reason: 'expired'; exp: number; now: number }
  | { reason: 'iat_in_future'; iat: number; now: number; skew: number }
  | { reason: 'lifetime_too_long'; lifetime: number; max: number }
  | { reason: 'replayed'; jti: string }
  | { reason: 'client_id_mismatch'; expected: string; got: string }
  | { reason: 'resource_mismatch'; expected: string; got: string }
  | { reason: 'resource_invalid'; resource: string }
  | { reason: 'assertion_too_large'; size: number; max: number }
  | { reason: 'assertion_malformed' };
```

**Why this matters:** at the seam where we serialize the error to the wire, we pick a single string ("Invalid assertion" for security). But the rich `EmaValidationError` flows to `onError` so the deployer can debug, log, alert. **The wire response stays unchanged; the internal observability dramatically improves.**

Two small helpers translate:

```ts
function emaErrorToWire(e: EmaValidationError): OAuthError {
  switch (e.reason) {
    case 'resource_invalid':
    case 'resource_mismatch':
      return new OAuthError('invalid_target', 'Invalid resource');
    case 'assertion_too_large':
    case 'assertion_malformed':
    case 'invalid_typ':
    case 'invalid_alg':
    case 'issuer_not_trusted':
    case 'no_matching_key':
    case 'signature_failed':
    case 'invalid_claim':
    case 'aud_mismatch':
    case 'expired':
    case 'iat_in_future':
    case 'lifetime_too_long':
    case 'replayed':
    case 'client_id_mismatch':
    case 'jwks_fetch_failed':
      return new OAuthError('invalid_grant', 'Invalid assertion');
  }
}
```

## 2. File regions

A single `src/oauth-provider.ts` with explicit region banners:

```ts
// ╔══════════════════════════════════════════════════════════════╗
// ║  ENTERPRISE-MANAGED AUTHORIZATION (EMA / ID-JAG / RFC 7523)  ║
// ╠══════════════════════════════════════════════════════════════╣
// ║  Region 1: Constants & types                                 ║
// ║  Region 2: Pure validators (no I/O)                          ║
// ║  Region 3: Adapter interfaces (JwksProvider, JtiStore)       ║
// ║  Region 4: Default adapter implementations                   ║
// ║  Region 5: Orchestrator (the only EMA code on OAuthProvider) ║
// ╚══════════════════════════════════════════════════════════════╝
```

Each region is a "mini-file" inside the monolith. Today's PR has these concerns scattered between lines 144–4182 (a span of 4,000 lines). They become contiguous.

## 3. Region-by-region detail

### Region 1: Constants & types

Moved from line 4142+ to immediately above the rest. ~50 lines.

```ts
const EMA_ID_JAG_JWT_TYPE = 'oauth-id-jag+jwt';
const EMA_MAX_JWT_BYTES = 16 * 1024;
const EMA_JWKS_MAX_SIZE_BYTES = 64 * 1024;
const EMA_JWKS_FETCH_TIMEOUT_MS = 10_000;
const EMA_DEFAULT_JWKS_CACHE_TTL_S = 5 * 60;
const EMA_DEFAULT_CLOCK_SKEW_S = 60;
const EMA_DEFAULT_MAX_ASSERTION_LIFETIME_S = 5 * 60;
const EMA_SUPPORTED_ALGS = new Set(['RS256', 'ES256'] as const);
type EmaAlg = 'RS256' | 'ES256';

type EmaValidationError = /* …tagged union from §1.2 above… */;

interface IdJagHeader { typ: string; alg: string; kid?: string; }
interface ParsedIdJag {
  header: IdJagHeader;
  rawClaims: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
}
interface ValidatedIdJag {
  iss: string;
  sub: string;
  aud: string | string[];
  resource: string;
  client_id: string;
  jti: string;
  exp: number;
  iat: number;
  scope?: string;
  additionalClaims: Record<string, unknown>;
}
```

Naming change: `ENTERPRISE_*` → `EMA_*`. Shorter, no information lost.

### Region 2: Pure validators (the heart of the restructure)

Free functions, no `this`, no I/O. Each one is testable in isolation.

```ts
function emaParseJwt(assertion: string): Result<ParsedIdJag, EmaValidationError>;

function emaValidateHeader(
  header: Record<string, unknown>,
  allowedAlgs: ReadonlySet<EmaAlg>
): Result<IdJagHeader, EmaValidationError>;

function emaSelectTrustedIssuer(
  iss: string,
  registry: readonly TrustedIssuer[]
): Result<TrustedIssuer, EmaValidationError>;

function emaSelectJwk(
  jwks: JsonWebKeySet,
  alg: EmaAlg,
  kid: string | undefined
): Result<JsonWebKey, EmaValidationError>;

function emaValidateClaims(args: {
  rawClaims: Record<string, unknown>;
  trustedIssuer: TrustedIssuer;
  expectedAudience: string;
  clientId: string;
  configuredResource: string | undefined;
  matchOriginOnly: boolean;
  now: number;
  clockSkewSeconds: number;
  maxAssertionLifetime: number;
}): Result<ValidatedIdJag, EmaValidationError>;

function emaParseScopeParam(
  scope: unknown,
  assertionScopes: readonly string[]
): Result<string[], EmaValidationError>;

function emaValidateMapperResult(
  result: unknown
): Result<EmaAuthorization, EmaValidationError>;

function emaClampTokenTTL(args: {
  configuredTTL: number;
  assertionExp: number;
  mapperTTL: number | undefined;
  now: number;
}): Result<number, EmaValidationError>;
```

Each function:
- Takes plain data.
- Returns `Result`.
- Has zero side effects (no clock, no `fetch`, no KV).
- Is unit-testable with a few lines.

The `now` parameter is explicit — testable without mocking `Date.now()`.

### Region 3: Adapter interfaces

Side-effecting operations behind narrow interfaces.

```ts
interface JwksProvider {
  /** Fetch JWKS for an issuer, optionally bypassing cache. */
  fetch(issuer: TrustedIssuer, opts: { forceRefresh: boolean }): Promise<Result<JsonWebKeySet, EmaValidationError>>;
}

interface JtiStore {
  /** Mark a JTI as used. Returns `replayed` error if already present. */
  markUsed(args: { issuer: string; jti: string; exp: number; now: number }): Promise<Result<void, EmaValidationError>>;
}

interface SignatureVerifier {
  /** Verify a signature using the imported JWK. */
  verify(args: { alg: EmaAlg; jwk: JsonWebKey; signature: Uint8Array; signingInput: Uint8Array }): Promise<boolean>;
}
```

Three narrow interfaces. Tests provide stubs:

```ts
const fakeJwks: JwksProvider = {
  fetch: async () => ok({ keys: [TEST_JWK] }),
};
```

### Region 4: Default adapter implementations

```ts
function createDefaultJwksProvider(cacheTtlS: number): JwksProvider { /* fetch + Map cache */ }
function createKvJtiStore(kv: KVNamespace): JtiStore { /* current PR's logic */ }
const webCryptoVerifier: SignatureVerifier = { /* current PR's logic */ };
```

These are closures that capture their state, not class fields. Two consequences:
- The cache is no longer on `OAuthProviderImpl`. The class becomes shorter.
- Tests instantiate adapters with their own state, no shared globals.

For the `JwksProvider` we keep the in-memory `Map` cache because it amortizes signature verification on repeated requests within an isolate's lifetime. Layering on top of `cf.cacheEverything` is fine.

For the `JtiStore`, the default is KV — same as the PR. Document that strict-once requires a custom implementation.

**Bonus:** Adding a force-refresh cool-down lives in the `JwksProvider` (closes review §3.4).

### Region 5: Orchestrator

This is the only EMA code that touches `OAuthProviderImpl`. ~50 lines, replaces the current 128-line god-method.

```ts
private async handleJwtBearerGrant(
  body: any,
  clientInfo: ClientInfo,
  env: any,
  requestUrl: URL
): Promise<Response> {
  const opts = this.options.enterpriseManagedAuthorization;
  if (!opts) {
    return this.createErrorResponse('unsupported_grant_type', 'Grant type not supported');
  }
  if (clientInfo.tokenEndpointAuthMethod === 'none') {
    return this.createErrorResponse(
      'invalid_client',
      'Enterprise-managed authorization requires client authentication',
      401
    );
  }

  const result = await this.executeEmaPipeline({ body, clientInfo, env, requestUrl, opts });

  if (!result.ok) {
    this.options.onError?.(emaErrorToOnErrorPayload(result.error));
    const wire = emaErrorToWire(result.error);
    return this.createErrorResponse(wire.code, wire.message);
  }

  return new Response(JSON.stringify(result.value), {
    headers: { 'Content-Type': 'application/json' },
  });
}

private async executeEmaPipeline(args: {
  body: any;
  clientInfo: ClientInfo;
  env: any;
  requestUrl: URL;
  opts: EmaOptions<Env>;
}): Promise<Result<TokenResponse, EmaValidationError>> {
  const { body, clientInfo, env, requestUrl, opts } = args;
  const now = Math.floor(Date.now() / 1000);

  const r1 = emaParseRequest(body, EMA_MAX_JWT_BYTES);
  if (!r1.ok) return r1;

  const r2 = emaParseJwt(r1.value.assertion);
  if (!r2.ok) return r2;

  const r3 = emaValidateHeader(r2.value.header, EMA_SUPPORTED_ALGS);
  if (!r3.ok) return r3;

  const r4 = emaSelectTrustedIssuer(
    asString(r2.value.rawClaims.iss),
    opts.trustedIssuers
  );
  if (!r4.ok) return r4;

  const r5 = await this.jwksProvider.fetch(r4.value, { forceRefresh: false });
  if (!r5.ok) return r5;

  // attempt verify; on key miss, force-refresh once
  const r6 = await emaVerifySignature(this.signatureVerifier, this.jwksProvider, {
    parsed: r2.value,
    header: r3.value,
    issuer: r4.value,
  });
  if (!r6.ok) return r6;

  const r7 = emaValidateClaims({
    rawClaims: r2.value.rawClaims,
    trustedIssuer: r4.value,
    expectedAudience: r4.value.audience ?? this.getAuthorizationServerIssuer(requestUrl),
    clientId: clientInfo.clientId,
    configuredResource: this.options.resourceMetadata?.resource,
    matchOriginOnly: !!this.options.resourceMatchOriginOnly,
    now,
    clockSkewSeconds: opts.clockSkewSeconds ?? EMA_DEFAULT_CLOCK_SKEW_S,
    maxAssertionLifetime: opts.maxAssertionLifetime ?? EMA_DEFAULT_MAX_ASSERTION_LIFETIME_S,
  });
  if (!r7.ok) return r7;

  const r8 = await this.jtiStore.markUsed({
    issuer: r7.value.iss,
    jti: r7.value.jti,
    exp: r7.value.exp,
    now,
  });
  if (!r8.ok) return r8;

  const assertionScopes = parseScopeString(r7.value.scope);
  const r9 = emaParseScopeParam(body.scope, assertionScopes);
  if (!r9.ok) return r9;

  const mapperResult = await Promise.resolve(opts.mapClaims({
    claims: claimsFromValidated(r7.value),
    clientInfo,
    resource: r7.value.resource,
    requestedScope: r9.value,
    env,
  }));
  const r10 = emaValidateMapperResult(mapperResult);
  if (!r10.ok) return r10;

  const r11 = emaClampTokenTTL({
    configuredTTL: this.options.accessTokenTTL ?? DEFAULT_ACCESS_TOKEN_TTL,
    assertionExp: r7.value.exp,
    mapperTTL: r10.value.accessTokenTTL,
    now,
  });
  if (!r11.ok) return r11;

  return await this.issueEmaToken({
    authz: r10.value,
    assertionScopes,
    resource: r7.value.resource,
    clientId: clientInfo.clientId,
    accessTokenTTL: r11.value,
    env,
    now,
  });
}
```

Yes, it's a wall of `if (!rN.ok) return rN`. That's the point. Every step is **named, ordered, and inspectable**. A security reviewer reads it top-to-bottom in 60 seconds. The current 128-line method is harder.

If the verbosity grates, a tiny helper localizes it (still no library):

```ts
async function pipe<T, E>(...steps: Array<() => Result<T, E> | Promise<Result<T, E>>>): Promise<Result<T, E>> {
  let cur: Result<T, E> = ok(undefined as any);
  for (const step of steps) {
    if (!cur.ok) return cur;
    cur = await step();
  }
  return cur;
}
```

But honestly: the explicit form above is clearer for security audits. **Don't add `pipe`.** Keep it boring.

### `issueEmaToken` — the one remaining stateful step

Extracted from the current method's tail:

```ts
private async issueEmaToken(args: {
  authz: EmaAuthorization;
  assertionScopes: string[];
  resource: string;
  clientId: string;
  accessTokenTTL: number;
  env: any;
  now: number;
}): Promise<Result<TokenResponse, EmaValidationError>> {
  const tokenScopes = args.assertionScopes.length > 0
    ? this.downscope(args.authz.scope, args.assertionScopes)
    : args.authz.scope;

  const grantId = generateRandomString(16);
  const { encryptedData, key: encryptionKey } = await encryptProps(args.authz.props);
  const grant: Grant = {
    id: grantId,
    clientId: args.clientId,
    userId: args.authz.userId,
    scope: tokenScopes,
    metadata: args.authz.metadata ?? null,
    encryptedProps: encryptedData,
    createdAt: args.now,
    expiresAt: args.now + args.accessTokenTTL,
    resource: args.resource,
  };
  await this.saveGrantWithTTL(args.env, `grant:${args.authz.userId}:${grantId}`, grant, args.now);

  const accessToken = await this.createAccessToken({
    userId: args.authz.userId,
    grantId,
    clientId: args.clientId,
    scope: tokenScopes,
    encryptedProps: encryptedData,
    encryptionKey,
    expiresIn: args.accessTokenTTL,
    audience: args.resource,
    env: args.env,
  });

  return ok({
    access_token: accessToken,
    token_type: 'bearer',
    expires_in: args.accessTokenTTL,
    scope: tokenScopes.join(' '),
    resource: args.resource,
  });
}
```

Note: this re-uses existing methods (`saveGrantWithTTL`, `createAccessToken`, `downscope`, `encryptProps`). No duplication of grant/token machinery.

## 4. Configuration API changes

| Current | Proposed | Why |
|---------|----------|-----|
| `enabled?: boolean` | (removed) | Footgun. Mere presence enables. |
| `trustedIssuers: TrustedIssuer[]` | (kept) | Required, non-empty. |
| `mapClaims: …` | (kept) | Required. |
| `jwksCacheTtl?: number` | `jwksCacheTtlSeconds?: number` | Disambiguate units. |
| `clockSkewSeconds?: number` | (kept) | Already clear. |
| `maxAssertionLifetime?: number` | `maxAssertionLifetimeSeconds?: number` | Disambiguate. |
| — | `jwksProvider?: JwksProvider` | NEW: lets deployers plug custom cache. |
| — | `jtiStore?: JtiStore` | NEW: lets deployers plug DO-backed strict-once. |

The default for each adapter is the current PR's behavior, so no breaking change for users.

**Construction-time validation also requires `resourceMetadata.resource`** when EMA is on (closes review §3.1).

## 5. Test reorganization

Tests stay in `__tests__/oauth-provider.test.ts` (per AGENTS.md) but the EMA block is restructured:

```
describe('Enterprise-Managed Authorization', () => {
  describe('Pure validators', () => {
    describe('emaParseJwt', () => { /* 5–10 cases, no fixtures */ });
    describe('emaValidateHeader', () => { /* 5–10 cases */ });
    describe('emaSelectTrustedIssuer', () => { /* 3 cases */ });
    describe('emaSelectJwk', () => { /* 5 cases */ });
    describe('emaValidateClaims', () => { /* 15 cases */ });
    describe('emaParseScopeParam', () => { /* 4 cases */ });
    describe('emaValidateMapperResult', () => { /* 4 cases */ });
    describe('emaClampTokenTTL', () => { /* 3 cases */ });
  });
  describe('Adapters', () => {
    describe('default JwksProvider', () => { /* fetch behavior */ });
    describe('KV JtiStore', () => { /* read/write/replay */ });
  });
  describe('End-to-end token endpoint', () => {
    /* the existing 10–15 integration tests, retained */
  });
});
```

Net effect: same coverage, but unit tests pin individual validators. Adding a new claim check becomes a few lines, not a full integration setup.

## 6. Migration steps

Each step is a self-contained commit that keeps tests green.

1. **Extract types & constants** to a single region at the top of the EMA section. Pure refactor. (≈50 lines moved.)
2. **Introduce `Result<T, E>` type and `EmaValidationError` union.** Add helpers `ok`/`err`. Add `emaErrorToWire`. No call-site changes yet.
3. **Extract pure validators as free functions** (Region 2). Initially they still throw `OAuthError`. Inline call-sites stay identical.
4. **Convert validators to return `Result`.** Wire through to `validateEnterpriseAssertion` orchestrator. The class method becomes 20 lines of "call validator, on error throw OAuthError". Tests still pass.
5. **Add `JwksProvider` and `JtiStore` interfaces.** Default implementations in `OAuthProviderImpl` constructor. The class still owns them — no behavior change.
6. **Split `handleJwtBearerGrant`** into `executeEmaPipeline` + `issueEmaToken`. The throw-based path becomes the `Result` pipeline.
7. **Remove the over-broad catch** in `handleJwtBearerGrant`. Real exceptions propagate; validation failures flow as `Result`.
8. **Optional plug points** — expose `jwksProvider` / `jtiStore` on `EmaOptions`. Document. Add tests for stub-based injection.
9. **Drop `enabled`** in favor of presence-based enabling. **Breaking** for existing experiment users; gated by major-version semver. (PR is draft; not published — safe.)
10. **Reorganize tests** into the nested-describe structure from §5. Behavior preserved.
11. **Add tests for new pure validators.** Coverage now lands on unit-level, not integration-level.

Total estimated diff: **±900 lines net inside the file**; ≈1300 lines of test reshuffling (mostly moves, not new). The end state should be ≈ same line count as PR #203 but with far better locality and inspectability.

## 7. What this does NOT do (deliberately)

- Does NOT split `src/oauth-provider.ts` into multiple files. AGENTS.md forbids it.
- Does NOT introduce `effect`, `neverthrow`, `zod`, or any Result library.
- Does NOT change wire-level error responses.
- Does NOT remove KV-based JTI store (kept as default).
- Does NOT change the `mapClaims` callback shape.
- Does NOT introduce refresh tokens for EMA (separate decision; spec is silent).
- Does NOT add an `authorization_servers`-array signal that the resource is EMA-only (spec doesn't define one).

## 8. Quick win list (orthogonal fixes)

Independent of the restructure, these are 1–5 line fixes worth landing:

- **W1.** Require `resourceMetadata.resource` when EMA enabled. (Review §3.1.)
- **W2.** Add JWKS force-refresh cool-down per issuer. (Review §3.4.)
- **W3.** Co-locate `EMA_*` constants. (Review §2.2.)
- **W4.** Tighten the catch in `handleJwtBearerGrant`. (Review §2.3.)
- **W5.** Drop the leaky `userId.includes(':')` check by escaping in the token serializer. (Review §2.5 — slightly bigger.)
- **W6.** Audience-normalization comment / documented strict-match. (Review §2.10.)

W1–W4 and W6 could land first as a "tidy" commit. W5 needs more thought.

## 9. Open questions to confirm with Matt

1. **Single-file vs multi-file source.** AGENTS.md says single-file. This plan honors that with regions. Do we want to push back on AGENTS.md for EMA's scope? (My recommendation: no — regions get us 90% of the benefit, the security review story stays intact.)
2. **Drop `enabled`?** Cleaner but breaks any existing config (even though PR is draft). Confirm.
3. **Expose `JwksProvider` / `JtiStore` as public extension points?** Adds API surface, enables strict-once semantics. Confirm.
4. **Refresh tokens for EMA grants?** Out of scope for this restructure unless desired. Spec is silent.
5. **Required `resourceMetadata.resource`?** This is the only behavior change that could break a careless deployer. Confirm.
6. **Push these changes to PR #203 (overwrite irvinebroque's branch) or open a parallel "v2" PR?** PR #203 is explicitly experimental; I'd open a parallel PR keeping `experiment/enterprise-managed-authorization` for reference.
