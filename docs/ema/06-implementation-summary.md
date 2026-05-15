# EMA Restructure — Implementation Summary

What this branch actually changed compared to PR #203.

## Files

### New files (`src/ema/*`)

| File | Lines | Purpose |
|------|-------|---------|
| `constants.ts` | 43 | All `EMA_*` constants in one place |
| `types.ts` | 234 | Public types (`EmaOptions`, `EmaTrustedIssuer`, …) + internal types (`ParsedIdJag`, `ValidatedIdJag`, …) |
| `result.ts` | 122 | `Result<T,E>` type, `EmaValidationError` tagged union, `emaErrorToWire` translator, `EmaOnErrorPayload` helper |
| `parser.ts` | 55 | `parseIdJag` — pure compact-JWS parser returning `Result` |
| `validators.ts` | 376 | `validateIdJagHeader`, `selectTrustedIssuer`, `validateIdJagClaims`, `parseEmaScopeParam`, `validateEmaMapperResult`, `clampEmaAccessTokenTTL` — all pure, all `Result`-returning |
| `signature.ts` | 79 | `selectJwk` (pure JWK picker), `verifyIdJagSignature` (WebCrypto verifier) |
| `jwks.ts` | 165 | `createDefaultJwksProvider` — in-memory cached fetcher with anti-DoS cool-down |
| `jti.ts` | 49 | `createKvJtiStore` — default KV-backed replay store |
| `util.ts` | 15 | `sha256Hex` helper used by `jti.ts` |

### New test file

| File | Tests | Purpose |
|------|-------|---------|
| `__tests__/ema-validators.test.ts` | 50 | Unit tests for the pure validators — no `OAuthProvider`, no fetch mocks, no KV. Runs in ms. |

### Modified files

- `src/oauth-provider.ts`: −335 lines net (5466 → 5131). EMA-specific logic dropped; new orchestrator + adapter-wiring code added.
- `__tests__/oauth-provider.test.ts`: removed 8 `enabled: true` lines, added 1 new construction-time test for the `resourceMetadata.resource` requirement.

## Behavior changes (all four requested)

1. **Dropped `enabled: boolean`** — presence of `enterpriseManagedAuthorization` enables EMA. Forgetting `enabled: true` no longer silently disables.
2. **Required `resourceMetadata.resource`** when EMA is configured. The provider throws at construction if missing. Defense-in-depth: closes the gap where any `resource` claim would be accepted.
3. **JWKS force-refresh cool-down** — per-issuer rate-limit (30s default) on force-refreshes. Prevents IdP DoS via random-`kid` spam.
4. **Exposed `jwksProvider` and `jtiStore` plug points** — deployers needing DO-backed strict-once JTI semantics or custom JWKS caching can supply their own adapters. Defaults are unchanged.

## Other behavior changes (necessary follow-ons)

- Renamed `jwksCacheTtl` → `jwksCacheTtlSeconds`, `maxAssertionLifetime` → `maxAssertionLifetimeSeconds`. Consistent unit suffix with `clockSkewSeconds`.
- Renamed all `Enterprise*` types → `Ema*` for brevity. Public option key `enterpriseManagedAuthorization` unchanged (deployer-facing).
- Renamed `ENTERPRISE_*` constants → `EMA_*`. Co-located in `src/ema/constants.ts`.
- Added `nbf` (not-before) claim handling per RFC 7523 §3 rule 5.
- The 18 sites of `throw new OAuthError('invalid_grant', 'Invalid assertion')` are gone — failures now flow as `Result<T, EmaValidationError>` and translate to the same wire response at the boundary.

## Effectful pattern

Hand-rolled, two helpers, no dependencies:

```ts
type Result<T, E> = { ok: true; value: T } | { ok: false; error: E };
const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });
const err = <E>(error: E): Result<never, E> => ({ ok: false, error });
```

Tagged error union with 24 distinct reasons. The orchestrator (`runEmaPipeline` in `oauth-provider.ts`) chains them with explicit `if (!r.ok) return r;` — boring, inspectable, exactly what security reviewers want. No `pipe`, no `andThen`, no library magic.

Errors translate to wire-level OAuth errors at one place (`emaErrorToWire`). Most failures collapse to a single `invalid_grant: Invalid assertion` per the security recommendation; resource issues remain `invalid_target`; input-shape issues remain `invalid_request`. The structured `EmaValidationError` is preserved for future `onError` plumbing via `emaErrorToOnErrorPayload`.

## Test inventory

- **Existing 360 integration tests**: all passing.
- **+1 new integration test**: rejects EMA config without `resourceMetadata.resource`.
- **+50 new unit tests** in `ema-validators.test.ts` covering each pure validator end-to-end, including edge cases (`nbf` in future, multi-value `aud`, scope grammar, mapper-return shape, TTL clamping).

**Total: 411 tests, 411 passing.**

## What was NOT done (deferred or skipped)

- **Stage 6 — extract `runEmaPipeline` to a free function in `src/ema/orchestrator.ts`.** Skipped: the orchestrator needs `OAuthProviderImpl` methods (`getAuthorizationServerIssuer`, `downscope`, `saveGrantWithTTL`, `createAccessToken`) and the cost of plumbing a context interface outweighs the benefit since all *validation* is already pure and split out. The class method is now ~90 lines of named, ordered, inspectable validator calls — already achieves "split concerns".
- **Reorganizing the 10k-line integration test file**. The 360 existing tests remain in `__tests__/oauth-provider.test.ts` as-is. New unit tests live in their own focused file.
- **Pushing back on AGENTS.md's single-source-file convention for the existing OAuth flows.** Only EMA-specific code was extracted to `src/ema/`. Non-EMA logic stays in `oauth-provider.ts` per the audit-friendly convention.
- **Refresh tokens for EMA grants.** The MCP spec is silent. PR #203 didn't include them; this restructure doesn't either. Worth surfacing as a follow-up if real deployments hit it.

## Line-count snapshot

```
src/oauth-provider.ts          5131  (baseline 5466, PR #203 was 6290)
src/ema/constants.ts             43
src/ema/jti.ts                   49
src/ema/jwks.ts                 165
src/ema/parser.ts                55
src/ema/result.ts               122
src/ema/signature.ts             79
src/ema/types.ts                234
src/ema/util.ts                  15
src/ema/validators.ts           376
──────────────────────────────────
TOTAL SRC                      6269
```

```
__tests__/oauth-provider.test.ts        ~10,200 (existing, +new resource-required test)
__tests__/ema-validators.test.ts            375 (new — unit tests)
```

EMA code per file averages ~125 lines — small, focused, individually auditable. The orchestrator is the only place where you read the full flow top-to-bottom.
