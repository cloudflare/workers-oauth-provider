# AGENTS.md

## Project overview

`@cloudflare/workers-oauth-provider` is a production-grade OAuth 2.1 provider library for Cloudflare Workers. It implements authorization code flow with PKCE, OAuth discovery, client registration, token exchange, audience validation, and encryption of sensitive data stored in KV.

**Primary use case:** This library powers authorization for **MCP (Model Context Protocol) servers**. MCP servers are OAuth Resource Servers, and this library provides both protected-resource middleware and the authorization server functionality needed to secure them.

This library was largely written with Claude AI assistance, with all code thoroughly reviewed by Cloudflare security engineers.

## MCP specification compliance

When modifying OAuth functionality, **always check the latest published MCP specification** (not drafts):

- **Specification:** https://modelcontextprotocol.io/specification/2026-07-28
- **Authorization section:** https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- **Authorization server discovery:** https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery
- **Client registration:** https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration
- **Security considerations:** https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations

This library must be feature-complete with the latest published MCP spec version. Key MCP auth requirements:

- MCP servers are OAuth Resource Servers with protected resource metadata (RFC 9728)
- MCP clients use Resource Indicators (RFC 8707), and servers validate token audience
- Client registration supports pre-registration and Client ID Metadata Documents (CIMD)
- Dynamic Client Registration (DCR) is deprecated in MCP 2026-07-28 and retained for compatibility
- Authorization responses use issuer identification (RFC 9207)
- Streamable HTTP transport uses OAuth 2.1 for authentication

When in doubt about OAuth behavior, the MCP specification takes precedence for MCP-related use cases.

## Repository structure

```
workers-oauth-provider/
├── src/
│   ├── oauth-provider.ts      # Core provider implementation
│   ├── oauth-capabilities.ts  # Pure server/client metadata capability policy
│   ├── oauth-client-metadata.ts # Typed DCR parsing and CIMD resolution pipeline
│   └── ema/                   # Enterprise-Managed Authorization pipeline
├── __tests__/
│   ├── oauth-provider.test.ts # Comprehensive provider integration suite
│   ├── oauth-capabilities.test.ts # Pure capability policy tests
│   ├── setup.ts               # Vitest setup and mocking
│   └── mocks/
│       └── cloudflare-workers.ts
├── conformance/               # Black-box MCP authorization conformance matrix
│   ├── README.md              # Scope, revision coverage, and traceability
│   ├── shared.ts              # Typed Worker RPC contract and fixture constants
│   ├── spec-versions.ts       # Ordered MCP authorization revision timeline
│   ├── support/               # Workerd lifecycle and OAuth client
│   └── worker/                # Real Wrangler Worker with local KV
├── dist/                      # Build output (tsdown)
├── docs/
│   └── advanced-configuration.md
├── .github/workflows/
│   ├── ci.yml                 # PR validation
│   ├── release.yml            # Changesets-based npm publishing
│   └── pkg-pr-new.yml         # PR preview packages
├── storage-schema.md          # KV namespace data structure docs
├── HISTORY.md                 # Kenton's original project history
├── SECURITY.md                # Vulnerability reporting
└── README.md                  # Usage documentation
```

**Audit-oriented architecture:** Request orchestration and storage-backed OAuth behavior remain in `src/oauth-provider.ts`. Typed OAuth client metadata parsing plus CIMD fetching and resolution live in `src/oauth-client-metadata.ts`; pure authorization-server/client capability policy lives in `src/oauth-capabilities.ts`. The experimental Enterprise-Managed Authorization validation pipeline is isolated in `src/ema/` so its JWT and trust-boundary code can be reviewed independently.

## Setup

```bash
npm install    # Install dependencies
npm run build  # Build with tsdown
```

Node 24+ required.

## Commands

| Command                    | What it does                              |
| -------------------------- | ----------------------------------------- |
| `npm run build`            | Builds single-file ESM bundle with tsdown |
| `npm run check`            | Runs typecheck + tests                    |
| `npm run typecheck`        | TypeScript type checking (no emit)        |
| `npm run test`             | Runs vitest test suite                    |
| `npm run test:conformance` | Runs MCP auth conformance tests           |
| `npm run test:watch`       | Runs vitest in watch mode                 |
| `npm run prettier`         | Formats all files with Prettier           |

## Code standards

### TypeScript

- Strict mode enabled
- Target: ES2021, Module: ES2022
- All public methods and interfaces must have JSDoc documentation
- Private fields use `#` prefix (modern TS private fields)

### Naming conventions

- `PascalCase` for classes, interfaces, enums
- `camelCase` for methods, variables
- `SCREAMING_SNAKE_CASE` for constants
- `Impl` suffix for internal implementations
- `Options` suffix for configuration interfaces

### Architecture patterns

**PImpl pattern:** The public `OAuthProvider` class wraps a private `OAuthProviderImpl`. This prevents TypeScript private methods from being accidentally exposed over RPC in Cloudflare Workers.

```typescript
export class OAuthProvider {
  #impl: OAuthProviderImpl;
  fetch(...) { return this.#impl.fetch(...); }
}
```

**Dual handler support:** The library supports both `ExportedHandler` (plain objects) and `WorkerEntrypoint` (classes) patterns. Maintain both for backwards compatibility.

### Formatting

Prettier with 120 character line width. Run `npm run prettier` before committing.

## Security considerations

This is a security-critical OAuth library. All changes must consider:

**Token storage:**

- Secrets (tokens, authorization codes) are stored as SHA-256 hashes only
- Props are encrypted with AES-GCM, key wrapped with the token itself
- Only token holders can decrypt their associated props

**Validation:**

- Redirect URIs validated against XSS payloads
- Client IDs validated (including CIMD URL validation)
- PKCE enforced for public clients (S256 method)
- Scope downscoping validated per RFC 6749 Section 3.3

**Refresh token rotation:**

- Dual refresh tokens: current + previous both valid
- Handles network failure cases gracefully
- Previous token invalidated only after new token first used

## Testing

Tests use **vitest** with custom mocks for Cloudflare Workers APIs.

```bash
npm run test               # Full suite, including conformance
npm run test:conformance   # MCP authorization conformance only
npm run test:watch         # Watch mode
```

**Main integration test:** `__tests__/oauth-provider.test.ts`

**MCP authorization conformance:** `conformance/` contains black-box tests for every dated authorization revision represented by the official MCP conformance timeline. Wrangler's `createTestHarness()` runs a real Worker in Workerd with a local KV binding; tests exercise public `OAuthProvider` and `OAuthHelpers` interfaces and include requirement traceability in `conformance/README.md`.

**Mock implementations:**

- `MockKV` — In-memory KV with TTL simulation
- `MockExecutionContext` — ctx.props support
- `createMockRequest()` — HTTP request builder

**Coverage areas:**

- OAuth metadata discovery endpoints
- Authorization code flow with PKCE
- Token exchange and refresh flows
- Client registration (RFC 7591)
- Grant management and revocation
- Error responses and validation
- Scope downscoping
- Resource-aware audience validation

**Test pattern:**

```typescript
beforeEach(() => {
  mockEnv = createMockEnv();
  mockCtx = new MockExecutionContext();
  oauthProvider = new OAuthProvider(options);
});

afterEach(() => {
  mockEnv.OAUTH_KV.clear();
});
```

## Contributing

### Changesets

Changes affecting the public API or bug fixes need a changeset:

```bash
npx changeset    # Interactive: select semver bump, write description
```

### Pull request process

CI runs on every PR:

1. `npm ci` — Clean install
2. `npm run build` — Build with tsdown
3. `npm run check` — Typecheck + tests
4. Prettier format check

All checks must pass before merge.

### Bonk (AI code review)

Mention `/bonk` or `@ask-bonk` in PR comments to get AI-powered code review and suggestions. Bonk can analyze code, suggest fixes, and even auto-commit improvements.

### Semver: changes that invalidate tokens or refresh tokens must be minor

Any change that alters the format of data stored on grants (e.g. the `resource` field) can silently invalidate existing refresh tokens. These changes **must** be released as a minor version bump, not a patch. This applies to any change where tokens issued by the previous version would fail validation against the new version.

### RFC compliance

This library implements multiple OAuth/security RFCs. When making changes, maintain compliance with:

- OAuth 2.1 (draft-ietf-oauth-v2-1-13)
- OAuth 2.0 Bearer Token Usage (RFC 6750)
- OAuth 2.0 Token Revocation (RFC 7009)
- OAuth 2.0 Dynamic Client Registration (RFC 7591, deprecated by MCP 2026-07-28)
- PKCE (RFC 7636)
- OAuth 2.0 Authorization Server Metadata (RFC 8414)
- OAuth 2.0 Token Exchange (RFC 8693)
- Resource Indicators for OAuth 2.0 (RFC 8707)
- OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
- OAuth 2.0 Protected Resource Metadata (RFC 9728)
- Client ID Metadata Documents (draft spec)
- OpenID Connect RP Metadata Choices 1.0

### Generated files

- `dist/` — Generated by `npm run build`, don't hand-edit
- `package-lock.json` — Generated by `npm install`, don't hand-edit

## Boundaries

**Always:**

- Run `npm run check` before considering work done
- Add tests for new functionality
- Document public APIs with JSDoc
- Consider security implications of changes
- Maintain backwards compatibility for handler patterns

**Ask first:**

- Adding new dependencies (this ships to users with zero runtime deps)
- Changing KV storage schema (requires migration planning)
- Modifying OAuth endpoints or flows
- Adding new feature flags

**Never:**

- Hardcode secrets or API keys
- Bypass constructor validation
- Store unhashed tokens or secrets in KV
- Break existing handler patterns
- Use `any` type without explicit justification
- Force push to main

## Keeping AGENTS.md updated

Update this file when:

- Adding new modules or significant features
- Changing project structure
- Modifying build/test tooling
- Adding new code patterns or conventions
- Changing contribution workflows
