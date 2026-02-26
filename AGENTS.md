# AGENTS.md

## Project overview

`@cloudflare/workers-oauth-provider` is a production-grade OAuth 2.1 provider library for Cloudflare Workers. It implements authorization code flow with PKCE, dynamic client registration, token exchange, and end-to-end encryption of sensitive data stored in KV.

**Primary use case:** This library powers authentication for **MCP (Model Context Protocol) servers**. MCP servers are OAuth Resource Servers, and this library provides the authorization server functionality needed to secure them.

This library was largely written with Claude AI assistance, with all code thoroughly reviewed by Cloudflare security engineers.

## MCP specification compliance

When modifying OAuth functionality, **always check the latest published MCP specification** (not drafts):

- **Specification:** https://modelcontextprotocol.io/specification/2025-11-25
- **Authorization section:** https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

This library must be feature-complete with the latest published MCP spec version. Key MCP auth requirements:

- MCP servers are OAuth Resource Servers with protected resource metadata (RFC 9728)
- MCP clients must support Resource Indicators (RFC 8707) for audience-scoped tokens
- Client registration supports: out-of-band, CIMD (Client ID Metadata Documents), and DCR (Dynamic Client Registration)
- Streamable HTTP transport uses OAuth 2.1 for authentication

When in doubt about OAuth behavior, the MCP specification takes precedence for MCP-related use cases.

## Repository structure

```
workers-oauth-provider/
├── src/
│   └── oauth-provider.ts      # Single source file (~4,100 lines)
├── __tests__/
│   ├── oauth-provider.test.ts # Comprehensive test suite (~6,400 lines)
│   ├── setup.ts               # Vitest setup and mocking
│   └── mocks/
│       └── cloudflare-workers.ts
├── dist/                      # Build output (tsdown)
├── examples/
│   └── typed-env-worker/      # Example worker with typed environment
├── .github/workflows/
│   ├── ci.yml                 # PR validation
│   ├── release.yml            # Changesets-based npm publishing
│   └── pkg-pr-new.yml         # PR preview packages
├── storage-schema.md          # KV namespace data structure docs
├── SECURITY.md                # Vulnerability reporting
└── README.md                  # Usage documentation
```

**Single-file architecture:** All implementation is in `src/oauth-provider.ts`. This is intentional for security review — all code in one place aids auditing.

## Setup

```bash
npm install    # Install dependencies
npm run build  # Build with tsdown
```

Node 24+ required.

## Commands

| Command              | What it does                              |
| -------------------- | ----------------------------------------- |
| `npm run build`      | Builds single-file ESM bundle with tsdown |
| `npm run check`      | Runs typecheck + tests                    |
| `npm run typecheck`  | TypeScript type checking (no emit)        |
| `npm run test`       | Runs vitest test suite                    |
| `npm run test:watch` | Runs vitest in watch mode                 |
| `npm run prettier`   | Formats all files with Prettier           |

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
npm run test          # Single run
npm run test:watch    # Watch mode
```

**Test file:** `__tests__/oauth-provider.test.ts`

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

### RFC compliance

This library implements multiple OAuth/security RFCs. When making changes, maintain compliance with:

- OAuth 2.1 (draft-ietf-oauth-v2-1-13)
- OAuth 2.0 Authorization Server Metadata (RFC 8414)
- OAuth 2.0 Protected Resource Metadata (RFC 9728)
- OAuth 2.0 Dynamic Client Registration (RFC 7591)
- PKCE (RFC 7636)
- OAuth 2.0 Token Exchange (RFC 8693)
- Resource Indicators for OAuth 2.0 (RFC 8707)
- Client ID Metadata Documents (draft spec)

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
