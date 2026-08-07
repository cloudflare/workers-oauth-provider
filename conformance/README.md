# MCP authorization conformance tests

This directory contains black-box conformance tests for the OAuth authorization-server and protected-resource behavior provided by `OAuthProvider`.

The suite intentionally tests only MCP authorization. It does not test MCP JSON-RPC methods, lifecycle, tools, prompts, resources, or HTTP transport framing. The protected `/mcp` route is a minimal authenticated HTTP endpoint so the tests can observe whether a bearer token reaches the application handler.

## Run the suite

```sh
npm run test:conformance
```

The normal `npm test` and `npm run check` commands also discover these tests, so a conformance regression fails CI.

## Tested revisions

The matrix follows every dated authorization revision represented by the official [`@modelcontextprotocol/conformance`](https://github.com/modelcontextprotocol/conformance) timeline:

- [`2025-03-26`](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- [`2025-06-18`](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [`2025-11-25`](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

Requirements are enabled from the revision that introduced them. Shared OAuth behavior is exercised against every revision, with the target revision sent in the `MCP-Protocol-Version` header.

These are compatibility profiles, not server-side protocol negotiation. The common server profile stays fixed while client request behavior changes by revision: `2025-03-26` omits the RFC 8707 `resource` parameter, while `2025-06-18` and later include it in authorization and token requests. Canonical-resource pinning is tested separately: omission defaults to or inherits the configured canonical value, while explicit malformed or mismatched values fail with `invalid_target`.

## Coverage and traceability

| Scenario                                                                                               | Applicable revisions                       | Specification                                                                                          |
| ------------------------------------------------------------------------------------------------------ | ------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| Authorization server metadata, endpoints, grants, token authentication methods, and S256 advertisement | `SHOULD` in 2025-03; required later        | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), MCP authorization                                  |
| Authorization code flow for public and confidential clients                                            | All                                        | OAuth 2.1 authorization code grant                                                                     |
| S256 PKCE enforcement; missing, plain, unsupported method, and incorrect verifier rejection            | All                                        | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), OAuth 2.1                                          |
| Safe redirect URI and client validation                                                                | All                                        | OAuth 2.1 authorization endpoint security                                                              |
| `client_secret_basic`, `client_secret_post`, and public-client token endpoint authentication           | All                                        | OAuth 2.1 token endpoint                                                                               |
| DCR public/confidential clients and metadata validation                                                | `SHOULD` in 2025-03/06; `MAY` later        | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591), MCP client registration                            |
| Public-client refresh rotation, retry behavior, downscoping, and RFC 7009 revocation                   | `SHOULD` in 2025-03; rotation `MUST` later | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) |
| Bearer challenges and `invalid_token` responses                                                        | All                                        | [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750), OAuth 2.1                                          |
| Protected Resource Metadata at the path-aware well-known URL                                           | `2025-06-18`+                              | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728), MCP authorization server discovery                 |
| `resource_metadata` links in `WWW-Authenticate`                                                        | `2025-06-18`+                              | RFC 9728                                                                                               |
| Resource Indicators in authorization/token responses and exact audience validation                     | `2025-06-18`+                              | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), MCP authorization security considerations          |
| Baseline and operation-specific `insufficient_scope` challenges                                        | `2025-11-25`+                              | RFC 6750, MCP scope challenge handling                                                                 |
| Pre-registered clients and Client ID Metadata Documents                                                | `2025-11-25`+                              | MCP client registration, OAuth Client ID Metadata Documents                                            |
| Authorization response issuer advertisement in success and terminal error responses                    | `2026-07-28`                               | [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)                                                     |
| `offline_access` kept out of resource metadata and Bearer challenges                                   | `2026-07-28`                               | MCP refresh token guidance                                                                             |

## Latest release coverage

The official [`latest` specification](https://modelcontextprotocol.io/specification/latest) resolves to `2026-07-28`. This suite covers the authorization-server and protected-resource responsibilities from that release:

| 2026 authorization change                              | This package's role                                                     | Coverage                                                                                                     |
| ------------------------------------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| RFC 9207 authorization-response issuer (SEP-2468)      | Authorization server                                                    | Metadata advertisement plus successful and terminal error responses                                          |
| DCR `application_type` guidance (SEP-837)              | MCP client                                                              | Not applicable to this server library; DCR remains available as a deprecated compatibility mechanism         |
| Bind persisted client credentials to issuer (SEP-2352) | MCP client                                                              | Not applicable to this server library                                                                        |
| Refresh-token and `offline_access` guidance (SEP-2207) | Authorization server and protected resource                             | Public-client rotation; `offline_access` advertised by the AS but excluded from PRM and Bearer challenges    |
| Scope accumulation during step-up (SEP-2350)           | Primarily MCP client; resource server supplies current-operation scopes | `insufficient_scope` challenge includes all scopes required for the current operation                        |
| OAuth well-known discovery suffix rules (SEP-2351)     | MCP client discovers; AS/RS publish metadata                            | RFC 8414 authorization-server metadata plus root and path-specific RFC 9728 metadata/challenges              |
| DCR deprecation in favor of CIMD                       | Authorization server                                                    | CIMD advertisement, document/auth-method negotiation, pre-registration, and optional DCR compatibility       |
| RFC 8707 Resource Indicators and audience restriction  | Authorization server and protected resource                             | Canonical default/inheritance, exact explicit-value pinning, token response resource, and audience rejection |

The broader `2026-07-28` protocol changes—stateless request `_meta`, `server/discover`, MCP method headers, tools, and transport lifecycle—are intentionally out of scope because this package does not implement MCP transport or protocol methods.

Authorization extensions are versioned separately from the core release. Stable Enterprise-Managed Authorization has focused implementation tests in `__tests__/`; it remains experimental package functionality rather than part of this core conformance matrix. The OAuth Client Credentials extension is still draft and is not implemented by this package.

## Relationship to the official conformance runner

The upstream `@modelcontextprotocol/conformance` authorization-server mode currently exposes two scenarios—metadata and authorization code grant—and applies both to all four dates. The real Worker fixture passed both upstream scenarios for every date using upstream `0.2.0-alpha.10` (`49103de`) over a local HTTPS issuer.

The upstream authorization-code scenario does not send RFC 8707 `resource`. The provider safely defaults a configured canonical resource at authorization and inherits it at code exchange, so that compatibility scenario remains audience-bound. This suite also tests explicit Resource Indicators and adds the revision-specific protected-resource, audience, registration, scope, refresh, revocation, and issuer scenarios listed above.

## Test architecture

`worker/` is a real Wrangler project started through Cloudflare's [`createTestHarness()`](https://developers.cloudflare.com/workers/testing/test-harness/) API. Wrangler builds the Worker and runs it in Workerd with:

- a local `OAUTH_KV` namespace using the actual Workers KV binding API;
- the `global_fetch_strictly_public` compatibility flag used by CIMD;
- an application-owned authorization handler that grants synthetic consent;
- a protected `/mcp` handler that exposes only authenticated props; and
- the canonical resource `https://mcp.example.com/mcp` where the revision requires Resource Indicators.

`support/oauth-client.ts` is the OAuth HTTP client around the test harness. A typed Worker RPC selects either the fixed backwards-compatible profile or the canonical-resource profile and pre-registers clients through `OAuthHelpers`; DCR and every OAuth flow run over HTTP. The harness recreates local storage after each test.

Tests assert only observable HTTP responses, redirects, metadata, challenges, and token behavior. They do not access provider internals or stored records.

## Files

- `worker/index.ts` — deployable Worker fixture hosting `OAuthProvider`.
- `worker/wrangler.jsonc` — Worker configuration and local KV binding.
- `shared.ts` — explicit RPC configuration, credential types, and fixture constants.
- `support/harness.ts` — Workerd lifecycle and per-test storage reset.
- `support/oauth-client.ts` — OAuth HTTP client.
- `authorization-server.test.ts` — metadata and authorization-code/PKCE flows.
- `authorization-security.test.ts` — redirect, client authentication, Resource Indicator, issuer, and refresh-scope security.
- `protected-resource.test.ts` — RFC 9728 discovery, Bearer challenges, scopes, and audience enforcement.
- `client-registration.test.ts` — DCR, pre-registration, and CIMD.
- `token-lifecycle.test.ts` — refresh, downscoping, code replay, and revocation.
- `spec-versions.ts` — revision applicability matrix.

Application-owned identity, consent presentation, and operation-level authorization policy remain outside the provider and therefore outside this server conformance suite.
