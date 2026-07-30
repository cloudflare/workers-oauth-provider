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

Requirements are enabled from the revision that introduced them. Shared OAuth behavior is exercised against every revision.

## Coverage and traceability

| Scenario                                                                                               | Applicable revisions                   | Specification                                                                                          |
| ------------------------------------------------------------------------------------------------------ | -------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Authorization server metadata, endpoints, grants, token authentication methods, and S256 advertisement | All                                    | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), MCP authorization                                  |
| Authorization code flow for public and confidential clients                                            | All                                    | OAuth 2.1 authorization code grant                                                                     |
| S256 PKCE enforcement; missing, plain, unsupported method, and incorrect verifier rejection            | All                                    | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), OAuth 2.1                                          |
| Safe redirect URI and client validation                                                                | All                                    | OAuth 2.1 authorization endpoint security                                                              |
| `client_secret_basic`, `client_secret_post`, and public-client token endpoint authentication           | All                                    | OAuth 2.1 token endpoint                                                                               |
| DCR public/confidential clients and metadata validation                                                | All, retained as compatibility in 2026 | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591), MCP client registration                            |
| Refresh rotation, retry behavior, downscoping, and RFC 7009 revocation                                 | All                                    | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) |
| Protected Resource Metadata at the path-aware well-known URL                                           | `2025-06-18`+                          | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728), MCP authorization server discovery                 |
| `WWW-Authenticate` discovery and `invalid_token` behavior                                              | `2025-06-18`+                          | [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750), RFC 9728                                           |
| Resource Indicators in authorization/token responses and exact audience validation                     | `2025-06-18`+                          | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), MCP authorization security considerations          |
| Baseline and operation-specific `insufficient_scope` challenges                                        | `2025-11-25`+                          | RFC 6750, MCP scope challenge handling                                                                 |
| Pre-registered clients and Client ID Metadata Documents                                                | `2025-11-25`+                          | MCP client registration, OAuth Client ID Metadata Documents                                            |
| Authorization response issuer advertisement and response parameter                                     | `2026-07-28`                           | [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)                                                     |
| `offline_access` kept out of resource metadata and Bearer challenges                                   | `2026-07-28`                           | MCP refresh token guidance                                                                             |

## Test architecture

`worker/` is a real Wrangler project started through Cloudflare's [`createTestHarness()`](https://developers.cloudflare.com/workers/testing/test-harness/) API. Wrangler builds the Worker and runs it in Workerd with:

- a local `OAUTH_KV` namespace using the actual Workers KV binding API;
- the `global_fetch_strictly_public` compatibility flag used by CIMD;
- an application-owned authorization handler that grants synthetic consent;
- a protected `/mcp` handler that exposes only authenticated props; and
- the canonical resource `https://mcp.example.com/mcp` where the revision requires Resource Indicators.

`support/oauth-server.ts` is a thin OAuth HTTP client around the test harness. It uses Worker RPC only to pre-register clients through `OAuthHelpers`; DCR and every OAuth flow run over HTTP. The harness recreates local storage after each test.

Tests assert only observable HTTP responses, redirects, metadata, challenges, and token behavior. They do not access provider internals or stored records.

## Files

- `worker/index.ts` — deployable Worker fixture hosting `OAuthProvider`.
- `worker/wrangler.jsonc` — Worker configuration and local KV binding.
- `support/oauth-server.ts` — test-harness lifecycle and OAuth HTTP client.
- `authorization-server.test.ts` — metadata and authorization-code/PKCE flows.
- `authorization-security.test.ts` — redirect, client authentication, Resource Indicator, issuer, and refresh-scope security.
- `protected-resource.test.ts` — RFC 9728 discovery, Bearer challenges, scopes, and audience enforcement.
- `client-registration.test.ts` — DCR, pre-registration, and CIMD.
- `token-lifecycle.test.ts` — refresh, downscoping, code replay, and revocation.
- `spec-versions.ts` — revision applicability matrix.

Application-owned identity, consent presentation, and operation-level authorization policy remain outside the provider and therefore outside this server conformance suite. Experimental authorization extensions such as Enterprise-Managed Authorization continue to have focused validation and integration coverage in `__tests__/` rather than being treated as core dated-spec requirements here.
