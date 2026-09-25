---
name: workers-oauth-provider-migrate-1.0
description: Upgrade a Cloudflare Worker's @cloudflare/workers-oauth-provider from 0.x, 1.0 or 1.1 to the latest 1.x. Use when bumping that dependency, or when OAuthProvider / OAuthAuthorizationServer / OAuthResourceServer construction throws after an upgrade.
---

# Upgrade @cloudflare/workers-oauth-provider to the latest 1.x

Reference (read the section for every hit): `node_modules/@cloudflare/workers-oauth-provider/docs/migration-1.0.md`.
Types and JSDoc: `node_modules/@cloudflare/workers-oauth-provider/dist/oauth-provider.d.ts`.
No KV migration exists or is needed; never edit stored data.

## Procedure

1. Note the installed version (`package.json`). Skip guide sections tagged older than it.
2. Search the project for each pattern below and apply the fix.
3. Bump to the latest `^1`, install, typecheck, run tests. Construction errors quote the rule; grep the guide for the message.
4. Keep `OAuthProvider` if the project uses it. Don't move to `OAuthAuthorizationServer`/`OAuthResourceServer` unless asked.

| Pattern in the project                                                                                                                          | Fix                                                                                                   | Guide section                                                 |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `new OAuthProvider(` without `resourceMetadata`                                                                                                 | add `resourceMetadata: { resource }` (ask the user for the value)                                     | The canonical resource is required                            |
| `resourceMatchOriginOnly`                                                                                                                       | delete                                                                                                | Removed: `resourceMatchOriginOnly`                            |
| `resolveExternalToken`                                                                                                                          | return `audience: <resource>`                                                                         | `resolveExternalToken` names its audience                     |
| `scopes_supported` inside `resourceMetadata`                                                                                                    | move to top-level `requiredScopes`                                                                    | `requiredScopes` replaces `resourceMetadata.scopes_supported` |
| `allowImplicitFlow`, `allowPlainPKCE`                                                                                                           | delete; own clients must use code + S256                                                              | Removed: the implicit grant and plain PKCE                    |
| `redirectUris` / redirect URIs with `http://` non-loopback or a custom scheme                                                                   | https or loopback; native apps: `allowPrivateUseRedirectUris: true`                                   | Redirect URIs must be HTTPS or loopback HTTP                  |
| `clientRegistrationTTL: 0`; any `*TTL` below 60                                                                                                 | `0` → `undefined`; raise to ≥ 60                                                                      | Lifetimes are validated at construction                       |
| `userId:` built with `:` (e.g. `` `${a}:${b}` ``)                                                                                               | `encodeURIComponent(...)`, same value in `listUserGrants`/`revokeGrant`                               | User IDs cannot contain `:`                                   |
| `revokeExistingGrantsBatchSize`                                                                                                                 | delete                                                                                                | Removed: `revokeExistingGrantsBatchSize`                      |
| imports of `resourceMatches`, `validateResourceUri`, `isValidOAuthScopeToken`, `base64UrlToBytes`, `parseJwtJsonPart`, `getJwtCryptoAlgorithms` | inline the logic; no replacement export                                                               | Internal helpers are no longer exported                       |
| `createClient(` / `updateClient(`                                                                                                               | only `authorization_code`/`refresh_token`/enabled grants, `code` responses; don't update CIMD clients | Client helpers validate what they store                       |
| `tokenExchangeCallback`                                                                                                                         | `OAuthError('invalid_grant')` now revokes the grant; `env` is available; check returned TTLs          | `tokenExchangeCallback`                                       |
| `purgeExpiredData(`                                                                                                                             | persist `result.cursor`, pass it back as `cursor`                                                     | `purgeExpiredData()` resumes from a cursor                    |
| `new OAuthAuthorizationServer(`                                                                                                                 | drop `authorizeEndpoint`/`tokenEndpoint` if they equal `${issuer}/authorize`, `${issuer}/oauth/token` | `OAuthAuthorizationServer` endpoints have defaults            |
| `ExchangeTokenOptions.aud`, `AuthRequest.resource` as arrays                                                                                    | single strings                                                                                        | Type changes                                                  |

## Ask the user, don't guess

- The canonical `resource` (the URL MCP clients connect to; becomes the token audience).
- On a multi-resource `OAuthAuthorizationServer`: `legacyGrantResource`, the destination for pre-1.0 grants. Fixed once deployed.
- Whether registered clients use remote `http` or custom-scheme redirect URIs (they stop authorizing), and whether any user IDs contain `:`. Neither shows up in a typecheck.
- Whether DCR clients registered narrow `grant_types` (now enforced).
- Adopting optional features (role classes, `ctx.auth`, `insufficientScope`, consent helpers, `refreshTokenIdleTTL`): offer, don't do unasked.

## Verify

- `wrangler dev`, then `curl -i http://localhost:8787<api route>`: `401` whose `WWW-Authenticate` has `resource_metadata="…/.well-known/oauth-protected-resource<resource path>"`.
- With a loopback dev resource, `curl http://localhost:8787/.well-known/oauth-protected-resource<resource path>`: `200` with the exact `resource`. Production serves it only on the resource's own origin.
- `curl http://localhost:8787/.well-known/oauth-authorization-server`: `authorization_endpoint` and `token_endpoint` unchanged from before the upgrade.
