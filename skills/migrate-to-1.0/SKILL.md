---
name: workers-oauth-provider-migrate-1.0
description: Migrate a Cloudflare Worker from @cloudflare/workers-oauth-provider 0.x to 1.0. Use when upgrading that dependency, when OAuthProvider construction throws about resourceMetadata.resource or resourceMatchOriginOnly, or when asked to adopt the 1.0 role-based API (OAuthAuthorizationServer / OAuthResourceServer).
---

# Migrate @cloudflare/workers-oauth-provider 0.x → 1.0

The single source of truth for every change is the migration guide shipped with the package:
`node_modules/@cloudflare/workers-oauth-provider/docs/migration-1.0.md`
(also at https://github.com/cloudflare/workers-oauth-provider/blob/main/docs/migration-1.0.md).
Read it fully before editing. This skill is the procedure around it; do not work from memory of 0.x or from this file alone.

## Procedure

1. **Detect the shape.** Find `new OAuthProvider(` and read its options. The common shape is one Worker acting as authorization server and resource server; that shape stays on `OAuthProvider` in 1.0. Do not introduce `OAuthAuthorizationServer`/`OAuthResourceServer` unless the user asks for a multi-Worker or multi-resource topology.
2. **Choose the canonical resource — ask the user.** `resourceMetadata: { resource }` is required in 1.0. The value is the URL MCP clients connect to (often an existing `apiRoute` on the Worker's public origin, e.g. `https://mcp.example.com/mcp`). Infer a candidate from `wrangler.jsonc` routes/custom domains plus `apiRoute`, present it, and get confirmation — it becomes the token audience, so it must be right.
3. **Apply the guide's changes** that match the code: add `resourceMetadata.resource`; delete `resourceMatchOriginOnly`; make `resolveExternalToken` return the canonical `audience`; single-string `resource`/`aud` types; check `apiRoute`s are the resource path or descendants.
4. **Bump the dependency** to `^1.0.0` and install.
5. **Verify** (below), then walk the user through the guide's "Existing stored data" section so they know what their live clients will experience (nothing, in the common case).

## Stop and ask the user

- The canonical `resource` value (step 2). Never guess silently.
- On a multi-resource `OAuthAuthorizationServer`: which resource is `legacyGrantResource` (the migration destination for pre-1.0 grants). Omitting it makes old grants reauthorize.
- Any DCR client base registered with narrow `grant_types`: 1.0 enforces them; confirm the registered types cover what clients actually send before deploying.
- Adopting new 1.0 surface (role classes, `ctx.auth`, `insufficientScope`, `onError.internal`) is optional — offer, don't do unasked.

## Verify

1. `tsc`/typecheck and the project's tests pass.
2. `wrangler dev`, then:
   - `curl http://localhost:8787/.well-known/oauth-protected-resource` → 200, `resource` equals the chosen canonical value (loopback `http` is allowed in dev).
   - `curl -i http://localhost:8787<api route>` → 401 with a `WWW-Authenticate` header naming `resource_metadata`.
   - Construction errors surface on the first request and name the violated rule; fix per the guide.
3. If the deployment has live users, re-read "Existing stored data — nothing to do" in the guide and confirm no step you took contradicts it (no KV edits, no `legacyGrantResource` changes after rollout).
