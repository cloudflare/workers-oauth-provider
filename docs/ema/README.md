# MCP Enterprise-Managed Authorization (EMA) — Implementation Context

Reference material for adding EMA support to `@cloudflare/workers-oauth-provider`. This folder captures the protocol, the RFCs it composes, and the structural review of draft PR cloudflare/workers-oauth-provider#203.

## Files

| File | Purpose |
|------|---------|
| [`01-spec.md`](./01-spec.md) | Canonical MCP EMA specification (extracted from `modelcontextprotocol/ext-auth`). The authoritative protocol description. |
| [`02-rfcs.md`](./02-rfcs.md) | Implementer-focused reference for every RFC EMA touches. Read this when validating an ID-JAG or wiring metadata. |
| [`03-flow.md`](./03-flow.md) | Concrete flow from the *Authorization Server*'s perspective — i.e. what this library actually has to do on the wire. |
| [`04-pr-203-review.md`](./04-pr-203-review.md) | Structural review of irvinebroque's experiment PR #203 (the starting point we're restructuring). |
| [`05-restructure-plan.md`](./05-restructure-plan.md) | Proposed Effectful, DRY, concern-split restructure. |

## TL;DR (read this first)

EMA introduces a **third party** into OAuth: the **enterprise IdP**. The IdP signs a short-lived JWT — the **ID-JAG** (Identity Assertion JWT Authorization Grant) — that says "user *X* (with corporate identity), via OAuth client *C*, is allowed to obtain an access token for MCP resource *R* with scopes *S*".

The MCP client redeems the ID-JAG at our token endpoint using **RFC 7523's JWT-bearer grant**. We validate it (signature + claims + replay), map its claims onto our local user/scope/props model, and issue a normal opaque access token. The end user never visits our `/authorize` endpoint.

```
  IdP  ──(signs ID-JAG)──▶  MCP Client  ──(POST /token, jwt-bearer)──▶  AS (us)  ──▶  Access Token
```

### What we have to implement

1. **Trust registry**: per-IdP `{issuer, jwksUri, allowed algs, expected aud}`.
2. **JWT-bearer grant** (`urn:ietf:params:oauth:grant-type:jwt-bearer`) on the token endpoint.
3. **ID-JAG validator** with strict `typ=oauth-id-jag+jwt` typing, signature verification via fetched JWKS, claim checks (`iss`, `aud`, `client_id`, `resource`, `exp`, `iat`, `jti`), and **replay protection** (one `jti` per assertion lifetime).
4. **Claims-to-props mapper hook**: the deployer-supplied function that turns validated IdP claims into the local `userId` / `scope` / `props`.
5. **AS metadata**: advertise `jwt-bearer` in `grant_types_supported` when EMA is on.

### What we explicitly do NOT need

- PKCE on the jwt-bearer grant (RFC 7636 does not apply — see [`02-rfcs.md`](./02-rfcs.md#rfc-7636--pkce-does-not-apply-to-jwt-bearer)).
- An authorization endpoint round-trip for the EMA flow.
- Refresh tokens for EMA-issued grants (the spec is silent; the current PR omits them — see review).

### Key non-RFC requirement worth highlighting

The `client_id` ↔ `iss` trust binding is the **single most important security check** and is **not** in any single RFC — it emerges from composing RFC 7523 §3 + RFC 7591's "metadata is self-asserted" warning. Without it, any trusted IdP can mint tokens for any registered client. PR #203 implements this implicitly by trusting that the IdP set `client_id` in the ID-JAG to match the authenticated `client_id` — see [`04-pr-203-review.md`](./04-pr-203-review.md) §3 for whether this is sufficient.
