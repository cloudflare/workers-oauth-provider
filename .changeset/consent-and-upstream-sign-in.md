---
'@cloudflare/workers-oauth-provider': minor
---

Add helpers for authorization servers that sign users in through another OAuth provider, implementing the MCP security best practices' confused-deputy protections.

- `beginConsent()` / `approveConsent()` run a consent page whose handle is bound to the browser by a `__Host-` cookie, single-use and valid for ten minutes, with `frame-ancestors 'none'` and `X-Frame-Options: DENY`. `approveConsent()` can narrow the scopes, never widen them.
- `approveConsent(…, { remember: { secret } })` and `isConsentRemembered()` remember an approval per call in a signed cookie bound to the client, redirect URI and resource, covering only the approved scopes. Without `remember`, consent is asked every time.
- `beginUpstream()` / `finishUpstream()` store the approved request server-side, create the third party's `state` only after consent, bind it to the browser, and return it once at the callback with your `data` (such as a PKCE verifier).
- `cookiePrefix` renames the cookies; it must start with `__Host-`.
- `OAuthError`'s new `revokeGrant: true`, thrown from `tokenExchangeCallback`, revokes the grant it ran for before answering, for when the upstream grant is gone.

Transactions are stored in `OAUTH_KV` under `transaction:{sha256(handle)}` with a ten-minute TTL. See `docs/upstream-sign-in.md`.
