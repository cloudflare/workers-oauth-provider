---
'@cloudflare/workers-oauth-provider': minor
---

Add helpers for authorization servers that sign users in through another OAuth provider, implementing the MCP security best practices' confused-deputy protections.

- `beginConsent()` / `approveConsent()` / `denyConsent()` run a consent page whose handle is bound to the browser by a `__Host-` cookie, single-use and valid for ten minutes, with `frame-ancestors 'none'` and `X-Frame-Options: DENY`. `approveConsent({ scope })` takes the scopes the user chose on the page, fewer or more than requested, each in `scopesSupported`.
- `approveConsent(…, { remember: { secret } })` and `isConsentRemembered()` remember an approval per call in a signed cookie bound to the client, redirect URI and resource, covering only the approved scopes. Without `remember`, consent is asked every time.
- `beginUpstream()` / `finishUpstream()` store the approved request server-side, create the third party's `state` only after consent, bind it to the browser, and return it once at the callback with your `data` (such as a PKCE verifier).
- `cookiePrefix` renames the cookies; it must start with `__Host-`.
- An `OAuthError('invalid_grant')` thrown from `tokenExchangeCallback` now revokes the grant the callback ran for, with its access tokens, before answering. `invalid_grant` can never recover (RFC 6749 §5.2), so the client re-authorizes instead of retrying, and outstanding access tokens stop working immediately. Throw `temporarily_unavailable` for transient upstream failures to keep the grant.

Transactions are stored in `OAUTH_KV` under `transaction:{sha256(handle)}`, encrypted with a key derived from the handle, with a ten-minute TTL; each has its own binding cookie, so concurrent authorizations in one browser don't collide. `remember.subject` binds a remembered approval to the signed-in user. `denyConsent()` returns the `access_denied` redirect back to the client with its `state` and `iss`. See `docs/consent-page.md` and `docs/upstream-sign-in.md`.
