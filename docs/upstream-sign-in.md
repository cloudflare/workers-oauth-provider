# Signing in through another provider

Many MCP servers don't have their own users: they sign people in with GitHub, Sentry, Google, or another OAuth provider, and call that provider's API with the user's token. The MCP server is still the authorization server for MCP clients, but its `/authorize` page hands the user to the third party and finishes when the third party redirects back.

Every MCP client then reaches the third party through your one OAuth app. MCP's security best practices call this the [confused deputy problem](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#confused-deputy-problem) and require consent per client before the redirect, a consent page that can't be framed or forged, and a `state` bound to the user's browser. The helpers below implement those requirements; the consent page itself is yours.

## The flow

```ts
const oauth = authorizationServer.getOAuthApi(env); // or env.OAUTH_PROVIDER with OAuthProvider

// GET /authorize: parse, then ask for consent.
const request = await oauth.parseAuthRequest(req);
const client = await oauth.lookupClient(request.clientId);
const consent = await oauth.beginConsent(request);
return new Response(renderConsentPage({ client, request, handle: consent.handle }), {
  headers: consent.headers, // binding cookie, no framing, no caching
});

// POST /authorize: the user approved. Now, and only now, start the third-party redirect.
const form = await req.formData();
const approved = await oauth.approveConsent(req, String(form.get('handle')), {
  scope: form.getAll('scope').map(String), // optional: the scopes the user ticked, from any in scopesSupported
});
const verifier = crypto.randomUUID() + crypto.randomUUID();
const { state, headers } = await oauth.beginUpstream(approved.request, {
  data: { verifier }, // returned at the callback; never sent to the third party
  headers: approved.headers,
});
headers.set('Location', githubAuthorizeUrl({ state, codeChallenge: await s256(verifier) }));
return new Response(null, { status: 302, headers });

// GET /callback: recover the request, exchange the third party's code, finish.
const { request: original, data, headers: clear } = await oauth.finishUpstream<{ verifier: string }>(req);
const upstream = await exchangeGithubCode(new URL(req.url).searchParams.get('code')!, data.verifier);
const { redirectTo } = await oauth.completeAuthorization({
  request: original,
  userId: upstream.user.id,
  metadata: {},
  scope: original.scope,
  props: { githubToken: upstream.accessToken }, // encrypted; handlers get it in ctx.props
});
clear.set('Location', redirectTo);
return new Response(null, { status: 302, headers: clear });
```

Build the consent page itself, and the Deny path (`denyConsent()`), as in [consent-page.md](consent-page.md), which also covers which errors to redirect and which to render. Validation failures throw `AuthorizationError` without a `redirectUri`: render them locally. A `TypeError` (bad options) or a storage failure is a bug or an outage, not the user's doing.

`beginUpstream()` doesn't check consent itself: call it only after `approveConsent()`, or when `isConsentRemembered()` says yes. (A server whose clients are all pre-registered, with no dynamic registration, isn't required to ask per client and can call it directly.)

If the third party sends the user back with an error (they declined there, or it failed), `finishUpstream()` still returns the original request, so answer the client with it:

```ts
const { request: original, headers } = await oauth.finishUpstream(req);
const error = new URL(req.url).searchParams.get('error');
if (error) {
  const redirect = new URL(original.redirectUri);
  redirect.searchParams.set('error', 'access_denied');
  redirect.searchParams.set('state', original.state);
  if (original.issuer) redirect.searchParams.set('iss', original.issuer);
  headers.set('Location', redirect.href);
  return new Response(null, { status: 302, headers });
}
```

## What the helpers guarantee

- **The consent page can't be forged or framed.** `beginConsent()` binds the handle to the browser with a `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Lax`, ten minutes) and returns `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY`. A post from another site has the handle but not the cookie, and is refused.
- **`state` exists only after consent.** `beginUpstream()` creates it, stores the approved request server-side, and binds it to the browser. The callback is refused without the matching cookie, so a stolen third-party code can't be replayed in another browser.
- **Single use, ten minutes, several at once.** Each handle and `state` works once, and each has its own binding cookie, so two tabs can authorize at the same time. KV keys hold only the SHA-256 of the handle, and the record, including your `data` (a PKCE verifier, say), is encrypted with a key only the handle derives: reading KV alone reveals nothing. KV can't make `get`-then-`delete` atomic, so two simultaneous requests from the _same_ browser with the same handle could both pass; the cookie binding rules out anyone else.
- **Nothing trusted comes from the form.** The authorization request is recovered from storage, not from hidden fields, so the page can't be made to approve a different client or redirect URI. `scope` is the page's to choose, fewer or more than the client requested, but only from `scopesSupported`.

## Remembering consent

Pass `remember` to `approveConsent()` and check `isConsentRemembered()` before showing the page; when it's remembered, go straight to `beginUpstream()`. See [consent-page.md](consent-page.md#remembering-consent), which also covers the cookie names.

## When the third party revokes access

Store the third party's refresh token in `props` and refresh it in `tokenExchangeCallback`. When it answers `invalid_grant`, the user has revoked your app or the token is gone for good. Throw `invalid_grant` too: the library revokes this grant, with its tokens, so the MCP client re-authorizes instead of retrying a grant that can never work. For a transient failure (the provider is down, rate limited), throw `temporarily_unavailable` instead, which leaves the grant for the retry.

```ts
tokenExchangeCallback: async ({ grantType, props }) => {
  if (grantType !== 'refresh_token') return;
  const upstream = await refreshGithubToken(props.githubRefreshToken);
  if (upstream.error === 'bad_refresh_token') {
    throw new OAuthError('invalid_grant', { description: 'GitHub access was revoked' }); // revokes this grant
  }
  if (!upstream.ok) {
    throw new OAuthError('temporarily_unavailable', { description: 'GitHub is unavailable', statusCode: 503 });
  }
  return { newProps: { ...props, githubToken: upstream.accessToken, githubRefreshToken: upstream.refreshToken } };
},
```
