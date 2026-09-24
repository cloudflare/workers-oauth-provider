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
  scope: form.getAll('scope').map(String), // optional: the scopes the user ticked
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

The consent page must name the client, show the scopes and the `redirect_uri` its tokens will go to, and post `handle` back. Every helper that fails throws `AuthorizationError` without a `redirectUri`, so render it locally, the same as `parseAuthRequest()` failures.

## What the helpers guarantee

- **The consent page can't be forged or framed.** `beginConsent()` binds the handle to the browser with a `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Lax`, ten minutes) and returns `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY`. A post from another site has the handle but not the cookie, and is refused.
- **`state` exists only after consent.** `beginUpstream()` creates it, stores the approved request server-side, and binds it to the browser. The callback is refused without the matching cookie, so a stolen third-party code can't be replayed in another browser.
- **Single use, ten minutes.** Each handle and `state` works once. KV keys hold only the SHA-256 of the handle. KV can't make `get`-then-`delete` atomic, so two simultaneous requests from the _same_ browser with the same handle could both pass; the cookie binding rules out anyone else.
- **Nothing trusted comes from the form.** The authorization request is recovered from storage, not from hidden fields, and `scope` can only narrow what was requested.

## Remembering consent

By default the consent page appears on every authorization, which also lets users re-authorize with different scopes. To skip it for clients a user already approved, pass `remember` when approving and check before showing the page:

```ts
const remember = { secret: env.CONSENT_SECRET }; // at least 32 characters, from a Worker secret

if (await oauth.isConsentRemembered(req, request, remember)) {
  const { state, headers } = await oauth.beginUpstream(request, { data: { verifier } });
  // …redirect to the third party
}
// …after the consent POST:
await oauth.approveConsent(req, handle, { scope, remember }); // maxAgeSeconds defaults to 30 days
```

Approvals live in a signed `__Host-` cookie, bound to the client ID, its redirect URI and the resource, and they cover only the scopes that were approved: asking for more brings the page back.

## Cookie names

The helpers set `__Host-oauth-consent`, `__Host-oauth-upstream` and `__Host-oauth-approvals`. Change the prefix with the `cookiePrefix` option if those collide with yours; it must start with `__Host-`.

## When the third party revokes access

Store the third party's refresh token in `props` and refresh it in `tokenExchangeCallback`. When it answers `invalid_grant`, the user has revoked your app or the token is gone for good. Throw with `revokeGrant: true` so this grant is revoked too, and the MCP client re-authorizes instead of retrying:

```ts
tokenExchangeCallback: async ({ grantType, props }) => {
  if (grantType !== 'refresh_token') return;
  const upstream = await refreshGithubToken(props.githubRefreshToken);
  if (upstream.error === 'bad_refresh_token') {
    throw new OAuthError('invalid_grant', { description: 'GitHub access was revoked', revokeGrant: true });
  }
  return { newProps: { ...props, githubToken: upstream.accessToken, githubRefreshToken: upstream.refreshToken } };
},
```
