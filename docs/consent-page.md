# Building a consent page

Your `authorizeEndpoint` is your page: the library validates the request, and you sign the user in and ask whether this client may act for them. The consent helpers (`beginConsent()`, `approveConsent()`, `denyConsent()`, `isConsentRemembered()`) make that page safe to build. A server that signs users in through another provider also needs [upstream-sign-in.md](upstream-sign-in.md).

## What the page must show

From the MCP authorization spec and security best practices:

- **The client's name**, and **the scopes** being granted.
- **The redirect URI's hostname** (MUST): where the tokens will go.
- **A warning when that hostname is `localhost`** (SHOULD). A CIMD client's name comes from its metadata document, but anyone can present that document and listen on a local port, so the name alone doesn't prove which app is asking.
- **A CIMD client's domain**, prominently. Its `client_id` is a URL on a domain the client controls; a DCR client's name is self-asserted.
- **No framing**, and a form that can't be forged: `beginConsent()` returns the headers and the browser-bound handle that do this.

## Escape everything that came from the client

`clientName`, `clientUri`, `logoUri` and the scope strings come from dynamic registration or a CIMD document, so an attacker chooses them. Rendered without escaping, they're script running on your authorization origin, next to your users' sessions.

## A minimal page

`describeConsent(request)` returns exactly those facts: the client's name, its verified domain for a CIMD client, the redirect URI's hostname, whether that is a local app, and the scopes.

```ts
import type { ConsentDescription } from '@cloudflare/workers-oauth-provider';

const escape = (value: string) => value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

function consentPage(details: ConsentDescription, handle: string): string {
  const name = escape(details.clientName);
  const origin = details.clientDomain
    ? `Published by <strong>${escape(details.clientDomain)}</strong>.`
    : 'This app registered itself; its name is not verified.';
  const scopes = details.scope
    .map(
      (scope) => `<label><input type="checkbox" name="scope" value="${escape(scope)}" checked> ${escape(scope)}</label>`
    )
    .join('<br>');
  return `<!doctype html>
<meta charset="utf-8">
<title>Authorize ${name}</title>
<h1>Allow ${name} to access your account?</h1>
<p>${origin} Access will be sent to <strong>${escape(details.redirectHost)}</strong>.</p>
${details.redirectIsLoopback ? '<p><strong>This sends access to an app on your computer.</strong> Continue only if you just started signing in from it.</p>' : ''}
<form method="post">
  <input type="hidden" name="handle" value="${escape(handle)}">
  ${scopes}
  <p><button name="decision" value="approve">Allow</button> <button name="decision" value="deny">Deny</button></p>
</form>`;
}
```

## Showing it, approving, declining

```ts
const oauth = authorizationServer.getOAuthApi(env); // or env.OAUTH_PROVIDER with OAuthProvider

// GET /authorize (after signing the user in with your own session)
const request = await oauth.parseAuthRequest(req);
const details = await oauth.describeConsent(request); // first: a failed lookup leaves nothing in KV
const consent = await oauth.beginConsent(request);
consent.headers.set('Content-Type', 'text/html; charset=utf-8');
return new Response(consentPage(details, consent.handle), { headers: consent.headers });

// POST /authorize
const form = await req.formData();
const handle = String(form.get('handle'));
if (form.get('decision') !== 'approve') {
  const denied = await oauth.denyConsent(req, handle); // redirect to the client: access_denied, state, iss
  return new Response(null, { status: 302, headers: denied.headers });
}
const approved = await oauth.approveConsent(req, handle, { scope: form.getAll('scope').map(String) });
const { redirectTo } = await oauth.completeAuthorization({
  request: approved.request, // from storage, not from the form
  userId: session.userId,
  metadata: {},
  scope: approved.request.scope,
  props: { userId: session.userId },
});
approved.headers.set('Location', redirectTo);
return new Response(null, { status: 302, headers: approved.headers });
```

The authorization request is kept server-side between the two requests; the form carries only the handle, which works once, for ten minutes, in the browser that opened the page. `scope` is what the user ticked: fewer or more than the client requested, each in `scopesSupported`.

## Errors: redirect or render?

A redirect back to the client is only safe once the client and its exact redirect URI are validated. Everything else is shown on your page.

| Where it fails                                                                     | What to do                                                                                                                         |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `parseAuthRequest()` throws `AuthorizationError` **with** `redirectUri`            | Redirect to it with `error`, `error_description`, `state` and `iss` from the error (see the quick start)                           |
| `parseAuthRequest()` throws `AuthorizationError` **without** `redirectUri`         | Render locally. Never redirect: the client or redirect URI isn't trusted                                                           |
| `parseAuthRequest()` / `lookupClient()` throw `CimdFetchError`                     | Render locally: the client's metadata document couldn't be fetched (`error.reason`, `error.detail` for your logs)                  |
| `approveConsent()`, `denyConsent()`, `finishUpstream()` throw `AuthorizationError` | Render locally: the page expired, was used, or was opened in another browser, or the scopes aren't supported. Offer to start again |
| Any helper throws something else (`TypeError`, a KV failure)                       | A bug or an outage, not the user's doing: let it surface as a 500                                                                  |
| The user clicks Deny                                                               | `denyConsent()`, then send its redirect                                                                                            |
| A third-party provider returns `error=` to your callback                           | `finishUpstream()`, then redirect to the client with `access_denied` ([upstream-sign-in.md](upstream-sign-in.md))                  |
| Token endpoint errors                                                              | The library answers them; observe them with `onError`                                                                              |

```ts
try {
  // …the handlers above
} catch (error) {
  if (error instanceof AuthorizationError && error.redirectTo) {
    return Response.redirect(error.redirectTo, 302); // error, error_description, state, iss
  }
  if (error instanceof AuthorizationError || error instanceof CimdFetchError) {
    const message = error instanceof AuthorizationError ? error.description : 'This app could not be verified.';
    return new Response(escape(message), { status: 400, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
  throw error;
}
```

## Remembering consent

By default the page appears on every authorization, which also lets users re-authorize with different scopes. To skip it for clients a user already approved, pass `remember` when approving and check before showing the page:

```ts
const remember = { secret: env.CONSENT_SECRET, subject: session.userId }; // secret: 32+ chars, from a Worker secret

if (await oauth.isConsentRemembered(req, request, remember)) {
  // skip the page: complete the authorization (or start the third-party sign-in) directly
}
// …when approving:
await oauth.approveConsent(req, handle, { scope, remember }); // maxAgeSeconds defaults to 30 days
```

Approvals live in a signed `__Host-` cookie, bound to the client ID, its redirect URI and the resource, and they cover only the scopes that were approved: asking for more brings the page back. Pass `subject` (the signed-in user) whenever you know it, so another account on the same browser is asked again. Without it an approval belongs to the browser, which is what a proxy server gets, since it learns the user from the third party only after consent.

## Cookie names

Each consent page and each third-party redirect gets its own short-lived cookie, `__Host-oauth-consent-…` or `__Host-oauth-upstream-…` (so two tabs can authorize at once), and remembered approvals live in `__Host-oauth-approvals`. Change the prefix with the `cookiePrefix` option if those collide with yours; it must start with `__Host-`.
