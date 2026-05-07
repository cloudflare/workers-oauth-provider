---
'@cloudflare/workers-oauth-provider': minor
---

Convert `OAuthError` thrown from `tokenExchangeCallback` into structured
`/token` responses.

Previously, an error thrown from `tokenExchangeCallback` during the
`authorization_code` or `refresh_token` grant flows would bubble up as an
unhandled exception and be served as `500 Internal Server Error`. This forced
clients to keep retrying with the same dead refresh token, producing
"refresh-token retry storms" against upstream providers.

The provider now catches `OAuthError` thrown from the callback (or any code
it calls — errors propagate naturally up through deep call stacks) and
returns a standard `{ error, error_description }` response with the supplied
status code and headers.

```ts
import { OAuthError } from '@cloudflare/workers-oauth-provider';

tokenExchangeCallback: async (options) => {
  if (options.grantType === 'refresh_token') {
    // `refreshUpstream` may throw `OAuthError` from any depth.
    return { newProps: await refreshUpstream(options.props) };
  }
};

async function refreshUpstream(props) {
  const res = await fetch(/* upstream token endpoint */);
  if (res.status === 401) {
    throw new OAuthError('invalid_grant', {
      description: 'upstream refresh token is invalid',
    });
  }
  if (res.status === 429) {
    throw new OAuthError('temporarily_unavailable', {
      description: 'upstream rate limited',
      statusCode: 429,
      headers: { 'Retry-After': res.headers.get('retry-after') ?? '60' },
    });
  }
  return await res.json();
}
```

`OAuthError(code, options)` takes:

- `code` (positional, required) — must be one of the registered OAuth
  `/token` error codes supported by this package.
- `options.description` — human-readable text returned in `error_description`.
- `options.statusCode` — HTTP status code (default `400`).
- `options.headers` — additional response headers. Set `Retry-After` here
  for transient failures so well-behaved clients back off; per RFC 7231
  §7.1.3 the value may be either seconds or an HTTP-date. No implicit
  default — if you don't set it, no `Retry-After` is sent.

This package's `OAuthError` class is the recommended form. Existing
application-specific OAuth error classes also work if they throw a real
`Error` with `name === 'OAuthError'`, a registered token-endpoint `code`,
and optional `description` / `statusCode` / `headers` fields. Anything
else — plain `Error`, plain objects with a `code` field, OAuth errors with
non-token-endpoint codes, etc. — continues to surface as `500 Internal
Server Error` so unexpected failures stay visible. The provider does not
catch-everything-and-return-400.

The exported `OAuthError` class supersedes the previously-internal one: the
constructor signature is now `(code, options)` rather than `(code, message)`.
Internal call sites are updated; `description` now lives alongside
`statusCode` and `headers` in the options object.

**New exports:** `OAuthError` (class), `OAuthErrorOptions` (interface),
`OAuthTokenErrorCode` (type union of registered codes).
