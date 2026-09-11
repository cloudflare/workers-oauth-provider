/**
 * PLACEHOLDER LOGIN AND CONSENT PAGE. It asks for a username and believes the answer.
 *
 * Replace this file in production: authenticate the resource owner before the form is
 * ever shown (a signed session cookie, an upstream IdP such as GitHub, or Cloudflare
 * Access in front of `/authorize`), add a CSRF token, and show a consent screen the user
 * can act on. See "Before production" in the README.
 */
export function renderLoginPage(url: URL, clientName: string, scopes: string[], resource: string): Response {
  // Posting back to the same query string is what carries the authorization request to
  // the POST; `parseAuthRequest()` re-validates it there. Nothing is stored in between.
  const action = escapeHtml(`${url.pathname}${url.search}`);
  const scopeItems = (scopes.length ? scopes : ['(none)'])
    .map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`)
    .join('');

  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Authorize ${escapeHtml(clientName)}</title>
  </head>
  <body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 3rem auto">
    <h1>Authorize ${escapeHtml(clientName)}</h1>
    <p>This is a placeholder login. Any username is accepted.</p>
    <p>Scopes that will be granted:</p>
    <ul>${scopeItems}</ul>
    <p>Resource: <code>${escapeHtml(resource)}</code></p>
    <form method="post" action="${action}">
      <label>Sign in as <input name="username" value="demo" autocomplete="username" /></label>
      <p>
        <button type="submit" name="action" value="approve">Approve</button>
        <button type="submit" name="action" value="deny">Deny</button>
      </p>
    </form>
  </body>
</html>
`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => HTML_ESCAPES[character]);
}
