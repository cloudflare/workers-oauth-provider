---
'@cloudflare/workers-oauth-provider': minor
---

Redirect URIs must use `https`, or `http` on a loopback host (`localhost`, `127.0.0.0/8`, `::1`), as MCP and OAuth 2.1 require, with no userinfo or fragment. The rule is enforced at dynamic registration, in CIMD documents, in `createClient()` and `updateClient()` (which previously validated nothing), and on every authorization request, so clients registered before the policy are held to it: their authorizations fail with a locally rendered `invalid_request`, never a redirect.

Breaking: clients registered with a remote `http` redirect URI or a private-use scheme stop authorizing. Native apps that rely on RFC 8252 private-use schemes (`com.example.app:/cb`) keep working with the new `allowPrivateUseRedirectUris: true`; remote `http` is never accepted.
