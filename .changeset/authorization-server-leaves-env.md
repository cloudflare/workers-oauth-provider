---
'@cloudflare/workers-oauth-provider': patch
---

`OAuthAuthorizationServer.fetch()` no longer writes `env.OAUTH_PROVIDER` into the caller's `env` when it answers a path that isn't one of its endpoints. It answers `404` directly; a dead branch meant it fell through to a placeholder handler after setting the helpers, which only the combined `OAuthProvider`'s `defaultHandler` reads. Use `authorizationServer.getOAuthApi(env)` for the helpers, as documented.
