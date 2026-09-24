---
'@cloudflare/workers-oauth-provider': minor
---

`tokenExchangeCallback` receives the request's `env` (`TokenExchangeCallbackOptions<Env>['env']`), as `resolveExternalToken` already does. A callback that needs secrets or bindings, such as an upstream OAuth client secret, no longer forces the provider to be rebuilt on every request to close over `env`.
