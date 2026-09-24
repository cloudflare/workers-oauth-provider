---
'@cloudflare/workers-oauth-provider': patch
---

With `disallowPublicClientRegistration`, a dynamic registration that prefers `none` but also supports a secret method is registered with the secret method instead of being refused. `none` is simply not on offer during negotiation; a client that supports only `none` is still refused.
