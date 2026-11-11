---
'@cloudflare/workers-oauth-provider': patch
---

The token endpoint now reads the grant for an authorization-code exchange with the minimum KV edge cache TTL (30 seconds). KV caches negative lookups at the edge, so an exchange arriving before the grant write has propagated to its location was answered with `invalid_grant`, and every retry of the same fresh code kept hitting the cached miss for a full 60 seconds. Reading with `cacheTtl: 30` halves that window: retries succeed once the write reaches the location, at worst one 30-second negative-cache cycle later.
