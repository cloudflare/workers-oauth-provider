---
'@cloudflare/workers-oauth-provider': minor
---

Add a pluggable storage provider interface via the `storage` option.

By default, the provider still uses the `OAUTH_KV` namespace exactly as before.
Custom backends now implement the small KV-shaped `OAuthStorage` interface and
are passed as an instance:

```ts
import { env } from 'cloudflare:workers';

export default new OAuthProvider({
  // ...
  storage: new MyStorage(env.MY_BINDING),
});
```

This keeps the library backend-agnostic: no built-in Postgres/Hyperdrive code,
no `pg` dependency, and no storage-specific config DSL. See
`docs/storage-providers.md` for the interface, a Postgres/Hyperdrive example,
and a migration guide for standardizing on the module-scope provider export.
