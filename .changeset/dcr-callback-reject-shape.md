---
'@cloudflare/workers-oauth-provider': minor
---

Simplify `clientRegistrationCallback` to be an allow-or-reject policy hook. Returning `undefined` allows registration; returning an object rejects registration with optional `code`, `description`, and `status`. Metadata override behavior has been removed.
