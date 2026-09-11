---
'@cloudflare/workers-oauth-provider': minor
---

Add pluggable storage providers. All clients, grants, access tokens, and replay markers now go through a small storage contract. Omitting the new `storage` option keeps the `OAUTH_KV` binding and its physical key layout, so existing deployments need no migration. The Durable Object SQLite provider (`@cloudflare/workers-oauth-provider/storage/durable-object`) serializes each user's grants, tokens, and refresh rotations in one object with strong read-after-write, and replaces a user's earlier grants for the same client through an index instead of scanning every grant. Retryable storage failures at the token endpoint return `temporarily_unavailable` with `Retry-After`. The contract is exported from `@cloudflare/workers-oauth-provider/storage` for custom providers.
