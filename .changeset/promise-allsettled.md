---
'@cloudflare/workers-oauth-provider': patch
---

Use `Promise.allSettled` instead of `Promise.all` for best-effort grant revocation in `completeAuthorization()`, ensuring all grants are attempted even if one fails.
