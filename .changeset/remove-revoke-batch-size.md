---
'@cloudflare/workers-oauth-provider': patch
---

The `revokeExistingGrantsBatchSize` option of `completeAuthorization()` is removed. Since 1.0 every grant carries key metadata, so earlier grants are found without reading them; the option only set how many pre-1.0 grants were read at once, and those disappear as they refresh. They are now read 50 at a time.
