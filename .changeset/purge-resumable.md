---
'@cloudflare/workers-oauth-provider': patch
---

`purgeExpiredData()` is resumable. It returns a `cursor` whenever the sweep isn't finished, and takes it back as `PurgeOptions.cursor`. Previously every invocation started from the first grant, so with more than `batchSize` live grants a scheduled sweep re-checked the same records forever, never reached later grants, and never swept orphaned tokens at all. Persist the cursor between runs; the example in `docs/advanced-configuration.md` stores it in KV.
