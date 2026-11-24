---
'@cloudflare/workers-oauth-provider': patch
---

Re-check `registrationExpiresAt` after re-reading the client record in `renewClientRegistrationIfDue` to skip redundant KV writes when a concurrent request already renewed the DCR client registration, and add multi-cycle lifecycle coverage verifying `refreshTokenIdleTTL` + `clientRegistrationTTL` sliding renewal past 90 days.
