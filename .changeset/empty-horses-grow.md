---
"@cloudflare/workers-oauth-provider": patch
---

Add resolveExternalToken to support external token auth flows

Adds resolveExternalToken to support auth for external tokens. The callback only runs IF internal auth check fails. E.g. a canonical OAuth server is used by multiple services, allowing server-server communication with the same token.
