---
'@cloudflare/workers-oauth-provider': patch
---

`createClient()` and `updateClient()` check grant and response types against what the server implements, as dynamic registration does, so a client can no longer be stored with, say, `grantTypes: ['implicit']` and then fail every authorization. `updateClient()` refuses a Client ID Metadata Document client while CIMD is enabled, instead of writing a stored copy that did nothing then and would have become the client if CIMD were later turned off. `deleteClient()` on a CIMD client revokes its grants, as before, and is now documented as doing so.
