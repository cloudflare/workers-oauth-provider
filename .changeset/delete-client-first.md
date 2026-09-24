---
'@cloudflare/workers-oauth-provider': patch
---

`deleteClient()` deletes the client before revoking its grants, so the client stops working at once even if revocation fails partway; calling it again finishes the revocation. It finds the client's grants from their KV key metadata instead of reading every grant in the namespace one by one, which could exceed a Worker's subrequest limit and, because the client record was deleted last, leave the client active.
