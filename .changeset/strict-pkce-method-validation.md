---
'@cloudflare/workers-oauth-provider': patch
---

Reject unsupported PKCE `code_challenge_method` values instead of treating them as `plain`. PKCE policy is now revalidated by `completeAuthorization()`, and token exchange fails closed for malformed grants created by older versions.
