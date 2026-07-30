---
'@cloudflare/workers-oauth-provider': patch
---

Reject unsupported PKCE `code_challenge_method` values instead of treating them as `plain`. Discovery and request validation now share one PKCE capability policy, `completeAuthorization()` revalidates reconstructed requests, and token exchange fails closed for malformed grants created by older versions.
