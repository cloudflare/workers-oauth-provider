---
'@cloudflare/workers-oauth-provider': patch
---

Validate authorization response types in both `parseAuthRequest()` and `completeAuthorization()`. Missing, unsupported, and client-disallowed values are rejected after client and redirect URI validation but before grant creation or existing-grant revocation.
