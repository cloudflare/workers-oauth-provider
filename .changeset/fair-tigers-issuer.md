---
'@cloudflare/workers-oauth-provider': minor
---

Enable RFC 9207 authorization response issuer identification. Authorization server metadata advertises support, parsed requests carry the expected issuer for application-owned terminal error responses, and successful code and implicit redirects include `iss`.
