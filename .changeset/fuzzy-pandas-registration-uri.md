---
'@cloudflare/workers-oauth-provider': patch
---

Stop returning `registration_client_uri` from dynamic client registration. The provider implements RFC 7591 registration but not the RFC 7592 client configuration endpoint previously advertised by this field.
