---
'@cloudflare/workers-oauth-provider': patch
---

Return a fully qualified `registration_client_uri` from dynamic client registration when `clientRegistrationEndpoint` is configured as a path, as required by RFC 7592.
