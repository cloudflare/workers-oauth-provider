---
'@cloudflare/workers-oauth-provider': patch
---

Tighten Client ID Metadata Document validation by requiring a non-empty `client_name` and accepting only the currently implemented public-client authentication method, `none`. Support OpenID RP Metadata Choices by selecting `none` from `token_endpoint_auth_methods_supported`, including ChatGPT-style documents that also advertise `private_key_jwt`.
