---
'@cloudflare/workers-oauth-provider': patch
---

Client ID Metadata Document clients can authenticate with `private_key_jwt` (RFC 7523). A document that offers only `private_key_jwt`, which was refused before, now works. The client publishes its keys in `jwks` or an `https:` `jwks_uri`, and signs each token and revocation request with an `RS256` or `ES256` client assertion. The assertion is checked for `iss`, `sub`, `aud`, `exp` (at most an hour away) and a single-use `jti`. A document that offers both `none` and `private_key_jwt`, as ChatGPT's does, keeps working with `none` and may use either method. With CIMD enabled, the authorization server metadata advertises `private_key_jwt` and `token_endpoint_auth_signing_alg_values_supported`.
