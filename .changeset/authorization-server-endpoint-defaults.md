---
'@cloudflare/workers-oauth-provider': minor
---

`OAuthAuthorizationServer`'s `authorizeEndpoint` and `tokenEndpoint` are optional and default to `${issuer}/authorize` and `${issuer}/oauth/token`, under the issuer's path if it has one. `OAuthProvider` still requires both.

Construction also rejects any endpoint another would claim, so it could never be reached: a token, registration or authorization endpoint on the metadata path with a query (metadata is served whatever the query), an endpoint that is the token endpoint plus a query, or an authorization endpoint equal to the token or registration endpoint.
