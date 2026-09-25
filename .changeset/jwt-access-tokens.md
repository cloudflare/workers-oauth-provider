---
'@cloudflare/workers-oauth-provider': minor
---

Add experimental signed JWT access tokens to `OAuthAuthorizationServer`, exempt from 1.x semver while experimental. Set `accessTokens: { issuing: 'jwt', jwt: { keys } }` to issue ES256 RFC 9068 access tokens and publish a JWKS. Configuring `jwt` while issuing `'opaque'` publishes the keys and accepts JWTs first, for a staged switch or a rollback. `validateToken()` still finds the stored token record by the token's hash, so revocation stays immediate. `createJwtAccessTokenValidator()` validates the tokens offline in a resource server against public keys the application supplies, for one explicit issuer. Authorization codes and refresh tokens stay opaque, and existing opaque access tokens remain valid until they expire. Adds `jose` as a runtime dependency.
