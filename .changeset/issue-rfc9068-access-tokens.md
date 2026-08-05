---
'@cloudflare/workers-oauth-provider': minor
---

Add opt-in RFC 9068 JWT access tokens to `OAuthAuthorizationServer`. The authorization server publishes a JWKS while retaining encrypted token records, so same-Worker resources and private Service Binding validation keep confidential `ctx.props`, token exchange, and immediate revocation. Add a fixed-issuer, fixed-audience validator for separate resource Workers that need offline access to explicitly public claims.
