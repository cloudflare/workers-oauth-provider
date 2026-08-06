---
'@cloudflare/workers-oauth-provider': minor
---

Add opt-in RFC 9068 JWT access tokens to `OAuthAuthorizationServer`. The authorization server publishes a JWKS while retaining encrypted token records, so same-Worker resources and private Service Binding validation keep confidential `ctx.props`, token exchange, and immediate revocation. Add a fixed-issuer, fixed-audience validator for separate resource Workers that need offline access to explicitly public claims. Add a functional `accessTokenFormat` issuance policy so deployments can install JWT readers and JWKS while continuing to write opaque access tokens, then switch new and refreshed access tokens to JWT without invalidating existing tokens or refresh grants. Correct cross-client token exchange so the authenticated exchanging client owns the new token, including JWT claims, format rollout, revocation, client deletion, and orphan cleanup.
