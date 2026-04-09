---
'@cloudflare/workers-oauth-provider': minor
---

Add DPoP support (RFC 9449). Binds access tokens to a client key pair — stolen tokens are useless without the private key. Enable with `allowDPoP: true`. Includes jti replay protection, grant-level key binding on refresh, and `DPoP` auth scheme support at the resource server. RS256 and ES256.
