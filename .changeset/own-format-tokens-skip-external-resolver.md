---
'@cloudflare/workers-oauth-provider': patch
---

A bearer token in this provider's own `userId:grantId:secret` format that isn't found in storage (an expired or revoked access token, or a forgery of the format) is now answered `invalid_token` directly instead of being handed to `resolveExternalToken`. Resolvers that validate foreign credentials upstream were forwarding our expired tokens to third-party APIs: about 24k calls an hour in one production deployment, from MCP clients presenting a stale access token before refreshing.
