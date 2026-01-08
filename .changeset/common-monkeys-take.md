---
'@cloudflare/workers-oauth-provider': patch
---

Add `getOAuthApi` helper function to access OAuthHelpers outside of the `fetch` method. This enables OAuth functionality in worker RPC methods and other entry points.
