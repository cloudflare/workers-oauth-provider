---
'@cloudflare/workers-oauth-provider': patch
---

Add `allowPlainPKCE` option to enforce S256-only PKCE as recommended by OAuth 2.1. When set to false, the plain PKCE method is rejected and only S256 is accepted. Defaults to true for backward compatibility.
