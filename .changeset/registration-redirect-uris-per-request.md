---
'@cloudflare/workers-oauth-provider': patch
---

A registration may list redirect URIs the redirect policy refuses, next to one it accepts. Some Cursor versions register `cursor://anysphere.cursor-mcp/oauth/callback` beside their https and loopback callbacks and sign in with the loopback one; 1.2.0 refused the whole registration because of the `cursor://` entry, although 0.10 accepted it. Dynamic registration, `createClient()` and `updateClient()` now need at least one redirect URI that follows the policy, and still refuse any with a dangerous scheme, a fragment or userinfo. Every authorization request is still held to the full policy: `parseAuthRequest()` refuses a refused URI locally, and `completeAuthorization()` won't send a code to one.
