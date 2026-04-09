---
'@cloudflare/workers-oauth-provider': patch
---

Include `fragment` in `response_modes_supported` when `allowImplicitFlow` is true (RFC 6749 §4.2.2).
