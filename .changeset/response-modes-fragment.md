---
'@cloudflare/workers-oauth-provider': patch
---

Advertise `fragment` in `response_modes_supported` when `allowImplicitFlow` enables the implicit `token` response type. RFC 8414 §2 requires authorization server metadata to list supported response modes; RFC 6749 §4.2.2 delivers implicit-flow access tokens through the redirect URI fragment.
