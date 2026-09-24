---
'@cloudflare/workers-oauth-provider': patch
---

A grant issued without a refresh token (`refreshTokenTTL: 0`, from the option or a `tokenExchangeCallback`) now expires with its access token. It used to be stored with no expiry, so every such authorization left a grant record in KV for good.
