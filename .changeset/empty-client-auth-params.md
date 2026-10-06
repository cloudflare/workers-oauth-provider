---
'@cloudflare/workers-oauth-provider': patch
---

An empty `client_id` or `client_secret` at the token endpoint is treated as omitted, as RFC 6749 §3.2 requires. A public client that sends `client_secret=` with no value now authenticates as `none` instead of failing with `invalid_client`, and an empty form parameter next to a Basic header no longer counts as a second authentication method. A non-empty secret or Basic credential on a `none` client is still refused.
