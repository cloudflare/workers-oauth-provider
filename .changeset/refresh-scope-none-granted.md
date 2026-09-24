---
'@cloudflare/workers-oauth-provider': patch
---

A token request whose `scope` names only scopes the grant doesn't hold is refused with `invalid_scope` (RFC 6749 §6) at code exchange, refresh and token exchange, instead of succeeding with a token that carries no scope. Requests that name at least one granted scope are still narrowed silently, as before.
