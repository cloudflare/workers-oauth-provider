---
'@cloudflare/workers-oauth-provider': minor
---

Error redirects back to the client no longer need building by hand. `AuthorizationError.redirectTo` is the ready-made redirect (`error`, `error_description`, `state`, `iss`), set only when a redirect is safe, i.e. when `redirectUri` was validated. `authorizationErrorRedirect(request, code, description?)` builds the same for an error the application decides on, such as a decline at a third-party provider, from a request the library validated. `denyConsent()` uses it.
