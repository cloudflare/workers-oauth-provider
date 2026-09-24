---
'@cloudflare/workers-oauth-provider': minor
---

`onError.internal` is now set on every error the library originates, not only the EMA path: `{ category, reason, detail? }` names the exact check that failed (`refresh_token_mismatch` vs `refresh_token_expired` vs `grant_not_found`, `code_replayed`, `client_secret_mismatch`, `resource_not_configured`, …) while the wire response stays exactly as before (RFC 6749 §5.2). The shape is exported as `OAuthErrorInternal`; category slugs are kebab-case subsystems, reason slugs snake_case checks, and both are stable. `OAuthError` accepts `options.internal` so a `tokenExchangeCallback` can tag its own errors; one thrown without it reaches `onError` as `{ category: 'token-exchange-callback', reason: 'callback_error', detail: error }`.
