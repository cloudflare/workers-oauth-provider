---
'@cloudflare/workers-oauth-provider': patch
---

Validate the URI scheme of client metadata fields during client registration.

The `client_uri`, `logo_uri`, `policy_uri`, `tos_uri`, and `jwks_uri` fields
were previously only checked to be strings. They are now required to be
absolute `http:` or `https:` URLs, consistent with how `redirect_uris` are
already validated. Registration (and Client ID Metadata Document ingestion)
now rejects values using other schemes with an `invalid_client_metadata`
error.

These fields are commonly surfaced in consent UIs (for example as link or
image targets), so restricting them to standard web URLs avoids non-http(s)
schemes flowing through to consumers.
