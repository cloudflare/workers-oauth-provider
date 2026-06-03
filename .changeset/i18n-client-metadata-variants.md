---
'@cloudflare/workers-oauth-provider': patch
---

Preserve RFC 7591 §2.2 internationalized client metadata variants.

Localized variants of the human-readable client metadata fields — expressed
with a `#<BCP 47 language tag>` suffix on the member name (e.g.
`client_name#ja`, `tos_uri#fr`) — were previously dropped during client
registration. They are now captured for `client_name`, `client_uri`,
`logo_uri`, `tos_uri`, and `policy_uri`, stored on the client record under a
new optional `i18n` map (keyed by the raw `field#tag` name), and echoed back in
the registration response alongside their canonical fields. The same handling
applies to Client ID Metadata Document ingestion.

Localized values are validated with the same rules as their canonical field:
URI variants must be absolute `http:` or `https:` URLs, and all variants must
be strings. Fields that are not part of RFC 7591 §2.2 (such as `jwks_uri` and
`redirect_uris`) are not collected.
