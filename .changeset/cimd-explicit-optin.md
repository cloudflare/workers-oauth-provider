---
'@cloudflare/workers-oauth-provider': minor
---

Add `clientIdMetadataDocumentEnabled` option to make CIMD (Client ID Metadata Document) support explicitly opt-in. Previously, CIMD auto-enabled when the `global_fetch_strictly_public` compatibility flag was present, which could cause crashes for servers where URL-shaped client_ids hit bot-protected endpoints. When not enabled (the default), URL-formatted client_ids now fall through to standard KV lookup instead of throwing.
