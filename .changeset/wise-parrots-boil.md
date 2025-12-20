---
'@cloudflare/workers-oauth-provider': patch
---

feat: add Client ID Metadata Document (CIMD) support

(by @mattzcarey in https://github.com/cloudflare/workers-oauth-provider/issues/112)

CIMD support allows clients to use HTTPS URLs as client_id values that
point to metadata documents.

When a client_id is an HTTPS URL with a non-root path, the provider
fetches and validates the metadata document instead of looking up in KV
storage. Added validation to ensure client_id in the document matches
the URL and redirect_uris are present.

matches the new authorization spec for MCP

https://modelcontextprotocol.io/specification/draft/basic/authorization
