---
'@cloudflare/workers-oauth-provider': patch
---

Fix client authentication method negotiation so ChatGPT can prefer `private_key_jwt` while offering the provider's supported `none` alternative.

DCR and CIMD now use one typed client metadata parser aligned with draft-ietf-oauth-client-id-metadata-document-00 (the revision pinned by MCP 2026-07-28) and OpenID Connect RP Metadata Choices 1.0. The CIMD resolver validates cross-field choices and prohibited credentials, rejects unsafe document URLs, applies response-size and timeout limits to the complete fetch, caches only validated documents with a 7-day lifetime cap, and recovers from a cached document that stops validating by re-resolving from origin in the same request.
