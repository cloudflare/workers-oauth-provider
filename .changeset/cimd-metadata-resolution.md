---
'@cloudflare/workers-oauth-provider': patch
---

Fix client authentication method negotiation so ChatGPT can prefer `private_key_jwt` while offering the provider's supported `none` alternative.

DCR and CIMD now use one typed client metadata parser. The CIMD resolver validates cross-field choices and prohibited credentials, rejects unsafe document URLs and redirects, caches only validated documents, and applies response-size and timeout limits to the complete fetch.
