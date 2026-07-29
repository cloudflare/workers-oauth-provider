---
'@cloudflare/workers-oauth-provider': patch
---

Tighten Client ID Metadata Document validation by requiring a non-empty `client_name` and rejecting `private_key_jwt` until token-endpoint assertion validation is implemented. This prevents accepting CIMD clients that cannot complete authorization securely.
