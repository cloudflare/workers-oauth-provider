---
'@cloudflare/workers-oauth-provider': minor
---

Validate protected resource metadata at construction time. Reject empty or invalid authorization server issuer lists, invalid resource and scope values, and bearer presentation methods the provider does not implement instead of publishing unusable or misleading RFC 9728 metadata.
