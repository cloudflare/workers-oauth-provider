---
'@cloudflare/workers-oauth-provider': minor
---

Use `resourceMetadata.resource` as the strict RFC 8707 resource policy. Configured deployments now require that exact resource throughout authorization, token issuance, and access-token validation. Unconfigured deployments remain interoperable by inheriting requested resources and defaulting omitted authorization resources to the request origin.
