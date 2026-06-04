---
'@cloudflare/workers-oauth-provider': patch
---

Add an opt-in `allowPublicClients` flag to `enterpriseManagedAuthorization`.

By default the enterprise-managed authorization (ID-JAG) grant requires client authentication, so public clients (`token_endpoint_auth_method: 'none'`) are rejected. Setting `allowPublicClients: true` also accepts public clients on this grant — for example clients registered via a Client ID Metadata Document (CIMD), which are always public and cannot present a client secret. The default remains `false`, preserving existing behavior.
