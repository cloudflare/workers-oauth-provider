---
'@cloudflare/workers-oauth-provider': major
---

Require one canonical HTTPS `resourceMetadata.resource` for every provider. MCP clients are required to send RFC 8707 resource parameters, but the provider tolerates omission at authorization, code exchange, and refresh for compatibility with legacy clients. Every new grant and access token is still bound to the configured canonical audience. Explicit values must match it, with tolerance only for ASCII case in the URI scheme and host.

Advertise the canonical resource in authorization server metadata as the provider's single RFC 9728 `protected_resources` entry. This remains the protected-resource identifier when the authorization server and resource server use different origins.

When processing a valid authorization-code exchange or refresh, bind a grant with no stored resource to the configured canonical resource. Matching grants inherit it and mismatched grants fail closed. Token exchange and protected API access now require the same canonical audience, and external token resolvers must return an audience.

Remove `resourceMatchOriginOnly`. Protected-resource challenges advertise RFC 9728 metadata only when the incoming protected URL is the exact canonical resource, avoiding a metadata document whose `resource` does not identify the original request.
