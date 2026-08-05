---
'@cloudflare/workers-oauth-provider': major
---

Require one canonical HTTPS `resourceMetadata.resource` for every provider. Clients may omit RFC 8707 resource parameters at authorization, code exchange, and refresh; the provider binds every new grant and access token to the configured canonical audience. Explicit values must match it, with tolerance only for ASCII case in the URI scheme and host.

When processing a valid authorization-code exchange or refresh, bind a grant with no stored resource to the configured canonical resource. Matching grants inherit it and mismatched grants fail closed. Token exchange and protected API access now require the same canonical audience, and external token resolvers must return an audience.

Remove `resourceMatchOriginOnly`. Protected-resource challenges advertise RFC 9728 metadata only when the incoming protected URL is the exact canonical resource, avoiding a metadata document whose `resource` does not identify the original request.
