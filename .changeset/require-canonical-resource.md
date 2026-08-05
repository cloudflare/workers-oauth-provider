---
'@cloudflare/workers-oauth-provider': major
---

Add the functional `OAuthAuthorizationServer` API for one authorization server to register and issue tokens for multiple MCP protected resources. `protectResource()` registers a canonical resource hosted in the same Worker and returns its independently routable fetch surface; `registerResource()` registers an audience hosted elsewhere; and `validateToken()` provides audience-checked opaque-token validation suitable for a fixed-resource private Service Binding. Authorization server metadata advertises the finite registry through RFC 9728 `protected_resources`.

Add `createOAuthResourceServer()` for a separately deployed protected-resource Worker. It publishes that resource's RFC 9728 metadata, returns Bearer challenges, accepts an application-supplied token-validation callback, checks the returned audience and expiry, and exposes validated application properties to the protected handler. The package does not add a public introspection or JWT endpoint.

Bind every new grant and access token to exactly one registered canonical HTTPS resource. A multi-resource authorization request must select exactly one resource unless `defaultResource` supplies a deliberate compatibility default. Code exchange and refresh inherit the resource stored on the grant and reject attempts to retarget it. Grants for the same user and client replace only grants for the same resource, so authorizing one MCP server does not revoke another server's grant.

For compatibility, an authorization server with one registered resource automatically uses it when a client omits `resource` and as the migration destination for a stored pre-resource grant. Multi-resource deployments can configure `legacyGrantResource` as a separate, server-controlled migration destination; without one, unbound old grants must be reauthorized. The existing combined `OAuthProvider` API remains supported and is normalized to this sole-resource behavior.

Require canonical `resourceMetadata.resource` values for hosted protected resources. Explicit resource values tolerate only ASCII case differences in the URI scheme and host. Token exchange, protected API access, external token resolvers, and standalone resource-server callbacks all fail closed on an audience mismatch. Remove `resourceMatchOriginOnly`, and advertise protected-resource metadata in challenges only when it identifies the exact canonical request URL.
