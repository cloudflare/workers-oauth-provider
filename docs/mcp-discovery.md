# MCP authorization discovery

How an MCP client finds your authorization server, and the two metadata documents it reads on the way.

An MCP client discovers authorization in two stages, following the [MCP authorization server discovery rules](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery).

For an MCP endpoint at `https://mcp.example.com/mcp`:

1. The client sends an unauthenticated request to `/mcp`.
2. The provider returns `401 Unauthorized` with a challenge similar to:

   ```http
   WWW-Authenticate: Bearer realm="OAuth", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="mcp:read"
   ```

3. The client fetches the protected resource metadata:

   ```text
   https://mcp.example.com/.well-known/oauth-protected-resource/mcp
   ```

4. That document identifies one or more authorization server issuers through `authorization_servers`.
5. The client fetches RFC 8414 authorization server metadata from the selected issuer. In [`examples/split-workers`](../examples/split-workers) that is:

   ```text
   https://auth.example.com/.well-known/oauth-authorization-server
   ```

6. The metadata tells the client where to authorize, exchange tokens, and register if registration is enabled.

Protected resource metadata and authorization server metadata serve different roles:

- Protected resource metadata describes the MCP server and identifies its authorization servers.
- Authorization server metadata describes OAuth endpoints and capabilities such as PKCE and CIMD.

## Protected resource metadata

Every protected resource needs its own `resourceMetadata.resource`. Configure each canonical HTTPS identifier with a lowercase scheme and host (plain `http` is accepted only on a loopback host, for `wrangler dev`):

```ts
resourceMetadata: {
  resource: 'https://mcp.example.com/mcp',
  authorization_servers: ['https://auth.example.com'],
  bearer_methods_supported: ['header'],
  resource_name: 'Files MCP server',
},
requiredScopes: ['files:read'], // published as this document's scopes_supported
```

For the example above, an unauthenticated request to the exact canonical URL receives a Bearer challenge pointing to:

```text
https://mcp.example.com/.well-known/oauth-protected-resource/mcp
```

That document returns the configured canonical `resource`. The discovery URL is built from the canonical resource: an origin uses `/.well-known/oauth-protected-resource`, and a path and query are inserted after the well-known prefix.

A canonical path is the base audience for its path-boundary descendants: a token for `https://mcp.example.com/mcp` is accepted at `/mcp/tools`, and a challenge at `/mcp/tools` advertises the one canonical document for `/mcp`, as RFC 9728 §5.1 permits. A request on another origin, or one that the canonical resource does not cover, gets a challenge without `resource_metadata`. Every protected route must be the canonical resource path or a descendant of it; the provider rejects any other `apiRoute` or `apiHandlers` key at construction, because a token could never validate there.

`authorization_servers` may contain more than one issuer. Each value must use canonical HTTPS issuer spelling: lowercase scheme and host, with no userinfo, default port, dot segments, query, or fragment. As with resources, `http` is accepted only on a loopback host. OAuth issuer comparison is exact. The MCP client chooses an authorization server and must keep credentials and tokens separate for each issuer. `new OAuthResourceServer()` requires it explicitly, wherever the resource runs.

## Clients that read only the root document

MCP clients that follow the spec read the challenge's `resource_metadata`, or try the path-specific URL first, so they never look at the root. `serveResourceMetadataAtRoot` covers clients that look for the metadata only at `/.well-known/oauth-protected-resource`, such as Alexa+ account linking, which reads the document there when account linking is configured. It's on `OAuthResourceServer` and `OAuthProvider`, and it's off by default:

```ts
new OAuthResourceServer<Env, AuthProps>({
  resourceMetadata: {
    resource: 'https://mcp.example.com/mcp',
    authorization_servers: ['https://auth.example.com'],
  },
  serveResourceMetadataAtRoot: true, // also at /.well-known/oauth-protected-resource
  validateToken: (env) => env.AUTH_SERVER.validateToken,
  handler,
});
```

The same document is served at the origin's root as well as at the path-specific URL, and the `401` challenge still names the path-specific one. The document's `resource` stays the configured one (`https://mcp.example.com/mcp`). That steps outside RFC 9728, whose well-known locations derive from the resource identifier, which is why the option is opt-in: a client that applies RFC 9728 §3.3 strictly to the root expects the origin there and gets no usable document, as with the `404` before. RFC 9728 §3.1 uses path components so one host can serve several resources, so don't enable this on a host whose other paths belong to other parties: a client that reads only the root would get this resource's document for any resource on the host. One resource per origin can claim the root, and the option changes nothing for a resource that is a bare origin.

## Authorization server metadata

The provider publishes RFC 8414 metadata containing:

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `protected_resources`, containing the authorization server's registered canonical resources
- `registration_endpoint`, when DCR is enabled
- supported response and grant types
- token endpoint authentication methods
- PKCE methods
- revocation endpoint
- RFC 9207 issuer support
- CIMD support when it is enabled and safe to use

The package serves RFC 8414 metadata rather than OpenID Connect discovery. MCP authorization servers need to provide at least one of those mechanisms, so RFC 8414 is sufficient.
