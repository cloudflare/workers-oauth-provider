---
'@cloudflare/workers-oauth-provider': minor
---

`OAuthResourceServer` and `OAuthProvider` take an opt-in `serveResourceMetadataAtRoot` option for clients that read protected resource metadata only at the origin's root, such as Alexa+ account linking. With it set, the metadata for a path resource like `https://mcp.example.com/mcp` is also served at `/.well-known/oauth-protected-resource`; the document still names the configured resource, and the path-specific document and the `401` challenge are unchanged. It defaults to false.
