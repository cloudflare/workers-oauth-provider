---
'@cloudflare/workers-oauth-provider': patch
---

adds a method `decodeToken` that retrieves a granted access token from the KV and returns the user-defined props attached to it. This permits token decoding outside of a fetch call, e.g. an RPC call from another worker.
