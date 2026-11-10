---
'@cloudflare/workers-oauth-provider': patch
---

Dynamic Client Registration now registers the grant types this server supports instead of rejecting a client that asks for more. VS Code's published metadata declares the device-code grant next to authorization code and refresh grants, and registration failed with `invalid_client_metadata` before this change. RFC 7591 allows the server to ignore unsupported requested values, so the registration keeps the supported subset, echoes it in the response, and the token endpoint still refuses grants the client never got. Response type validation stays strict, and a request whose supported grant set is empty is rejected, including `grant_types: []`, which previously registered a client that could never complete any flow.
