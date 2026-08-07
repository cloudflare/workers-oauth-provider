---
'@cloudflare/workers-oauth-provider': patch
---

Negotiate the CIMD token endpoint authentication method instead of rejecting on the declared value

A Client ID Metadata Document that declares `token_endpoint_auth_method: "private_key_jwt"` while advertising `token_endpoint_auth_methods_supported: ["none", "private_key_jwt"]` was rejected outright, because the declared value was treated as a requirement and the advertised list was never consulted. That is the document ChatGPT publishes, so its MCP connector could not authorize against any server using this library.

The declared method is now a preference: it is kept when this server implements it, and otherwise the first mutually supported entry from `token_endpoint_auth_methods_supported` is selected. A document is refused only when it asked for something and offered nothing this server accepts, and the error now names what the client advertised. Documents that omit both fields, or that offer no acceptable method, behave exactly as before.
