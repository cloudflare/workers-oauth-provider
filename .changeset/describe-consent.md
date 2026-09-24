---
'@cloudflare/workers-oauth-provider': minor
---

`OAuthHelpers.describeConsent(request)` returns what a consent page must show, per the MCP authorization spec: the client's name (or ID), its verified domain for a Client ID Metadata Document client, the redirect URI's hostname, whether the redirect goes to a local app (show a warning), and the scopes. Every string may come from the client, so escape it before rendering.
