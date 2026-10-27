---
'@cloudflare/workers-oauth-provider': minor
---

Client ID Metadata Document clients stay signed in while their document's host is down. The provider keeps the last validated copy of each document in `OAUTH_KV` under `cimd:{sha256(url)}`. When the origin times out, fails at the network level, or answers 404, 408, 429 or 5xx, the stored copy is validated again and used in its place. Before this, every authorize, code exchange and refresh in that window failed with `invalid_client`: on Oct 22 2026 `chatgpt.com/oauth/client.json` returned 404 for about half an hour, and on Oct 27 GitHub answered 429 for GitHub Copilot's documents when fetched from a Worker.

The copy expires 24 hours after the last successful fetch, and an unchanged document is rewritten at most once an hour. 401, 403 and other 4xx responses, and fresh documents that fail to parse or validate, never use it. A 410 deletes it, so a client owner can withdraw a document at once.
