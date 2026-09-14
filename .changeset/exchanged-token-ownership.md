---
'@cloudflare/workers-oauth-provider': major
---

An exchanged access token is owned by the authenticated exchanging client.

- A token issued by `urn:ietf:params:oauth:grant-type:token-exchange` records the exchanging client rather than the subject grant's client, so its RFC 9068 `client_id` claim names the client that requested it (RFC 8693 §2.1). Revocation follows ownership (RFC 7009 §2.1): the subject grant's client can no longer revoke the exchanged token, and the exchanging client can. This applies to opaque tokens as well as JWTs. Exchanged tokens issued before the upgrade keep the source grant's client as their revocation owner until they expire.
- `deleteClient()` sweeps tokens owned by the deleted client under another client's source grant, regardless of the current `allowTokenExchangeGrant` setting. It removes the client record before sweeping, so an interrupted sweep cannot leave a usable client behind, at the cost of a second full scan of `token:` keys.
