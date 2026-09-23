---
'@cloudflare/workers-oauth-provider': minor
---

Keep dynamically registered clients alive while they are in use.

A DCR registration expired `clientRegistrationTTL` after it was created, whatever the client was doing. A grant that outlived its registration, which any never-expiring or long-lived grant does, then failed every refresh with `invalid_client` although nothing had been revoked. Registrations written under the TTL now record when they expire, and a successful client-authenticated token endpoint request made in the second half of that lifetime rewrites the registration for the full TTL, at most once per half TTL per client.

Clients created through `createClient()`, CIMD clients, and registrations written before this version are never rewritten; the last expire on their original schedule and re-register once.
