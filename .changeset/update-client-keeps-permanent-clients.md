---
'@cloudflare/workers-oauth-provider': patch
---

`updateClient()` no longer applies `clientRegistrationTTL` to clients created through `createClient()`.

It re-applied the TTL to every client it wrote, so updating a pre-registered client silently gave it an expiry. The TTL is now preserved only for records stamped with `registrationExpiresAt`; other records are written permanently. Dynamic registrations written before that stamp existed therefore become permanent when updated.
