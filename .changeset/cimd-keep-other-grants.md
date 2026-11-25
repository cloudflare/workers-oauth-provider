---
'@cloudflare/workers-oauth-provider': minor
---

A new authorization from a Client ID Metadata Document client no longer revokes the user's other grants from that client. `revokeExistingGrants` now defaults to `false` when the `client_id` is an https URL with a path, and stays `true` for every other client.

A CIMD `client_id` is shared by every installation and connection of the client, so an earlier grant can belong to another device or agent that is still in use. 0.10.3 limited the default revocation to grants from the same redirect URI, but a hosted client uses one https callback for all of its connections and a fixed loopback port is the same on every device. Signing in a second agent still revoked the first, whose next refresh failed with `Grant not found`.

`revokeExistingGrants: true` now means the same for every client: revoke the user's other grants for this client and resource. For a CIMD client that used to revoke only grants from the same redirect URI. To keep one grant per user for a CIMD client, pass `true`. To choose which grants to end, use `listUserGrants()` and `revokeGrant()`.

Grant keys no longer mirror `redirectUri` into KV metadata. The grant record still stores it, and `listUserGrants()` still returns it.
