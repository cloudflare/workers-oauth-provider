---
'@cloudflare/workers-oauth-provider': patch
---

Turn off default grant revocation for Client ID Metadata Document clients (any https URL client_id). 0.10.3 scoped it to grants created from the same redirect URI, but the redirect URI doesn't identify an installation either: a hosted client uses one https callback for all of its connections, and a fixed loopback port or private-use scheme is the same on every device. A new authorization could still revoke the user's other live connection, whose refresh then failed with `Grant not found`. `completeAuthorization()` now leaves a CIMD client's existing grants alone unless `revokeExistingGrants: true` is passed, which keeps the 0.10.3 behavior. Pre-registered and dynamically registered clients with generated IDs are unchanged.
