---
'@cloudflare/workers-oauth-provider': patch
---

Stop default grant revocation for Client ID Metadata Document clients. 0.10.3 scoped it to grants created from the same redirect URI, but the redirect URI doesn't identify an installation either: a hosted client uses one https callback for all of its connections, and a fixed loopback port or private-use scheme is the same on every device. A new authorization could still revoke the user's other live connection, whose refresh then failed with `Grant not found`. `completeAuthorization()` now leaves a CIMD client's existing grants alone; they end when they expire or when the client revokes them. Revocation for pre-registered and dynamically registered clients is unchanged.
