---
'@cloudflare/workers-oauth-provider': patch
---

Scope default grant revocation to the authorizing redirect URI for Client ID Metadata Document clients. A CIMD client_id is the metadata document URL shared by every installation of the client, so `completeAuthorization()`'s default revocation logged the user out of all their other devices; it now revokes only grants created from the same redirect URI. Grants now record the redirect URI that created them, and grants created before this release are never auto-revoked by CIMD clients. Revocation for pre-registered and dynamically registered clients is unchanged.
