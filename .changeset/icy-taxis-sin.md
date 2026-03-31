---
'@cloudflare/workers-oauth-provider': minor
---

Fixes to correctly serve metadata at /.well-known/oauth-protected-resource with subpath suffixing and return the correct resource identifier per RFC 9728 §3.1 and §3.3. The old method of auth probing will still find the old resource metadata.
Upgraded to minor from patch since clients often cache resource parameters and changes to this are breaking for auth handshake as per the RFC.
