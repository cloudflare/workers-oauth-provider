---
'@cloudflare/workers-oauth-provider': patch
---

fix: reject a concurrent second exchange of one authorization code

Two token requests using the same authorization code could both read the grant
before either consumed it, and both issue token sets, violating the single use
RFC 6749 Section 4.1.2 requires (#420). The consumption write now carries a
per-exchange marker, and the grant is re-read after the write: an exchange whose
marker did not survive is answered `invalid_grant` and revokes the grant's
tokens, the policy a sequential replay already gets (RFC 6749 Section 10.5).
This closes the same-location interleave; a fully atomic claim still needs a
transactional storage backend.
