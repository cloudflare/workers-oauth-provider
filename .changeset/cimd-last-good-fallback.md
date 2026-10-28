---
'@cloudflare/workers-oauth-provider': minor
---

Add `clientIdMetadataDocumentFallback`, an optional hook that keeps CIMD clients working while their metadata document's host is down. The library saves the raw bytes of each document it validates through the hook. When the origin returns 404 or 5xx, times out, or fails at the network level, it resolves the client from the stored copy after validating it again. 403, other 4xx responses, and fresh documents that fail validation never use the stored copy. Storage, eligibility, and maximum age are up to the implementation. Without the option, behavior is unchanged.

Errors from the stale-copy observer do not interrupt a valid fallback.
