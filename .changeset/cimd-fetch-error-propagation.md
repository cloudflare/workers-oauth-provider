---
'@cloudflare/workers-oauth-provider': minor
---

Report CIMD metadata fetch failures instead of treating them as unknown clients.
A failed Client ID Metadata Document fetch previously became a `null` client
lookup, so a network problem (timeout, WAF block, upstream outage) was
indistinguishable from an unregistered client — at the token endpoint, in the
`onError` hook, and for `OAuthHelpers` callers. The fetch failure now throws a
new exported `CimdFetchError` carrying the metadata URL, stable
`metadata_resolution_failed` reason, and underlying diagnostic detail. The
token endpoint still returns the same generic `invalid_client` / "Client not
found" response, but reports the failure through the `onError` hook's
`internal` field (category `client-id-metadata-document`) together with a new
optional `request` field. Breaking for callers of `OAuthHelpers.lookupClient`
(and methods built on it) that relied on `null` for CIMD fetch failures: catch
`CimdFetchError` to restore the old behavior.
