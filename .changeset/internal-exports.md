---
'@cloudflare/workers-oauth-provider': patch
---

Six internal helpers are no longer exported from the package: `base64UrlToBytes`, `parseJwtJsonPart`, `getJwtCryptoAlgorithms`, `isValidOAuthScopeToken`, `resourceMatches` and `validateResourceUri`. They were exported by accident in 1.0 (the first three only so the enterprise-managed authorization modules could import them back from the package entry) and were never documented. A test now pins the package's runtime exports.
