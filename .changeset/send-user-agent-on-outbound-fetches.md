---
'@cloudflare/workers-oauth-provider': patch
---

The enterprise-managed authorization JWKS fetch and the Client ID Metadata Document fetch send `User-Agent: workers-oauth-provider/<version> (+https://github.com/cloudflare/workers-oauth-provider)`. Workers' `fetch` sends no `User-Agent`, and WAF rule sets such as AWS WAF's core rule set (`NoUserAgent_HEADER`) block requests without one, so an IdP behind CloudFront answered the JWKS fetch with `403` and every ID-JAG exchange from it failed with `jwks_fetch_failed`.
