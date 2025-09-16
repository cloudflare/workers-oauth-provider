---
'@cloudflare/workers-oauth-provider': patch
---

explicitly block javascript: (and other suspicious protocols) in redirect uris

In https://github.com/cloudflare/workers-oauth-provider/pull/80, we blocked redirects that didn't start with http:// or https:// to prevent xss attacks with javascript: URIs. However this blocked redirects to custom apps like cursor:// et al. This patch now explicitly blocks javascript: (and other suspicious protocols) in redirect uris.
