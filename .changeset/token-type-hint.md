---
'@cloudflare/workers-oauth-provider': patch
---

Honor `token_type_hint` in revocation to check the hinted type first (RFC 7009 §2.1). Incorrect hints fall through gracefully.
