---
'@cloudflare/workers-oauth-provider': patch
---

Verify client ownership on token revocation (RFC 7009 §2.1) and honor `token_type_hint` for lookup ordering. Previously any client could revoke any other client's tokens.
