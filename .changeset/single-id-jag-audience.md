---
'@cloudflare/workers-oauth-provider': patch
---

Require ID-JAG assertions to identify exactly one authorization server audience. Multi-element, duplicate, empty, malformed, and mismatched audience arrays are now rejected before authorization state is written.
