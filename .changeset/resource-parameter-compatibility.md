---
'@cloudflare/workers-oauth-provider': patch
---

Restore v0.8.2-compatible resource handling for grants without a stored RFC 8707 resource. Configured canonical resources are defaulted and inherited, bound grants reject explicit mismatches, and an unconfigured legacy grant can issue an unbound token or use an explicit token-request resource without persisting a new grant binding.

Deprecate `resourceMatchOriginOnly` without changing its behavior.
