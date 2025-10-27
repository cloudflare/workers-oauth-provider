---
'@cloudflare/workers-oauth-provider': patch
---

Enhance redirect URI scheme validation for security

Added a robust helper to validate redirect URI schemes, preventing dangerous pseudo-schemes (e.g., javascript:, data:, vbscript:) with normalization and case-insensitive checks. Expanded test coverage to include bypass attempts using mixed case, whitespace, control characters, and edge cases to ensure comprehensive protection against XSS and related attacks.