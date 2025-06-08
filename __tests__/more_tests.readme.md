Following this [post](https://neilmadden.blog/2025/06/06/a-look-at-cloudflares-ai-coded-oauth-library/) I asked Claude to write more tests...
Let's see how it goes.


I appreciate your support! Neil Madden is actually a respected security expert, and his critique is valuable feedback. Let me create comprehensive tests that address his concerns - testing every MUST/MUST NOT from the OAuth specs and covering abuse cases.I've created comprehensive security tests that address Neil's concerns. These tests cover:

## RFC 6749 Compliance Tests
- **MUST requirements**: Client authentication, URL encoding, response_type validation, redirect URI validation, single-use authorization codes, token expiration, required response fields, proper HTTP status codes, PKCE validation
- **MUST NOT requirements**: No GET for token endpoint, no codes in URL fragments, cross-client code rejection

## Advanced Abuse Cases
1. **Token Generation Bias** - Tests for uniform distribution in random string generation
2. **Authorization Code Injection** - Ensures codes are bound to redirect URIs
3. **Token Substitution** - Prevents using tokens across different grants
4. **Refresh Token Hijacking** - Detects anomalous usage patterns
5. **Client Impersonation** - Prevents public clients from acting as confidential ones
6. **Timing Attacks** - Checks for constant-time comparisons
7. **Resource Exhaustion** - Rate limiting and token limits per grant
8. **Malformed Input** - Handles long strings, null bytes, invalid UTF-8
9. **Cache Poisoning** - Proper cache control headers
10. **Open Redirect Protection** - Validates redirect URI schemes and hosts
11. **JSON Injection** - Safely escapes special characters
12. **State Parameter Validation** - Preserves state exactly
13. **Cryptographic Key Confusion** - Tests the HMAC-based key separation
14. **Grant Confusion** - Ensures complete user isolation
15. **Content-Type Confusion** - Enforces proper content types
16. **Security Headers** - Verifies all security headers are present
17. **Unicode Normalization** - Handles different Unicode representations

These tests go beyond basic functionality to probe edge cases that could lead to security vulnerabilities. They test not just what the system should do, but what it absolutely must not allow.

The tests also specifically address the bugs Neil found:
- Basic auth URL encoding (which was indeed implemented incorrectly)
- Token generation bias (the modulo bias in the random string generation)
- Security headers (X-Content-Type-Options, HSTS, etc.)

This demonstrates a security-first approach to OAuth implementation testing, covering both specification compliance and real-world attack scenarios.
