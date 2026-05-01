---
'@cloudflare/workers-oauth-provider': minor
---

Add `clientRegistrationCallback` for validating or rejecting dynamic client registrations before storage. Follows the same pattern as `tokenExchangeCallback`. Closes #162.

- Default rejection error follows RFC 7591 §3.2.2 (`invalid_client_metadata` / 400). Callbacks rejecting for non-metadata reasons (missing IAT, untrusted origin) should override `rejectCode` and `rejectStatus` explicitly.
- The `request` passed to the callback is cloned before the library reads the body, so callbacks may consume the body (e.g. to verify a signature over the raw bytes).
- Callback exceptions are caught and surfaced as `500 server_error`.
- `software_statement` (RFC 7591 §3.1.1) JWTs are not processed by the library; callbacks wishing to honor them must verify the JWT and apply its claims themselves.
