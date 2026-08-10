---
'@cloudflare/workers-oauth-provider': patch
---

Add an opt-in `issParameterCompat` option that omits the RFC 9207 `authorization_response_iss_parameter_supported` advertisement from authorization server metadata for clients that mishandle it (e.g. Codex CLI 0.143 and later, which drops the `iss` callback parameter before validating it — see openai/codex#31573). The `iss` authorization-response parameter is still always sent, so conforming clients keep authorization-server mix-up protection. Defaults to false.
