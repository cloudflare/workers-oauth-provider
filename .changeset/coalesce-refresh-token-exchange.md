---
'@cloudflare/workers-oauth-provider': patch
---

Add `coalesceRefreshTokenExchange` option to harden providers whose
`tokenExchangeCallback` performs a **non-idempotent** upstream operation during
the `refresh_token` grant — most commonly redeeming a _single-use, rotating_
upstream refresh token (i.e. the Worker is itself a client of another OAuth
server, like the Cloudflare MCP server).

Without this option, two concurrent refreshes that share the same downstream
refresh token both decrypt the same upstream credentials and both invoke
`tokenExchangeCallback`, racing to redeem the same single-use upstream token.
One wins; the other gets `invalid_grant` from upstream. The losing client then
retries with its (now _previous_) refresh token, which re-runs the callback
against the freshly-rotated upstream token, redeeming it again and cascading
further rotations — a self-sustaining stream of `invalid_grant` errors.

When `coalesceRefreshTokenExchange: true`:

- **Single-flight:** concurrent `refresh_token` requests presenting the same
  refresh token within a single isolate are coalesced — the callback runs once
  and every caller receives a clone of the same token response.
- **Idempotent replay:** a refresh presented with the grant's _previous_ refresh
  token is treated as a retry of the rotation that already happened. The
  callback is skipped and a fresh access token is minted from the grant's
  current props, without rotating the refresh token or re-touching upstream.

Defaults to `false` (the callback runs on every refresh, including retries), so
existing behaviour is unchanged unless you opt in.

Note: KV is eventually-consistent with no compare-and-swap, so simultaneous
refreshes landing on _different_ isolates before either has persisted cannot be
fully serialized; this collapses the common same-isolate burst and makes client
retries safe and upstream-free.
