---
'@cloudflare/workers-oauth-provider': patch
---

Fix TypeScript types by making OAuthProviderOptions generic over Env, eliminating the need for @ts-expect-error workarounds when using typed environments
