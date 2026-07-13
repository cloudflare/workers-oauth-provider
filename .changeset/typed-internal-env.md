---
'@cloudflare/workers-oauth-provider': patch
---

Replace internal `env: any` parameters with typed shapes. Internal provider methods now take `Env & ProviderEnv` (where `ProviderEnv` declares the required `OAUTH_KV: KVNamespace` binding), `ResolveExternalTokenInput` threads the `Env` generic through to the `resolveExternalToken` callback, and `OAuthHelpersImpl` is generic over `Env`. No runtime behavior change.
