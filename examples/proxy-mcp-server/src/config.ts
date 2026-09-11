import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';

/**
 * Scopes this authorization server advertises in its metadata and is willing to grant.
 *
 * The provider publishes this list but never enforces it: `completeAuthorization()` mints
 * a token carrying whatever scope array the application hands it, so the consent handler
 * filters against this same list.
 */
export const SCOPES_SUPPORTED = ['mcp:read', 'mcp:write'];

/** Scope the MCP resource requires for any request. */
export const MCP_READ_SCOPE = 'mcp:read';

/**
 * What the MCP handler sees as `ctx.props`.
 *
 * `ctx.props` is exactly what the application stored on the grant, so the granted scope
 * has to be copied in by hand: the provider validates a token's scope but does not show
 * it to the protected handler.
 */
export interface McpProps {
  userId: string;
  clientId: string;
  scopes: string[];
}

export interface Env {
  OAUTH_KV: KVNamespace;
  /** Injected by `OAuthProvider`: `parseAuthRequest`, `lookupClient`, `completeAuthorization`. */
  OAUTH_PROVIDER: OAuthHelpers<McpProps>;
}
