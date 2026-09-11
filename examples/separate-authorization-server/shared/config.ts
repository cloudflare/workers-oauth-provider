/**
 * Configuration shared by the two Workers in this example. Each Worker is otherwise
 * standalone: nothing here crosses the Service Binding at runtime.
 */

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
 * Application data stored on the grant by the authorization server. It is encrypted at
 * rest, belongs to the grant rather than to one token, and is handed back to whoever
 * validates a token for that grant.
 */
export interface GrantProps {
  userId: string;
  clientId: string;
}

/**
 * What the MCP handler sees as `ctx.props`. The resource server's validator adds the
 * *effective token* scope, which a client can narrow below the grant scope at the token
 * endpoint, so scope decisions must never be read from the grant props.
 */
export interface McpProps extends GrantProps {
  scopes: string[];
}
