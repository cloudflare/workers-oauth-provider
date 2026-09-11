import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import { authorizeHandler } from './authorize';
import { SCOPES_SUPPORTED, type Env } from './config';
import { McpApiHandler } from './mcp';

/**
 * Canonical protected-resource identifier, and the audience of every access token this
 * Worker issues and accepts.
 *
 * It must be an absolute HTTPS URL, it is validated in the `OAuthProvider` constructor,
 * and an `OAuthProvider` is constructed once at module scope, before any request exists.
 * The value therefore has to be known at build time, so wrangler's `define` map inlines
 * it per environment. See "Run locally" in the README.
 */
declare const MCP_RESOURCE: string;

/**
 * One Worker, both roles. Every request to `/mcp` is proxied through the provider, which
 * resolves the bearer token, rejects a missing, expired, revoked, or wrong-audience one,
 * and only then calls `McpApiHandler` with `ctx.props`. Everything else falls through to
 * `defaultHandler`, which owns the interactive `/authorize` page.
 */
export default new OAuthProvider<Env>({
  apiRoute: '/mcp',
  apiHandler: McpApiHandler,
  defaultHandler: authorizeHandler,

  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',

  // MCP 2026 prefers Client ID Metadata Documents. Dynamic client registration stays on
  // as the compatibility path that existing MCP clients and the conformance CLI use.
  clientRegistrationEndpoint: '/oauth/register',
  clientIdMetadataDocumentEnabled: true,

  scopesSupported: SCOPES_SUPPORTED,

  resourceMetadata: {
    resource: MCP_RESOURCE,
    // `authorization_servers` is omitted on purpose: the authorization server is this
    // same Worker, and the provider defaults the list to its own issuer.
    scopes_supported: SCOPES_SUPPORTED,
    resource_name: 'Proxy MCP server',
  },
});
