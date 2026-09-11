import { OAuthAuthorizationServer } from '@cloudflare/workers-oauth-provider';
import { WorkerEntrypoint } from 'cloudflare:workers';
import { SCOPES_SUPPORTED, type GrantProps } from '../../shared/config';
import { handleAuthorize } from './authorize';

/**
 * Canonical issuer of this authorization server, and the two audiences it issues tokens
 * for. `MCP_RESOURCE` is the other Worker in this example; `REPORTS_RESOURCE` is an
 * audience nothing here hosts, and it exists so the pinned validator below has something
 * it must refuse.
 *
 * All three must be absolute HTTPS URLs, they are validated in the constructor, and the
 * server is constructed once at module scope, before any request exists. The values
 * therefore have to be known at build time, so wrangler's `define` map inlines them per
 * environment. See "Run locally" in the README.
 */
declare const AUTH_ISSUER: string;
declare const MCP_RESOURCE: string;
declare const REPORTS_RESOURCE: string;
declare const ALLOW_HTTP: boolean;

export interface Env {
  OAUTH_KV: KVNamespace;
}

/**
 * The library owns metadata, token, revocation, and registration. The application owns
 * `/authorize`, because only the application knows who the user is.
 *
 * `resources` declares every audience this server issues tokens for, whether hosted here or
 * by another Worker. The registry is fixed at construction, so `defaultResource` and the
 * `resource()` handle below are checked before the first request.
 */
const authorizationServer = new OAuthAuthorizationServer<Env, GrantProps>({
  issuer: AUTH_ISSUER,
  resources: [MCP_RESOURCE, REPORTS_RESOURCE],
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',

  // MCP 2026 prefers Client ID Metadata Documents. Dynamic client registration stays on
  // as the compatibility path that existing MCP clients use.
  clientRegistrationEndpoint: '/oauth/register',
  clientIdMetadataDocumentEnabled: true,

  // Local development runs on http://localhost. OAuth 2.1 requires https everywhere else,
  // so the production environment inlines `false`. See "Run locally" in the README.
  allowHttp: ALLOW_HTTP,

  scopesSupported: SCOPES_SUPPORTED,

  // With more than one registered resource an authorization request must name exactly
  // one of them, which clients that predate RFC 8707 resource indicators do not do.
  defaultResource: MCP_RESOURCE,
});

// A handle pinned to one declared resource. A misspelled identifier throws here, at module
// initialization, instead of surfacing as a 503 across the Service Binding.
const mcp = authorizationServer.resource(MCP_RESOURCE);

/**
 * The MCP Worker's only view of this authorization server, reachable over a private
 * Service Binding and nothing else. It is pinned to one audience, so a compromised or
 * buggy MCP Worker cannot validate a token issued for `REPORTS_RESOURCE`. Bind it with
 * `entrypoint: "McpTokenValidator"`.
 */
export class McpTokenValidator extends WorkerEntrypoint<Env> {
  validateToken(token: string) {
    return mcp.validateToken(token, this.env);
  }
}

export default {
  fetch(request, env, ctx) {
    if (new URL(request.url).pathname === '/authorize') {
      // `getOAuthApi()` is how an application reaches `parseAuthRequest()` and
      // `completeAuthorization()` in this configuration. The combined `OAuthProvider`
      // injects the same API into `env` instead.
      return handleAuthorize(request, authorizationServer.getOAuthApi(env));
    }
    return authorizationServer.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
