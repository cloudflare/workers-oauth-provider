import { ExportedHandler, ExecutionContext } from '@cloudflare/workers-types';
import { WorkerEntrypoint } from 'cloudflare:workers';

// Types

/**
 * Enum representing the type of handler (ExportedHandler or WorkerEntrypoint)
 */
enum HandlerType {
  EXPORTED_HANDLER,
  WORKER_ENTRYPOINT,
}

/**
 * Discriminated union type for handlers
 */
type TypedHandler =
  | {
      type: HandlerType.EXPORTED_HANDLER;
      handler: ExportedHandlerWithFetch;
    }
  | {
      type: HandlerType.WORKER_ENTRYPOINT;
      handler: new (ctx: ExecutionContext, env: any) => WorkerEntrypointWithFetch;
    };

/**
 * Aliases for either type of Handler that makes .fetch required
 */
type ExportedHandlerWithFetch = ExportedHandler & Pick<Required<ExportedHandler>, 'fetch'>;
type WorkerEntrypointWithFetch = WorkerEntrypoint & Pick<Required<WorkerEntrypoint>, 'fetch'>;

/**
 * Configuration options for the OAuth Provider
 */
/**
 * Result of a token exchange callback function.
 * Allows updating the props stored in both the access token and the grant.
 */
export interface TokenExchangeCallbackResult {
  /**
   * New props to be stored specifically with the access token.
   * If not provided but newProps is, the access token will use newProps.
   * If neither is provided, the original props will be used.
   */
  accessTokenProps?: any;

  /**
   * New props to replace the props stored in the grant itself.
   * These props will be used for all future token refreshes.
   * If accessTokenProps is not provided, these props will also be used for the current access token.
   * If not provided, the original props will be used.
   */
  newProps?: any;

  /**
   * Override the default access token TTL (time-to-live) for this specific token.
   * This is especially useful when the application is also an OAuth client to another service
   * and wants to match its access token TTL to the upstream access token TTL.
   * Value should be in seconds.
   */
  accessTokenTTL?: number;
}

/**
 * Options for token exchange callback functions
 */
export interface TokenExchangeCallbackOptions {
  /**
   * The type of grant being processed.
   * 'authorization_code' for initial code exchange,
   * 'refresh_token' for refresh token exchange.
   */
  grantType: 'authorization_code' | 'refresh_token';

  /**
   * Client that received this grant
   */
  clientId: string;

  /**
   * User who authorized this grant
   */
  userId: string;

  /**
   * List of scopes that were granted
   */
  scope: string[];

  /**
   * Application-specific properties currently associated with this grant
   */
  props: any;
}

export interface OAuthProviderOptions {
  /**
   * URL(s) for API routes. Requests with URLs starting with any of these prefixes
   * will be treated as API requests and require a valid access token.
   * Can be a single route or an array of routes. Each route can be a full URL or just a path.
   * 
   * Used with `apiHandler` for the single-handler configuration. This is incompatible with
   * the `apiHandlers` property. You must use either `apiRoute` + `apiHandler` OR `apiHandlers`, not both.
   */
  apiRoute?: string | string[];

  /**
   * Handler for API requests that have a valid access token.
   * This handler will receive the authenticated user properties in ctx.props.
   * Can be either an ExportedHandler object with a fetch method or a class extending WorkerEntrypoint.
   * 
   * Used with `apiRoute` for the single-handler configuration. This is incompatible with
   * the `apiHandlers` property. You must use either `apiRoute` + `apiHandler` OR `apiHandlers`, not both.
   */
  apiHandler?: ExportedHandlerWithFetch | (new (ctx: ExecutionContext, env: any) => WorkerEntrypointWithFetch);

  /**
   * Map of API routes to their corresponding handlers for the multi-handler configuration.
   * The keys are the API routes (strings only, not arrays), and the values are the handlers.
   * Each route can be a full URL or just a path, and each handler can be either an ExportedHandler
   * object with a fetch method or a class extending WorkerEntrypoint.
   * 
   * This is incompatible with the `apiRoute` and `apiHandler` properties. You must use either
   * `apiRoute` + `apiHandler` (single-handler configuration) OR `apiHandlers` (multi-handler 
   * configuration), not both.
   */
  apiHandlers?: Record<string, ExportedHandlerWithFetch | (new (ctx: ExecutionContext, env: any) => WorkerEntrypointWithFetch)>;

  /**
   * Handler for all non-API requests or API requests without a valid token.
   * Can be either an ExportedHandler object with a fetch method or a class extending WorkerEntrypoint.
   */
  defaultHandler: ExportedHandler | (new (ctx: ExecutionContext, env: any) => WorkerEntrypointWithFetch);

  /**
   * URL of the OAuth authorization endpoint where users can grant permissions.
   * This URL is used in OAuth metadata and is not handled by the provider itself.
   */
  authorizeEndpoint: string;

  /**
   * URL of the token endpoint which the provider will implement.
   * This endpoint handles token issuance, refresh, and revocation.
   */
  tokenEndpoint: string;

  /**
   * Optional URL for the client registration endpoint.
   * If provided, the provider will implement dynamic client registration.
   */
  clientRegistrationEndpoint?: string;

  /**
   * Time-to-live for access tokens in seconds.
   * Defaults to 1 hour (3600 seconds) if not specified.
   */
  accessTokenTTL?: number;

  /**
   * List of scopes supported by this OAuth provider.
   * If not provided, the 'scopes_supported' field will be omitted from the OAuth metadata.
   */
  scopesSupported?: string[];

  /**
   * Controls whether the OAuth implicit flow is allowed.
   * This flow is discouraged in OAuth 2.1 due to security concerns.
   * Defaults to false.
   */
  allowImplicitFlow?: boolean;

  /**
   * Controls whether public clients (clients without a secret, like SPAs) can register via the
   * dynamic client registration endpoint. When true, only confidential clients can register.
   * Note: Creating public clients via the OAuthHelpers.createClient() method is always allowed.
   * Defaults to false.
   */
  disallowPublicClientRegistration?: boolean;

  /**
   * Optional callback function that is called during token exchange.
   * This allows updating the props stored in both the access token and the grant.
   * For example, if the application itself is also a client to some other OAuth API,
   * it may want to perform the equivalent upstream token exchange, and store the result in the props.
   *
   * The callback can return new props values that will be stored with the token or grant.
   * If the callback returns nothing or undefined for a props field, the original props will be used.
   */
  tokenExchangeCallback?: (
    options: TokenExchangeCallbackOptions
  ) => Promise<TokenExchangeCallbackResult | void> | TokenExchangeCallbackResult | void;

  /**
   * Optional callback function that is called whenever the OAuthProvider returns an error response
   * This allows the client to emit notifications or perform other actions when an error occurs.
   *
   * If the function returns a Response, that will be used in place of the OAuthProvider's default one.
   */
  onError?: (error: {
    code: string;
    description: string;
    status: number;
    headers: Record<string, string>;
  }) => Response | void;
}

// Using ExportedHandler from Cloudflare Workers Types for both API and default handlers
// This is Cloudflare's built-in type for Workers handlers with a fetch method
// For ApiHandler, ctx will include ctx.props with user properties

/**
 * Helper methods for OAuth operations provided to handler functions
 */
export interface OAuthHelpers {
  /**
   * Parses an OAuth authorization request from the HTTP request
   * @param request - The HTTP request containing OAuth parameters
   * @returns The parsed authorization request parameters
   */
  parseAuthRequest(request: Request): Promise<AuthRequest>;

  /**
   * Looks up a client by its client ID
   * @param clientId - The client ID to look up
   * @returns A Promise resolving to the client info, or null if not found
   */
  lookupClient(clientId: string): Promise<ClientInfo | null>;

  /**
   * Completes an authorization request by creating a grant and authorization code
   * @param options - Options specifying the grant details
   * @returns A Promise resolving to an object containing the redirect URL
   */
  completeAuthorization(options: CompleteAuthorizationOptions): Promise<{ redirectTo: string }>;

  /**
   * Creates a new OAuth client
   * @param clientInfo - Partial client information to create the client with
   * @returns A Promise resolving to the created client info
   */
  createClient(clientInfo: Partial<ClientInfo>): Promise<ClientInfo>;

  /**
   * Lists all registered OAuth clients with pagination support
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with items and optional cursor
   */
  listClients(options?: ListOptions): Promise<ListResult<ClientInfo>>;

  /**
   * Updates an existing OAuth client
   * @param clientId - The ID of the client to update
   * @param updates - Partial client information with fields to update
   * @returns A Promise resolving to the updated client info, or null if not found
   */
  updateClient(clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null>;

  /**
   * Deletes an OAuth client
   * @param clientId - The ID of the client to delete
   * @returns A Promise resolving when the deletion is confirmed.
   */
  deleteClient(clientId: string): Promise<void>;

  /**
   * Lists all authorization grants for a specific user with pagination support
   * Returns a summary of each grant without sensitive information
   * @param userId - The ID of the user whose grants to list
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with grant summaries and optional cursor
   */
  listUserGrants(userId: string, options?: ListOptions): Promise<ListResult<GrantSummary>>;

  /**
   * Revokes an authorization grant
   * @param grantId - The ID of the grant to revoke
   * @param userId - The ID of the user who owns the grant
   * @returns A Promise resolving when the revocation is confirmed.
   */
  revokeGrant(grantId: string, userId: string): Promise<void>;
}

/**
 * Parsed OAuth authorization request parameters
 */
export interface AuthRequest {
  /**
   * OAuth response type (e.g., "code" for authorization code flow)
   */
  responseType: string;

  /**
   * Client identifier for the OAuth client
   */
  clientId: string;

  /**
   * URL to redirect to after authorization
   */
  redirectUri: string;

  /**
   * Array of requested permission scopes
   */
  scope: string[];

  /**
   * Client state value to be returned in the redirect
   */
  state: string;

  /**
   * PKCE code challenge (RFC 7636)
   */
  codeChallenge?: string;

  /**
   * PKCE code challenge method (plain or S256)
   */
  codeChallengeMethod?: string;
}

/**
 * OAuth client registration information
 */
export interface ClientInfo {
  /**
   * Unique identifier for the client
   */
  clientId: string;

  /**
   * Secret used to authenticate the client (stored as a hash)
   * Only present for confidential clients; undefined for public clients.
   */
  clientSecret?: string;

  /**
   * List of allowed redirect URIs for the client
   */
  redirectUris: string[];

  /**
   * Human-readable name of the client application
   */
  clientName?: string;

  /**
   * URL to the client's logo
   */
  logoUri?: string;

  /**
   * URL to the client's homepage
   */
  clientUri?: string;

  /**
   * URL to the client's privacy policy
   */
  policyUri?: string;

  /**
   * URL to the client's terms of service
   */
  tosUri?: string;

  /**
   * URL to the client's JSON Web Key Set for validating signatures
   */
  jwksUri?: string;

  /**
   * List of email addresses for contacting the client developers
   */
  contacts?: string[];

  /**
   * List of grant types the client supports
   */
  grantTypes?: string[];

  /**
   * List of response types the client supports
   */
  responseTypes?: string[];

  /**
   * Unix timestamp when the client was registered
   */
  registrationDate?: number;

  /**
   * The authentication method used by the client at the token endpoint.
   * Values include:
   * - 'client_secret_basic': Uses HTTP Basic Auth with client ID and secret (default for confidential clients)
   * - 'client_secret_post': Uses POST parameters for client authentication
   * - 'none': Used for public clients that can't securely store secrets (SPAs, mobile apps, etc.)
   *
   * Public clients use 'none', while confidential clients use either 'client_secret_basic' or 'client_secret_post'.
   */
  tokenEndpointAuthMethod: string;
}

/**
 * Options for completing an authorization request
 */
export interface CompleteAuthorizationOptions {
  /**
   * The original parsed authorization request
   */
  request: AuthRequest;

  /**
   * Identifier for the user granting the authorization
   */
  userId: string;

  /**
   * Application-specific metadata to associate with this grant
   */
  metadata: any;

  /**
   * List of scopes that were actually granted (may differ from requested scopes)
   */
  scope: string[];

  /**
   * Application-specific properties to include with API requests
   * authorized by this grant
   */
  props: any;
}

/**
 * Authorization grant record
 */
export interface Grant {
  /**
   * Unique identifier for the grant
   */
  id: string;

  /**
   * Client that received this grant
   */
  clientId: string;

  /**
   * User who authorized this grant
   */
  userId: string;

  /**
   * List of scopes that were granted
   */
  scope: string[];

  /**
   * Application-specific metadata associated with this grant
   */
  metadata: any;

  /**
   * Encrypted application-specific properties
   */
  encryptedProps: string;

  /**
   * Unix timestamp when the grant was created
   */
  createdAt: number;

  /**
   * The hash of the current refresh token associated with this grant
   */
  refreshTokenId?: string;

  /**
   * Wrapped encryption key for the current refresh token
   */
  refreshTokenWrappedKey?: string;

  /**
   * The hash of the previous refresh token associated with this grant
   * This token is still valid until the new token is first used
   */
  previousRefreshTokenId?: string;

  /**
   * Wrapped encryption key for the previous refresh token
   */
  previousRefreshTokenWrappedKey?: string;

  /**
   * The hash of the authorization code associated with this grant
   * Only present during the authorization code exchange process
   */
  authCodeId?: string;

  /**
   * Wrapped encryption key for the authorization code
   * Only present during the authorization code exchange process
   */
  authCodeWrappedKey?: string;

  /**
   * PKCE code challenge for this authorization
   * Only present during the authorization code exchange process
   */
  codeChallenge?: string;

  /**
   * PKCE code challenge method (plain or S256)
   * Only present during the authorization code exchange process
   */
  codeChallengeMethod?: string;
}

/**
 * Token record stored in KV
 * Note: The actual token format is "{userId}:{grantId}:{random-secret}"
 * but we still only store the hash of the full token string.
 * This contains only access tokens; refresh tokens are stored within the grant records.
 */
export interface Token {
  /**
   * Unique identifier for the token (hash of the actual token)
   */
  id: string;

  /**
   * Identifier of the grant this token is associated with
   */
  grantId: string;

  /**
   * User ID associated with this token
   */
  userId: string;

  /**
   * Unix timestamp when the token was created
   */
  createdAt: number;

  /**
   * Unix timestamp when the token expires
   */
  expiresAt: number;

  /**
   * The encryption key for props, wrapped with this token
   */
  wrappedEncryptionKey: string;

  /**
   * Denormalized grant information for faster access
   */
  grant: {
    /**
     * Client that received this grant
     */
    clientId: string;

    /**
     * List of scopes that were granted
     */
    scope: string[];

    /**
     * Encrypted application-specific properties
     */
    encryptedProps: string;
  };
}

/**
 * Options for listing operations that support pagination
 */
export interface ListOptions {
  /**
   * Maximum number of items to return (max 1000)
   */
  limit?: number;

  /**
   * Cursor for pagination (from a previous listing operation)
   */
  cursor?: string;
}

/**
 * Result of a listing operation with pagination support
 */
export interface ListResult<T> {
  /**
   * The list of items
   */
  items: T[];

  /**
   * Cursor to get the next page of results, if there are more results
   */
  cursor?: string;
}

/**
 * Public representation of a grant, with sensitive data removed
 * Used for list operations where the complete grant data isn't needed
 */
export interface GrantSummary {
  /**
   * Unique identifier for the grant
   */
  id: string;

  /**
   * Client that received this grant
   */
  clientId: string;

  /**
   * User who authorized this grant
   */
  userId: string;

  /**
   * List of scopes that were granted
   */
  scope: string[];

  /**
   * Application-specific metadata associated with this grant
   */
  metadata: any;

  /**
   * Unix timestamp when the grant was created
   */
  createdAt: number;
}

/**
 * OAuth 2.0 Provider implementation for Cloudflare Workers
 * Implements authorization code flow with support for refresh tokens
 * and dynamic client registration.
 */
export class OAuthProvider {
  #impl: OAuthProviderImpl;

  /**
   * Creates a new OAuth provider instance
   * @param options - Configuration options for the provider
   */
  constructor(options: OAuthProviderOptions) {
    this.#impl = new OAuthProviderImpl(options);
  }

  /**
   * Main fetch handler for the Worker
   * Routes requests to the appropriate handler based on the URL
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @param ctx - Cloudflare Worker execution context
   * @returns A Promise resolving to an HTTP Response
   */
  fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    return this.#impl.fetch(request, env, ctx);
  }
}

/**
 * Implementation class backing OAuthProvider.
 *
 * We use a PImpl pattern in `OAuthProvider` to make sure we don't inadvertently export any private
 * methods over RPC. Unfortunately, declaring a method "private" in TypeScript is merely a type
 * annotation, and does not actually prevent the method from being called from outside the class,
 * including over RPC.
 */
class OAuthProviderImpl {
  /**
   * Configuration options for the provider
   */
  options: OAuthProviderOptions;

  /**
   * Represents the validated type of a handler (ExportedHandler or WorkerEntrypoint)
   */
  private typedDefaultHandler: TypedHandler;
  
  /**
   * Array of tuples of API routes and their validated handlers
   * In the simple case, this will be a single entry with the route and handler from options.apiRoute/apiHandler
   * In the advanced case, this will contain entries from options.apiHandlers
   */
  private typedApiHandlers: Array<[string, TypedHandler]>;

  /**
   * Creates a new OAuth provider instance
   * @param options - Configuration options for the provider
   */
  constructor(options: OAuthProviderOptions) {
    // Initialize typedApiHandlers as an array
    this.typedApiHandlers = [];
    
    // Check if we have incompatible configuration
    const hasSingleHandlerConfig = !!(options.apiRoute && options.apiHandler);
    const hasMultiHandlerConfig = !!options.apiHandlers;
    
    if (hasSingleHandlerConfig && hasMultiHandlerConfig) {
      throw new TypeError(
        'Cannot use both apiRoute/apiHandler and apiHandlers. ' +
        'Use either apiRoute + apiHandler OR apiHandlers, not both.'
      );
    }
    
    if (!hasSingleHandlerConfig && !hasMultiHandlerConfig) {
      throw new TypeError(
        'Must provide either apiRoute + apiHandler OR apiHandlers. ' +
        'No API route configuration provided.'
      );
    }
    
    // Validate default handler
    this.typedDefaultHandler = this.validateHandler(options.defaultHandler, 'defaultHandler');

    // Process and validate the API handlers
    if (hasSingleHandlerConfig) {
      // Single handler mode with apiRoute + apiHandler
      const apiHandler = this.validateHandler(options.apiHandler!, 'apiHandler');
      
      // For single handler mode, process the apiRoute(s) and map them all to the single apiHandler
      if (Array.isArray(options.apiRoute)) {
        options.apiRoute.forEach((route, index) => {
          this.validateEndpoint(route, `apiRoute[${index}]`);
          this.typedApiHandlers.push([route, apiHandler]);
        });
      } else {
        this.validateEndpoint(options.apiRoute!, 'apiRoute');
        this.typedApiHandlers.push([options.apiRoute!, apiHandler]);
      }
    } else {
      // Multiple handlers mode with apiHandlers map
      for (const [route, handler] of Object.entries(options.apiHandlers!)) {
        this.validateEndpoint(route, `apiHandlers key: ${route}`);
        this.typedApiHandlers.push([route, this.validateHandler(handler, `apiHandlers[${route}]`)]);
      }
    }

    // Validate that the oauth endpoints are either absolute paths or full URLs
    this.validateEndpoint(options.authorizeEndpoint, 'authorizeEndpoint');
    this.validateEndpoint(options.tokenEndpoint, 'tokenEndpoint');
    if (options.clientRegistrationEndpoint) {
      this.validateEndpoint(options.clientRegistrationEndpoint, 'clientRegistrationEndpoint');
    }

    this.options = {
      accessTokenTTL: DEFAULT_ACCESS_TOKEN_TTL,
      onError: ({ status, code, description }) =>
        console.warn(`OAuth error response: ${status} ${code} - ${description}`),
      ...options,
    };
  }

  /**
   * Validates that an endpoint is either an absolute path or a full URL
   * @param endpoint - The endpoint to validate
   * @param name - The name of the endpoint property for error messages
   * @throws TypeError if the endpoint is invalid
   */
  private validateEndpoint(endpoint: string, name: string): void {
    if (this.isPath(endpoint)) {
      // It should be an absolute path starting with /
      if (!endpoint.startsWith('/')) {
        throw new TypeError(`${name} path must be an absolute path starting with /`);
      }
    } else {
      // It should be a valid URL
      try {
        new URL(endpoint);
      } catch (e) {
        throw new TypeError(`${name} must be either an absolute path starting with / or a valid URL`);
      }
    }
  }

  /**
   * Validates that a handler is either an ExportedHandler or a class extending WorkerEntrypoint
   * @param handler - The handler to validate
   * @param name - The name of the handler property for error messages
   * @returns The type of the handler (EXPORTED_HANDLER or WORKER_ENTRYPOINT)
   * @throws TypeError if the handler is invalid
   */
  private validateHandler(handler: any, name: string): TypedHandler {
    if (typeof handler === 'object' && handler !== null && typeof handler.fetch === 'function') {
      // It's an ExportedHandler object
      return { type: HandlerType.EXPORTED_HANDLER, handler };
    }

    // Check if it's a class constructor extending WorkerEntrypoint
    if (typeof handler === 'function' && handler.prototype instanceof WorkerEntrypoint) {
      return { type: HandlerType.WORKER_ENTRYPOINT, handler };
    }

    throw new TypeError(
      `${name} must be either an ExportedHandler object with a fetch method or a class extending WorkerEntrypoint`
    );
  }

  /**
   * Main fetch handler for the Worker
   * Routes requests to the appropriate handler based on the URL
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @param ctx - Cloudflare Worker execution context
   * @returns A Promise resolving to an HTTP Response
   */
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Special handling for OPTIONS requests (CORS preflight)
    if (request.method === 'OPTIONS') {
      // For API routes and OAuth endpoints, respond with CORS headers
      if (
        this.isApiRequest(url) ||
        url.pathname === '/.well-known/oauth-authorization-server' ||
        this.isTokenEndpoint(url) ||
        (this.options.clientRegistrationEndpoint && this.isClientRegistrationEndpoint(url))
      ) {
        // Create an empty 204 No Content response with CORS headers
        return this.addCorsHeaders(
          new Response(null, {
            status: 204,
            headers: { 'Content-Length': '0' },
          }),
          request
        );
      }

      // For other routes, pass through to the default handler
    }

    // Handle .well-known/oauth-authorization-server
    if (url.pathname === '/.well-known/oauth-authorization-server') {
      const response = await this.handleMetadataDiscovery(url);
      return this.addCorsHeaders(response, request);
    }

    // Handle token endpoint
    if (this.isTokenEndpoint(url)) {
      const response = await this.handleTokenRequest(request, env);
      return this.addCorsHeaders(response, request);
    }

    // Handle client registration endpoint
    if (this.options.clientRegistrationEndpoint && this.isClientRegistrationEndpoint(url)) {
      const response = await this.handleClientRegistration(request, env);
      return this.addCorsHeaders(response, request);
    }

    // Check if it's an API request
    if (this.isApiRequest(url)) {
      const response = await this.handleApiRequest(request, env, ctx);
      return this.addCorsHeaders(response, request);
    }

    // Inject OAuth helpers into env if not already present
    if (!env.OAUTH_PROVIDER) {
      env.OAUTH_PROVIDER = this.createOAuthHelpers(env);
    }

    // Call the default handler based on its type
    // Note: We don't add CORS headers to default handler responses
    if (this.typedDefaultHandler.type === HandlerType.EXPORTED_HANDLER) {
      // It's an object with a fetch method
      return this.typedDefaultHandler.handler.fetch(
        request as Parameters<ExportedHandlerWithFetch['fetch']>[0],
        env,
        ctx
      );
    } else {
      // It's a WorkerEntrypoint class - instantiate it with ctx and env in that order
      const handler = new this.typedDefaultHandler.handler(ctx, env);
      return handler.fetch(request);
    }
  }

  /**
   * Determines if an endpoint configuration is a path or a full URL
   * @param endpoint - The endpoint configuration
   * @returns True if the endpoint is a path (starts with /), false if it's a full URL
   */
  private isPath(endpoint: string): boolean {
    return endpoint.startsWith('/');
  }

  /**
   * Matches a URL against an endpoint pattern that can be a full URL or just a path
   * @param url - The URL to check
   * @param endpoint - The endpoint pattern (full URL or path)
   * @returns True if the URL matches the endpoint pattern
   */
  private matchEndpoint(url: URL, endpoint: string): boolean {
    if (this.isPath(endpoint)) {
      // It's a path - match only the pathname
      return url.pathname === endpoint;
    } else {
      // It's a full URL - match the entire URL including hostname
      const endpointUrl = new URL(endpoint);
      return url.hostname === endpointUrl.hostname && url.pathname === endpointUrl.pathname;
    }
  }

  /**
   * Checks if a URL matches the configured token endpoint
   * @param url - The URL to check
   * @returns True if the URL matches the token endpoint
   */
  private isTokenEndpoint(url: URL): boolean {
    return this.matchEndpoint(url, this.options.tokenEndpoint);
  }

  /**
   * Checks if a URL matches the configured client registration endpoint
   * @param url - The URL to check
   * @returns True if the URL matches the client registration endpoint
   */
  private isClientRegistrationEndpoint(url: URL): boolean {
    if (!this.options.clientRegistrationEndpoint) return false;
    return this.matchEndpoint(url, this.options.clientRegistrationEndpoint);
  }

  /**
   * Checks if a URL matches a specific API route
   * @param url - The URL to check
   * @param route - The API route to check against
   * @returns True if the URL matches the API route
   */
  private matchApiRoute(url: URL, route: string): boolean {
    if (this.isPath(route)) {
      // It's a path - match only the pathname
      return url.pathname.startsWith(route);
    } else {
      // It's a full URL - match the entire URL including hostname
      const apiUrl = new URL(route);
      return url.hostname === apiUrl.hostname && url.pathname.startsWith(apiUrl.pathname);
    }
  }

  /**
   * Checks if a URL is an API request based on the configured API route(s)
   * @param url - The URL to check
   * @returns True if the URL matches any of the API routes
   */
  private isApiRequest(url: URL): boolean {
    // Check each route in our array of validated API handlers
    for (const [route, _] of this.typedApiHandlers) {
      if (this.matchApiRoute(url, route)) {
        return true;
      }
    }
    return false;
  }
  
  /**
   * Finds the appropriate API handler for a URL
   * @param url - The URL to find a handler for
   * @returns The TypedHandler for the URL, or undefined if no handler matches
   */
  private findApiHandlerForUrl(url: URL): TypedHandler | undefined {
    // Check each route in our array of validated API handlers
    for (const [route, handler] of this.typedApiHandlers) {
      if (this.matchApiRoute(url, route)) {
        return handler;
      }
    }
    return undefined;
  }

  /**
   * Gets the full URL for an endpoint, using the provided request URL's
   * origin for endpoints specified as just paths
   * @param endpoint - The endpoint configuration (path or full URL)
   * @param requestUrl - The URL of the incoming request
   * @returns The full URL for the endpoint
   */
  private getFullEndpointUrl(endpoint: string, requestUrl: URL): string {
    if (this.isPath(endpoint)) {
      // It's a path - use the request URL's origin
      return `${requestUrl.origin}${endpoint}`;
    } else {
      // It's already a full URL
      return endpoint;
    }
  }

  /**
   * Adds CORS headers to a response
   * @param response - The response to add CORS headers to
   * @param request - The original request
   * @returns A new Response with CORS headers added
   */
  private addCorsHeaders(response: Response, request: Request): Response {
    // Get the Origin header from the request
    const origin = request.headers.get('Origin');

    // If there's no Origin header, return the original response
    if (!origin) {
      return response;
    }

    // Create a new response that copies all properties from the original response
    // This makes the response mutable so we can modify its headers
    const newResponse = new Response(response.body, response);

    // Add CORS headers
    newResponse.headers.set('Access-Control-Allow-Origin', origin);
    newResponse.headers.set('Access-Control-Allow-Methods', '*');
    // Include Authorization explicitly since it's not included in * for security reasons
    newResponse.headers.set('Access-Control-Allow-Headers', 'Authorization, *');
    newResponse.headers.set('Access-Control-Max-Age', '86400'); // 24 hours

    return newResponse;
  }

  /**
   * Handles the OAuth metadata discovery endpoint
   * Implements RFC 8414 for OAuth Server Metadata
   * @param requestUrl - The URL of the incoming request
   * @returns Response with OAuth server metadata
   */
  private async handleMetadataDiscovery(requestUrl: URL): Promise<Response> {
    // For endpoints specified as paths, use the request URL's origin
    const tokenEndpoint = this.getFullEndpointUrl(this.options.tokenEndpoint, requestUrl);
    const authorizeEndpoint = this.getFullEndpointUrl(this.options.authorizeEndpoint, requestUrl);

    let registrationEndpoint: string | undefined = undefined;
    if (this.options.clientRegistrationEndpoint) {
      registrationEndpoint = this.getFullEndpointUrl(this.options.clientRegistrationEndpoint, requestUrl);
    }

    // Determine supported response types
    const responseTypesSupported = ['code'];

    // Add token response type if implicit flow is allowed
    if (this.options.allowImplicitFlow) {
      responseTypesSupported.push('token');
    }

    const metadata = {
      issuer: new URL(tokenEndpoint).origin,
      authorization_endpoint: authorizeEndpoint,
      token_endpoint: tokenEndpoint,
      // not implemented: jwks_uri
      registration_endpoint: registrationEndpoint,
      scopes_supported: this.options.scopesSupported,
      response_types_supported: responseTypesSupported,
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      // Support "none" auth method for public clients
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      // not implemented: token_endpoint_auth_signing_alg_values_supported
      // not implemented: service_documentation
      // not implemented: ui_locales_supported
      // not implemented: op_policy_uri
      // not implemented: op_tos_uri
      revocation_endpoint: tokenEndpoint, // Reusing token endpoint for revocation
      // not implemented: revocation_endpoint_auth_methods_supported
      // not implemented: revocation_endpoint_auth_signing_alg_values_supported
      // not implemented: introspection_endpoint
      // not implemented: introspection_endpoint_auth_methods_supported
      // not implemented: introspection_endpoint_auth_signing_alg_values_supported
      code_challenge_methods_supported: ['plain', 'S256'], // PKCE support
    };

    return new Response(JSON.stringify(metadata), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Handles client authentication and token issuance via the token endpoint
   * Supports authorization_code and refresh_token grant types
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @returns Response with token data or error
   */
  private async handleTokenRequest(request: Request, env: any): Promise<Response> {
    // Only accept POST requests
    if (request.method !== 'POST') {
      return this.createErrorResponse('invalid_request', 'Method not allowed', 405);
    }

    let contentType = request.headers.get('Content-Type') || '';
    let body: any = {};

    // According to OAuth 2.0 RFC 6749 Section 2.3, token requests MUST use
    // application/x-www-form-urlencoded content type
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return this.createErrorResponse('invalid_request', 'Content-Type must be application/x-www-form-urlencoded', 400);
    }

    // Process application/x-www-form-urlencoded
    const formData = await request.formData();
    for (const [key, value] of formData.entries()) {
      body[key] = value;
    }

    // Get client ID from request
    const authHeader = request.headers.get('Authorization');
    let clientId = '';
    let clientSecret = '';

    if (authHeader && authHeader.startsWith('Basic ')) {
      // Basic auth
      const credentials = atob(authHeader.substring(6));
      const [id, secret] = credentials.split(':');
      clientId = id;
      clientSecret = secret || '';
    } else {
      // Form parameters
      clientId = body.client_id;
      clientSecret = body.client_secret || '';
    }

    if (!clientId) {
      return this.createErrorResponse('invalid_client', 'Client ID is required', 401);
    }

    // Verify client exists
    const clientInfo = await this.getClient(env, clientId);
    if (!clientInfo) {
      return this.createErrorResponse('invalid_client', 'Client not found', 401);
    }

    // Determine authentication requirements based on token endpoint auth method
    const isPublicClient = clientInfo.tokenEndpointAuthMethod === 'none';

    // For confidential clients, validate the secret
    if (!isPublicClient) {
      if (!clientSecret) {
        return this.createErrorResponse('invalid_client', 'Client authentication failed: missing client_secret', 401);
      }

      // Verify the client secret matches
      if (!clientInfo.clientSecret) {
        return this.createErrorResponse(
          'invalid_client',
          'Client authentication failed: client has no registered secret',
          401
        );
      }

      const providedSecretHash = await hashSecret(clientSecret);
      if (providedSecretHash !== clientInfo.clientSecret) {
        return this.createErrorResponse('invalid_client', 'Client authentication failed: invalid client_secret', 401);
      }
    }
    // For public clients, no secret is required

    // Handle different grant types
    const grantType = body.grant_type;

    if (grantType === 'authorization_code') {
      return this.handleAuthorizationCodeGrant(body, clientInfo, env);
    } else if (grantType === 'refresh_token') {
      return this.handleRefreshTokenGrant(body, clientInfo, env);
    } else {
      return this.createErrorResponse('unsupported_grant_type', 'Grant type not supported');
    }
  }

  /**
   * Handles the authorization code grant type
   * Exchanges an authorization code for access and refresh tokens
   * @param body - The parsed request body
   * @param clientInfo - The authenticated client information
   * @param env - Cloudflare Worker environment variables
   * @returns Response with token data or error
   */
  private async handleAuthorizationCodeGrant(body: any, clientInfo: ClientInfo, env: any): Promise<Response> {
    const code = body.code;
    const redirectUri = body.redirect_uri;
    const codeVerifier = body.code_verifier;

    if (!code) {
      return this.createErrorResponse('invalid_request', 'Authorization code is required');
    }

    // Parse the authorization code to extract user ID and grant ID
    const codeParts = code.split(':');
    if (codeParts.length !== 3) {
      return this.createErrorResponse('invalid_grant', 'Invalid authorization code format');
    }

    const [userId, grantId, _] = codeParts;

    // Get the grant
    const grantKey = `grant:${userId}:${grantId}`;
    const grantData: Grant | null = await env.OAUTH_KV.get(grantKey, { type: 'json' });

    if (!grantData) {
      return this.createErrorResponse('invalid_grant', 'Grant not found or authorization code expired');
    }

    // Verify that the grant contains an auth code hash
    if (!grantData.authCodeId) {
      return this.createErrorResponse('invalid_grant', 'Authorization code already used');
    }

    // Verify the authorization code by comparing its hash to the one in the grant
    const codeHash = await hashSecret(code);
    if (codeHash !== grantData.authCodeId) {
      return this.createErrorResponse('invalid_grant', 'Invalid authorization code');
    }

    // Verify client ID matches
    if (grantData.clientId !== clientInfo.clientId) {
      return this.createErrorResponse('invalid_grant', 'Client ID mismatch');
    }

    // Check if PKCE is being used
    const isPkceEnabled = !!grantData.codeChallenge;

    // OAuth 2.1 requires redirect_uri parameter unless PKCE is used
    if (!redirectUri && !isPkceEnabled) {
      return this.createErrorResponse('invalid_request', 'redirect_uri is required when not using PKCE');
    }

    // Verify redirect URI if provided
    if (redirectUri && !clientInfo.redirectUris.includes(redirectUri)) {
      return this.createErrorResponse('invalid_grant', 'Invalid redirect URI');
    }

    // Verify PKCE code_verifier if code_challenge was provided during authorization
    if (isPkceEnabled) {
      if (!codeVerifier) {
        return this.createErrorResponse('invalid_request', 'code_verifier is required for PKCE');
      }

      // Verify the code verifier against the stored code challenge
      let calculatedChallenge: string;

      if (grantData.codeChallengeMethod === 'S256') {
        // SHA-256 transformation for S256 method
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        calculatedChallenge = base64UrlEncode(String.fromCharCode(...hashArray));
      } else {
        // Plain method, direct comparison
        calculatedChallenge = codeVerifier;
      }

      if (calculatedChallenge !== grantData.codeChallenge) {
        return this.createErrorResponse('invalid_grant', 'Invalid PKCE code_verifier');
      }
    }

    // Code is valid - generate tokens
    const accessTokenSecret = generateRandomString(TOKEN_LENGTH);
    const refreshTokenSecret = generateRandomString(TOKEN_LENGTH);

    const accessToken = `${userId}:${grantId}:${accessTokenSecret}`;
    const refreshToken = `${userId}:${grantId}:${refreshTokenSecret}`;

    // Use WebCrypto to generate token IDs from the full token strings
    const accessTokenId = await generateTokenId(accessToken);
    const refreshTokenId = await generateTokenId(refreshToken);

    // Define the access token TTL, may be updated by callback if provided
    let accessTokenTTL = this.options.accessTokenTTL!;

    // Get the encryption key for props by unwrapping it using the auth code
    const encryptionKey = await unwrapKeyWithToken(code, grantData.authCodeWrappedKey!);

    // Default to using the same encryption key and props for both grant and access token
    let grantEncryptionKey = encryptionKey;
    let accessTokenEncryptionKey = encryptionKey;
    let encryptedAccessTokenProps = grantData.encryptedProps;

    // Process token exchange callback if provided
    if (this.options.tokenExchangeCallback) {
      // Decrypt the existing props to provide them to the callback
      const decryptedProps = await decryptProps(encryptionKey, grantData.encryptedProps);

      // Default to using the original props for both grant and token
      let grantProps = decryptedProps;
      let accessTokenProps = decryptedProps;

      const callbackOptions: TokenExchangeCallbackOptions = {
        grantType: 'authorization_code',
        clientId: clientInfo.clientId,
        userId: userId,
        scope: grantData.scope,
        props: decryptedProps,
      };

      const callbackResult = await Promise.resolve(this.options.tokenExchangeCallback(callbackOptions));

      if (callbackResult) {
        // Use the returned props if provided, otherwise keep the original props
        if (callbackResult.newProps) {
          grantProps = callbackResult.newProps;

          // If accessTokenProps wasn't explicitly specified, use the updated newProps for the token too
          // This ensures token props are updated when only newProps are specified
          if (!callbackResult.accessTokenProps) {
            accessTokenProps = callbackResult.newProps;
          }
        }

        // If accessTokenProps was explicitly specified, use those
        if (callbackResult.accessTokenProps) {
          accessTokenProps = callbackResult.accessTokenProps;
        }

        // If accessTokenTTL was specified, use that for this token
        if (callbackResult.accessTokenTTL !== undefined) {
          accessTokenTTL = callbackResult.accessTokenTTL;
        }
      }

      // Re-encrypt the potentially updated grant props
      const grantResult = await encryptProps(grantProps);
      grantData.encryptedProps = grantResult.encryptedData;
      grantEncryptionKey = grantResult.key;

      // Re-encrypt the access token props if they're different from grant props
      if (accessTokenProps !== grantProps) {
        const tokenResult = await encryptProps(accessTokenProps);
        encryptedAccessTokenProps = tokenResult.encryptedData;
        accessTokenEncryptionKey = tokenResult.key;
      } else {
        // If they're the same, use the grant's encrypted data and key
        encryptedAccessTokenProps = grantData.encryptedProps;
        accessTokenEncryptionKey = grantEncryptionKey;
      }
    }

    // Calculate the access token expiration time (after callback might have updated TTL)
    const now = Math.floor(Date.now() / 1000);
    const accessTokenExpiresAt = now + accessTokenTTL;

    // Wrap the keys for the new tokens
    const accessTokenWrappedKey = await wrapKeyWithToken(accessToken, accessTokenEncryptionKey);
    const refreshTokenWrappedKey = await wrapKeyWithToken(refreshToken, grantEncryptionKey);

    // Update the grant:
    // - Remove the auth code hash (it's single-use)
    // - Remove PKCE-related fields (one-time use)
    // - Remove auth code wrapped key (no longer needed)
    // - Add the refresh token hash and wrapped key
    // - Make it permanent (no TTL)
    delete grantData.authCodeId;
    delete grantData.codeChallenge;
    delete grantData.codeChallengeMethod;
    delete grantData.authCodeWrappedKey;
    grantData.refreshTokenId = refreshTokenId;
    grantData.refreshTokenWrappedKey = refreshTokenWrappedKey;
    grantData.previousRefreshTokenId = undefined; // No previous token for first use
    grantData.previousRefreshTokenWrappedKey = undefined; // No previous token for first use

    // Update the grant with the refresh token hash and no TTL
    await env.OAUTH_KV.put(grantKey, JSON.stringify(grantData));

    // Store access token with denormalized grant information
    const accessTokenData: Token = {
      id: accessTokenId,
      grantId: grantId,
      userId: userId,
      createdAt: now,
      expiresAt: accessTokenExpiresAt,
      wrappedEncryptionKey: accessTokenWrappedKey,
      grant: {
        clientId: grantData.clientId,
        scope: grantData.scope,
        encryptedProps: encryptedAccessTokenProps,
      },
    };

    // Save access token with TTL (using the potentially callback-provided TTL)
    await env.OAUTH_KV.put(`token:${userId}:${grantId}:${accessTokenId}`, JSON.stringify(accessTokenData), {
      expirationTtl: accessTokenTTL,
    });

    // Return the tokens
    return new Response(
      JSON.stringify({
        access_token: accessToken,
        token_type: 'bearer',
        expires_in: accessTokenTTL,
        refresh_token: refreshToken,
        scope: grantData.scope.join(' '),
      }),
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  /**
   * Handles the refresh token grant type
   * Issues a new access token using a refresh token
   * @param body - The parsed request body
   * @param clientInfo - The authenticated client information
   * @param env - Cloudflare Worker environment variables
   * @returns Response with token data or error
   */
  private async handleRefreshTokenGrant(body: any, clientInfo: ClientInfo, env: any): Promise<Response> {
    const refreshToken = body.refresh_token;

    if (!refreshToken) {
      return this.createErrorResponse('invalid_request', 'Refresh token is required');
    }

    // Parse the token to extract user ID and grant ID
    const tokenParts = refreshToken.split(':');
    if (tokenParts.length !== 3) {
      return this.createErrorResponse('invalid_grant', 'Invalid token format');
    }

    const [userId, grantId, _] = tokenParts;

    // Calculate the token hash
    const providedTokenHash = await generateTokenId(refreshToken);

    // Get the associated grant using userId in the key
    const grantKey = `grant:${userId}:${grantId}`;
    const grantData: Grant | null = await env.OAUTH_KV.get(grantKey, { type: 'json' });

    if (!grantData) {
      return this.createErrorResponse('invalid_grant', 'Grant not found');
    }

    // Check if the provided token matches either the current or previous refresh token
    const isCurrentToken = grantData.refreshTokenId === providedTokenHash;
    const isPreviousToken = grantData.previousRefreshTokenId === providedTokenHash;

    if (!isCurrentToken && !isPreviousToken) {
      return this.createErrorResponse('invalid_grant', 'Invalid refresh token');
    }

    // Verify client ID matches
    if (grantData.clientId !== clientInfo.clientId) {
      return this.createErrorResponse('invalid_grant', 'Client ID mismatch');
    }

    // Generate new access token with embedded user and grant IDs
    const accessTokenSecret = generateRandomString(TOKEN_LENGTH);
    const newAccessToken = `${userId}:${grantId}:${accessTokenSecret}`;
    const accessTokenId = await generateTokenId(newAccessToken);

    // Always issue a new refresh token with each use
    const refreshTokenSecret = generateRandomString(TOKEN_LENGTH);
    const newRefreshToken = `${userId}:${grantId}:${refreshTokenSecret}`;
    const newRefreshTokenId = await generateTokenId(newRefreshToken);

    // Define the access token TTL, may be updated by callback if provided
    let accessTokenTTL = this.options.accessTokenTTL!;

    // Determine which wrapped key to use for unwrapping
    let wrappedKeyToUse: string;
    if (isCurrentToken) {
      wrappedKeyToUse = grantData.refreshTokenWrappedKey!;
    } else {
      wrappedKeyToUse = grantData.previousRefreshTokenWrappedKey!;
    }

    // Unwrap the encryption key using the refresh token
    const encryptionKey = await unwrapKeyWithToken(refreshToken, wrappedKeyToUse);

    // Default to using the same encryption key and props for both grant and access token
    let grantEncryptionKey = encryptionKey;
    let accessTokenEncryptionKey = encryptionKey;
    let encryptedAccessTokenProps = grantData.encryptedProps;

    // Process token exchange callback if provided
    if (this.options.tokenExchangeCallback) {
      // Decrypt the existing props to provide them to the callback
      const decryptedProps = await decryptProps(encryptionKey, grantData.encryptedProps);

      // Default to using the original props for both grant and token
      let grantProps = decryptedProps;
      let accessTokenProps = decryptedProps;

      const callbackOptions: TokenExchangeCallbackOptions = {
        grantType: 'refresh_token',
        clientId: clientInfo.clientId,
        userId: userId,
        scope: grantData.scope,
        props: decryptedProps,
      };

      const callbackResult = await Promise.resolve(this.options.tokenExchangeCallback(callbackOptions));

      let grantPropsChanged = false;
      if (callbackResult) {
        // Use the returned props if provided, otherwise keep the original props
        if (callbackResult.newProps) {
          grantProps = callbackResult.newProps;
          grantPropsChanged = true;

          // If accessTokenProps wasn't explicitly specified, use the updated newProps for the token too
          // This ensures token props are updated when only newProps are specified
          if (!callbackResult.accessTokenProps) {
            accessTokenProps = callbackResult.newProps;
          }
        }

        // If accessTokenProps was explicitly specified, use those
        if (callbackResult.accessTokenProps) {
          accessTokenProps = callbackResult.accessTokenProps;
        }

        // If accessTokenTTL was specified, use that for this token
        if (callbackResult.accessTokenTTL !== undefined) {
          accessTokenTTL = callbackResult.accessTokenTTL;
        }
      }

      // Only re-encrypt the grant props if they've changed
      if (grantPropsChanged) {
        // Re-encrypt the updated grant props
        const grantResult = await encryptProps(grantProps);
        grantData.encryptedProps = grantResult.encryptedData;

        // If the encryption key changed, we need to re-wrap the previous token key
        if (grantResult.key !== encryptionKey) {
          grantEncryptionKey = grantResult.key;
          wrappedKeyToUse = await wrapKeyWithToken(refreshToken, grantEncryptionKey);
        } else {
          grantEncryptionKey = grantResult.key;
        }
      }

      // Re-encrypt the access token props if they're different from grant props
      if (accessTokenProps !== grantProps) {
        const tokenResult = await encryptProps(accessTokenProps);
        encryptedAccessTokenProps = tokenResult.encryptedData;
        accessTokenEncryptionKey = tokenResult.key;
      } else {
        // If they're the same, use the grant's encrypted data and key
        encryptedAccessTokenProps = grantData.encryptedProps;
        accessTokenEncryptionKey = grantEncryptionKey;
      }
    }

    // Calculate the access token expiration time (after callback might have updated TTL)
    const now = Math.floor(Date.now() / 1000);
    const accessTokenExpiresAt = now + accessTokenTTL;

    // Wrap the key for both the new access token and refresh token
    const accessTokenWrappedKey = await wrapKeyWithToken(newAccessToken, accessTokenEncryptionKey);
    const newRefreshTokenWrappedKey = await wrapKeyWithToken(newRefreshToken, grantEncryptionKey);

    // Update the grant with the token rotation information

    // The token which the client used this time becomes the "previous" token, so that the client
    // can always use the same token again next time. This might technically violate OAuth 2.1's
    // requirement that refresh tokens be single-use. However, this requirement violates the laws
    // of distributed systems. It's important that the client can always retry when a transient
    // failure occurs. Under the strict requirement, if the failure occurred after the server
    // rotated the token but before the client managed to store the updated token, then the client
    // no longer has any valid refresh token and has effectively lost its grant. That's bad! So
    // instead, we don't invalidate the old token until the client successfully uses a newer token.
    // This provides most of the security benefits (tokens still rotate naturally) but without
    // being inherently unreliable.
    grantData.previousRefreshTokenId = providedTokenHash;
    grantData.previousRefreshTokenWrappedKey = wrappedKeyToUse;

    // The newly-generated token becomes the new "current" token.
    grantData.refreshTokenId = newRefreshTokenId;
    grantData.refreshTokenWrappedKey = newRefreshTokenWrappedKey;

    // Save the updated grant
    await env.OAUTH_KV.put(grantKey, JSON.stringify(grantData));

    // Store new access token with denormalized grant information
    const accessTokenData: Token = {
      id: accessTokenId,
      grantId: grantId,
      userId: userId,
      createdAt: now,
      expiresAt: accessTokenExpiresAt,
      wrappedEncryptionKey: accessTokenWrappedKey,
      grant: {
        clientId: grantData.clientId,
        scope: grantData.scope,
        encryptedProps: encryptedAccessTokenProps,
      },
    };

    // Save access token with TTL (using the potentially callback-provided TTL)
    await env.OAUTH_KV.put(`token:${userId}:${grantId}:${accessTokenId}`, JSON.stringify(accessTokenData), {
      expirationTtl: accessTokenTTL,
    });

    // Return the new access token and refresh token
    return new Response(
      JSON.stringify({
        access_token: newAccessToken,
        token_type: 'bearer',
        expires_in: accessTokenTTL,
        refresh_token: newRefreshToken,
        scope: grantData.scope.join(' '),
      }),
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  /**
   * Handles the dynamic client registration endpoint (RFC 7591)
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @returns Response with client registration data or error
   */
  private async handleClientRegistration(request: Request, env: any): Promise<Response> {
    if (!this.options.clientRegistrationEndpoint) {
      return this.createErrorResponse('not_implemented', 'Client registration is not enabled', 501);
    }

    // Check method
    if (request.method !== 'POST') {
      return this.createErrorResponse('invalid_request', 'Method not allowed', 405);
    }

    // Check content length to ensure it's not too large (1 MiB limit)
    const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (contentLength > 1048576) {
      // 1 MiB = 1048576 bytes
      return this.createErrorResponse('invalid_request', 'Request payload too large, must be under 1 MiB', 413);
    }

    // Parse client metadata with a size limitation
    let clientMetadata;
    try {
      const text = await request.text();
      if (text.length > 1048576) {
        // Double-check text length
        return this.createErrorResponse('invalid_request', 'Request payload too large, must be under 1 MiB', 413);
      }
      clientMetadata = JSON.parse(text);
    } catch (error) {
      return this.createErrorResponse('invalid_request', 'Invalid JSON payload', 400);
    }

    // Basic type validation functions
    const validateStringField = (field: any): string | undefined => {
      if (field === undefined) {
        return undefined;
      }
      if (typeof field !== 'string') {
        throw new Error('Field must be a string');
      }
      return field;
    };

    const validateStringArray = (arr: any): string[] | undefined => {
      if (arr === undefined) {
        return undefined;
      }
      if (!Array.isArray(arr)) {
        throw new Error('Field must be an array');
      }

      // Validate all elements are strings
      for (const item of arr) {
        if (typeof item !== 'string') {
          throw new Error('All array elements must be strings');
        }
      }

      return arr;
    };

    // Get token endpoint auth method, default to client_secret_basic
    const authMethod = validateStringField(clientMetadata.token_endpoint_auth_method) || 'client_secret_basic';
    const isPublicClient = authMethod === 'none';

    // Check if public client registrations are disallowed
    if (isPublicClient && this.options.disallowPublicClientRegistration) {
      return this.createErrorResponse('invalid_client_metadata', 'Public client registration is not allowed');
    }

    // Create client ID
    const clientId = generateRandomString(16);

    // Only create client secret for confidential clients
    let clientSecret: string | undefined;
    let hashedSecret: string | undefined;

    if (!isPublicClient) {
      clientSecret = generateRandomString(32);
      hashedSecret = await hashSecret(clientSecret);
    }

    let clientInfo: ClientInfo;
    try {
      // Validate redirect URIs - must exist and have at least one entry
      const redirectUris = validateStringArray(clientMetadata.redirect_uris);
      if (!redirectUris || redirectUris.length === 0) {
        throw new Error('At least one redirect URI is required');
      }

      clientInfo = {
        clientId,
        redirectUris,
        clientName: validateStringField(clientMetadata.client_name),
        logoUri: validateStringField(clientMetadata.logo_uri),
        clientUri: validateStringField(clientMetadata.client_uri),
        policyUri: validateStringField(clientMetadata.policy_uri),
        tosUri: validateStringField(clientMetadata.tos_uri),
        jwksUri: validateStringField(clientMetadata.jwks_uri),
        contacts: validateStringArray(clientMetadata.contacts),
        grantTypes: validateStringArray(clientMetadata.grant_types) || ['authorization_code', 'refresh_token'],
        responseTypes: validateStringArray(clientMetadata.response_types) || ['code'],
        registrationDate: Math.floor(Date.now() / 1000),
        tokenEndpointAuthMethod: authMethod,
      };

      // Add client secret only for confidential clients
      if (!isPublicClient && hashedSecret) {
        clientInfo.clientSecret = hashedSecret;
      }
    } catch (error) {
      return this.createErrorResponse(
        'invalid_client_metadata',
        error instanceof Error ? error.message : 'Invalid client metadata'
      );
    }

    // Store client info
    await env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(clientInfo));

    // Return client information with the original unhashed secret
    const response: Record<string, any> = {
      client_id: clientInfo.clientId,
      redirect_uris: clientInfo.redirectUris,
      client_name: clientInfo.clientName,
      logo_uri: clientInfo.logoUri,
      client_uri: clientInfo.clientUri,
      policy_uri: clientInfo.policyUri,
      tos_uri: clientInfo.tosUri,
      jwks_uri: clientInfo.jwksUri,
      contacts: clientInfo.contacts,
      grant_types: clientInfo.grantTypes,
      response_types: clientInfo.responseTypes,
      token_endpoint_auth_method: clientInfo.tokenEndpointAuthMethod,
      registration_client_uri: `${this.options.clientRegistrationEndpoint}/${clientId}`,
      client_id_issued_at: clientInfo.registrationDate,
    };

    // Only include client_secret for confidential clients
    if (clientSecret) {
      response.client_secret = clientSecret; // Return the original unhashed secret
    }

    return new Response(JSON.stringify(response), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Handles API requests by validating the access token and calling the API handler
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @param ctx - Cloudflare Worker execution context
   * @returns Response from the API handler or error
   */
  private async handleApiRequest(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    // Get access token from Authorization header
    const authHeader = request.headers.get('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return this.createErrorResponse('invalid_token', 'Missing or invalid access token', 401, {
        'WWW-Authenticate':
          'Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token"',
      });
    }

    const accessToken = authHeader.substring(7);

    // Parse the token to extract user ID and grant ID for parallel lookups
    const tokenParts = accessToken.split(':');
    if (tokenParts.length !== 3) {
      return this.createErrorResponse('invalid_token', 'Invalid token format', 401, {
        'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token"',
      });
    }

    const [userId, grantId, _] = tokenParts;

    // Generate token ID from the full token
    const accessTokenId = await generateTokenId(accessToken);

    // Look up the token record, which now contains the denormalized grant information
    const tokenKey = `token:${userId}:${grantId}:${accessTokenId}`;
    const tokenData: Token | null = await env.OAUTH_KV.get(tokenKey, { type: 'json' });

    // Verify token
    if (!tokenData) {
      return this.createErrorResponse('invalid_token', 'Invalid access token', 401, {
        'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token"',
      });
    }

    // Check if token is expired (should be auto-deleted by KV TTL, but double-check)
    const now = Math.floor(Date.now() / 1000);
    if (tokenData.expiresAt < now) {
      return this.createErrorResponse('invalid_token', 'Access token expired', 401, {
        'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token"',
      });
    }

    // Unwrap the encryption key using the access token
    const encryptionKey = await unwrapKeyWithToken(accessToken, tokenData.wrappedEncryptionKey);

    // Decrypt the props
    const decryptedProps = await decryptProps(encryptionKey, tokenData.grant.encryptedProps);

    // Set the decrypted props on the context object
    ctx.props = decryptedProps;

    // Inject OAuth helpers into env if not already present
    if (!env.OAUTH_PROVIDER) {
      env.OAUTH_PROVIDER = this.createOAuthHelpers(env);
    }

    // Find the appropriate API handler for this URL
    const url = new URL(request.url);
    const apiHandler = this.findApiHandlerForUrl(url);
    
    if (!apiHandler) {
      // This shouldn't happen since we already checked with isApiRequest,
      // but handle it gracefully just in case
      return this.createErrorResponse('invalid_request', 'No handler found for API route', 404);
    }
    
    // Call the API handler based on its type
    if (apiHandler.type === HandlerType.EXPORTED_HANDLER) {
      // It's an object with a fetch method
      return apiHandler.handler.fetch(request as Parameters<ExportedHandlerWithFetch['fetch']>[0], env, ctx);
    } else {
      // It's a WorkerEntrypoint class - instantiate it with ctx and env in that order
      const handler = new apiHandler.handler(ctx, env);
      return handler.fetch(request);
    }
  }
  /**
   * Creates the helper methods object for OAuth operations
   * This is passed to the handler functions to allow them to interact with the OAuth system
   * @param env - Cloudflare Worker environment variables
   * @returns An instance of OAuthHelpers
   */
  private createOAuthHelpers(env: any): OAuthHelpers {
    return new OAuthHelpersImpl(env, this);
  }

  /**
   * Fetches client information from KV storage
   * This method is not private because `OAuthHelpers` needs to call it. Note that since
   * `OAuthProviderImpl` is not exposed outside this module, this is still effectively
   * module-private.
   * @param env - Cloudflare Worker environment variables
   * @param clientId - The client ID to look up
   * @returns The client information, or null if not found
   */
  getClient(env: any, clientId: string): Promise<ClientInfo | null> {
    const clientKey = `client:${clientId}`;
    return env.OAUTH_KV.get(clientKey, { type: 'json' });
  }

  /**
   * Helper function to create OAuth error responses
   * @param code - OAuth error code (e.g., 'invalid_request', 'invalid_token')
   * @param description - Human-readable error description
   * @param status - HTTP status code (default: 400)
   * @param headers - Additional headers to include
   * @returns A Response object with the error
   */
  private createErrorResponse(
    code: string,
    description: string,
    status: number = 400,
    headers: Record<string, string> = {}
  ): Response {
    // Notify the user of the error and allow them to override the response
    const customErrorResponse = this.options.onError?.({ code, description, status, headers });
    if (customErrorResponse) return customErrorResponse;

    const body = JSON.stringify({
      error: code,
      error_description: description,
    });

    return new Response(body, {
      status,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    });
  }
}

// Constants
/**
 * Default expiration time for access tokens (1 hour in seconds)
 */
const DEFAULT_ACCESS_TOKEN_TTL = 60 * 60;

/**
 * Length of generated token strings
 */
const TOKEN_LENGTH = 32;

// Helper Functions
/**
 * Hashes a secret value using SHA-256
 * @param secret - The secret value to hash
 * @returns A hex string representation of the hash
 */
async function hashSecret(secret: string): Promise<string> {
  // Use the same approach as generateTokenId for consistency
  return generateTokenId(secret);
}

/**
 * Generates a cryptographically secure random string
 * @param length - The length of the string to generate
 * @returns A random string of the specified length
 */
function generateRandomString(length: number): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const values = new Uint8Array(length);
  crypto.getRandomValues(values);
  for (let i = 0; i < length; i++) {
    result += characters.charAt(values[i] % characters.length);
  }
  return result;
}

/**
 * Generates a token ID by hashing the token value using SHA-256
 * @param token - The token to hash
 * @returns A hex string representation of the hash
 */
async function generateTokenId(token: string): Promise<string> {
  // Convert the token string to a Uint8Array
  const encoder = new TextEncoder();
  const data = encoder.encode(token);

  // Use the WebCrypto API to create a SHA-256 hash
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  // Convert the hash to a hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

  return hashHex;
}

/**
 * Encodes a string as base64url (URL-safe base64)
 * @param str - The string to encode
 * @returns The base64url encoded string
 */
function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Encodes an ArrayBuffer as base64 string
 * @param buffer - The ArrayBuffer to encode
 * @returns The base64 encoded string
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

/**
 * Decodes a base64 string to an ArrayBuffer
 * @param base64 - The base64 string to decode
 * @returns The decoded ArrayBuffer
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Encrypts props data with a newly generated key
 * @param data - The data to encrypt
 * @returns An object containing the encrypted data and the generated key
 */
async function encryptProps(data: any): Promise<{ encryptedData: string; key: CryptoKey }> {
  // Generate a new encryption key for this specific props data
  // @ts-ignore
  const key: CryptoKey = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );

  // Use a constant IV (all zeros) since each key is used only once
  const iv = new Uint8Array(12);

  // Convert data to string
  const jsonData = JSON.stringify(data);
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(jsonData);

  // Encrypt the data
  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encodedData
  );

  // Convert to base64 for storage
  return {
    encryptedData: arrayBufferToBase64(encryptedBuffer),
    key,
  };
}

/**
 * Decrypts encrypted props data using the provided key
 * @param key - The CryptoKey to use for decryption
 * @param encryptedData - The encrypted data as a base64 string
 * @returns The decrypted data object
 */
async function decryptProps(key: CryptoKey, encryptedData: string): Promise<any> {
  // Convert base64 string back to ArrayBuffer
  const encryptedBuffer = base64ToArrayBuffer(encryptedData);

  // Use the same constant IV (all zeros) that was used for encryption
  const iv = new Uint8Array(12);

  // Decrypt the data
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encryptedBuffer
  );

  // Convert the decrypted buffer to a string, then parse as JSON
  const decoder = new TextDecoder();
  const jsonData = decoder.decode(decryptedBuffer);
  return JSON.parse(jsonData);
}

// Static HMAC key for wrapping key derivation
// This ensures that even if someone has the token ID, they can't derive the wrapping key
// We use a fixed array of 32 bytes for optimal performance
const WRAPPING_KEY_HMAC_KEY = new Uint8Array([
  0x22, 0x7e, 0x26, 0x86, 0x8d, 0xf1, 0xe1, 0x6d, 0x80, 0x70, 0xea, 0x17, 0x97, 0x5b, 0x47, 0xa6, 0x82, 0x18, 0xfa,
  0x87, 0x28, 0xae, 0xde, 0x85, 0xb5, 0x1d, 0x4a, 0xd9, 0x96, 0xca, 0xca, 0x43,
]);

/**
 * Derives a wrapping key from a token string
 * This intentionally uses a different method than token ID generation
 * to ensure the token ID cannot be used to derive the wrapping key
 * @param tokenStr - The token string to use as key material
 * @returns A Promise resolving to the derived CryptoKey
 */
async function deriveKeyFromToken(tokenStr: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();

  // Import the pre-defined HMAC key (already 32 bytes)
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    WRAPPING_KEY_HMAC_KEY,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // Use HMAC-SHA256 to derive the wrapping key material
  const hmacResult = await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(tokenStr));

  // Import the HMAC result as the wrapping key
  return await crypto.subtle.importKey(
    'raw',
    hmacResult,
    { name: 'AES-KW' },
    false, // not extractable
    ['wrapKey', 'unwrapKey']
  );
}

/**
 * Wraps an encryption key using a token-derived key
 * @param tokenStr - The token string to use for key wrapping
 * @param keyToWrap - The encryption key to wrap
 * @returns A Promise resolving to the wrapped key as a base64 string
 */
async function wrapKeyWithToken(tokenStr: string, keyToWrap: CryptoKey): Promise<string> {
  // Derive a key from the token
  const wrappingKey = await deriveKeyFromToken(tokenStr);

  // Wrap the encryption key
  const wrappedKeyBuffer = await crypto.subtle.wrapKey('raw', keyToWrap, wrappingKey, { name: 'AES-KW' });

  // Convert to base64 for storage
  return arrayBufferToBase64(wrappedKeyBuffer);
}

/**
 * Unwraps an encryption key using a token-derived key
 * @param tokenStr - The token string used for key wrapping
 * @param wrappedKeyBase64 - The wrapped key as a base64 string
 * @returns A Promise resolving to the unwrapped CryptoKey
 */
async function unwrapKeyWithToken(tokenStr: string, wrappedKeyBase64: string): Promise<CryptoKey> {
  // Derive a key from the token
  const wrappingKey = await deriveKeyFromToken(tokenStr);

  // Convert base64 wrapped key to ArrayBuffer
  const wrappedKeyBuffer = base64ToArrayBuffer(wrappedKeyBase64);

  // Unwrap the key
  return await crypto.subtle.unwrapKey(
    'raw',
    wrappedKeyBuffer,
    wrappingKey,
    { name: 'AES-KW' },
    { name: 'AES-GCM' },
    true, // extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Class that implements the OAuth helper methods
 * Provides methods for OAuth operations needed by handlers
 */
class OAuthHelpersImpl implements OAuthHelpers {
  private env: any;
  private provider: OAuthProviderImpl;

  /**
   * Creates a new OAuthHelpers instance
   * @param env - Cloudflare Worker environment variables
   * @param provider - Reference to the parent provider instance
   */
  constructor(env: any, provider: OAuthProviderImpl) {
    this.env = env;
    this.provider = provider;
  }

  /**
   * Parses an OAuth authorization request from the HTTP request
   * @param request - The HTTP request containing OAuth parameters
   * @returns The parsed authorization request parameters
   */
  async parseAuthRequest(request: Request): Promise<AuthRequest> {
    const url = new URL(request.url);
    const responseType = url.searchParams.get('response_type') || '';
    const clientId = url.searchParams.get('client_id') || '';
    const redirectUri = url.searchParams.get('redirect_uri') || '';
    const scope = (url.searchParams.get('scope') || '').split(' ').filter(Boolean);
    const state = url.searchParams.get('state') || '';
    const codeChallenge = url.searchParams.get('code_challenge') || undefined;
    const codeChallengeMethod = url.searchParams.get('code_challenge_method') || 'plain';

    // Check if implicit flow is requested but not allowed
    if (responseType === 'token' && !this.provider.options.allowImplicitFlow) {
      throw new Error('The implicit grant flow is not enabled for this provider');
    }

    return {
      responseType,
      clientId,
      redirectUri,
      scope,
      state,
      codeChallenge,
      codeChallengeMethod,
    };
  }

  /**
   * Looks up a client by its client ID
   * @param clientId - The client ID to look up
   * @returns A Promise resolving to the client info, or null if not found
   */
  async lookupClient(clientId: string): Promise<ClientInfo | null> {
    return await this.provider.getClient(this.env, clientId);
  }

  /**
   * Completes an authorization request by creating a grant and either:
   * - For authorization code flow: generating an authorization code
   * - For implicit flow: generating an access token directly
   * @param options - Options specifying the grant details
   * @returns A Promise resolving to an object containing the redirect URL
   */
  async completeAuthorization(options: CompleteAuthorizationOptions): Promise<{ redirectTo: string }> {
    // Generate a unique grant ID
    const grantId = generateRandomString(16);

    // Encrypt the props data with a new key generated for this grant
    const { encryptedData, key: encryptionKey } = await encryptProps(options.props);

    // Get current timestamp
    const now = Math.floor(Date.now() / 1000);

    // Check if this is an implicit flow request (response_type=token)
    if (options.request.responseType === 'token') {
      // For implicit flow, we skip the authorization code and directly issue an access token
      const accessTokenSecret = generateRandomString(TOKEN_LENGTH);
      const accessToken = `${options.userId}:${grantId}:${accessTokenSecret}`;

      // Generate token ID from the full token string
      const accessTokenId = await generateTokenId(accessToken);

      // Determine token expiration
      const accessTokenTTL = this.provider.options.accessTokenTTL || DEFAULT_ACCESS_TOKEN_TTL;
      const accessTokenExpiresAt = now + accessTokenTTL;

      // Wrap the encryption key with the access token
      const accessTokenWrappedKey = await wrapKeyWithToken(accessToken, encryptionKey);

      // Store the grant without an auth code (will be referenced by the access token)
      const grant: Grant = {
        id: grantId,
        clientId: options.request.clientId,
        userId: options.userId,
        scope: options.scope,
        metadata: options.metadata,
        encryptedProps: encryptedData,
        createdAt: now,
      };

      // Store the grant with a key that includes the user ID
      const grantKey = `grant:${options.userId}:${grantId}`;
      await this.env.OAUTH_KV.put(grantKey, JSON.stringify(grant));

      // Store access token with denormalized grant information
      const accessTokenData: Token = {
        id: accessTokenId,
        grantId: grantId,
        userId: options.userId,
        createdAt: now,
        expiresAt: accessTokenExpiresAt,
        wrappedEncryptionKey: accessTokenWrappedKey,
        grant: {
          clientId: options.request.clientId,
          scope: options.scope,
          encryptedProps: encryptedData,
        },
      };

      // Save access token with TTL
      await this.env.OAUTH_KV.put(
        `token:${options.userId}:${grantId}:${accessTokenId}`,
        JSON.stringify(accessTokenData),
        { expirationTtl: accessTokenTTL }
      );

      // Build the redirect URL for implicit flow (token in fragment, not query params)
      const redirectUrl = new URL(options.request.redirectUri);
      const fragment = new URLSearchParams();
      fragment.set('access_token', accessToken);
      fragment.set('token_type', 'bearer');
      fragment.set('expires_in', accessTokenTTL.toString());
      fragment.set('scope', options.scope.join(' '));

      if (options.request.state) {
        fragment.set('state', options.request.state);
      }

      // Set the fragment (hash) part of the URL
      redirectUrl.hash = fragment.toString();

      return { redirectTo: redirectUrl.toString() };
    } else {
      // Standard authorization code flow
      // Generate an authorization code with embedded user and grant IDs
      const authCodeSecret = generateRandomString(32);
      const authCode = `${options.userId}:${grantId}:${authCodeSecret}`;

      // Hash the authorization code
      const authCodeId = await hashSecret(authCode);

      // Wrap the encryption key with the auth code
      const authCodeWrappedKey = await wrapKeyWithToken(authCode, encryptionKey);

      // Store the grant with the auth code hash
      const grant: Grant = {
        id: grantId,
        clientId: options.request.clientId,
        userId: options.userId,
        scope: options.scope,
        metadata: options.metadata,
        encryptedProps: encryptedData,
        createdAt: now,
        authCodeId: authCodeId, // Store the auth code hash in the grant
        authCodeWrappedKey: authCodeWrappedKey, // Store the wrapped key
        // Store PKCE parameters if provided
        codeChallenge: options.request.codeChallenge,
        codeChallengeMethod: options.request.codeChallengeMethod,
      };

      // Store the grant with a key that includes the user ID
      const grantKey = `grant:${options.userId}:${grantId}`;

      // Set 10-minute TTL for the grant (will be extended when code is exchanged)
      const codeExpiresIn = 600; // 10 minutes
      await this.env.OAUTH_KV.put(grantKey, JSON.stringify(grant), { expirationTtl: codeExpiresIn });

      // Build the redirect URL for authorization code flow
      const redirectUrl = new URL(options.request.redirectUri);
      redirectUrl.searchParams.set('code', authCode);
      if (options.request.state) {
        redirectUrl.searchParams.set('state', options.request.state);
      }

      return { redirectTo: redirectUrl.toString() };
    }
  }

  /**
   * Creates a new OAuth client
   * @param clientInfo - Partial client information to create the client with
   * @returns A Promise resolving to the created client info
   */
  async createClient(clientInfo: Partial<ClientInfo>): Promise<ClientInfo> {
    const clientId = generateRandomString(16);

    // Determine token endpoint auth method
    const tokenEndpointAuthMethod = clientInfo.tokenEndpointAuthMethod || 'client_secret_basic';
    const isPublicClient = tokenEndpointAuthMethod === 'none';

    // Create a new client object
    const newClient: ClientInfo = {
      clientId,
      redirectUris: clientInfo.redirectUris || [],
      clientName: clientInfo.clientName,
      logoUri: clientInfo.logoUri,
      clientUri: clientInfo.clientUri,
      policyUri: clientInfo.policyUri,
      tosUri: clientInfo.tosUri,
      jwksUri: clientInfo.jwksUri,
      contacts: clientInfo.contacts,
      grantTypes: clientInfo.grantTypes || ['authorization_code', 'refresh_token'],
      responseTypes: clientInfo.responseTypes || ['code'],
      registrationDate: Math.floor(Date.now() / 1000),
      tokenEndpointAuthMethod,
    };

    // Only generate and store client secret for confidential clients
    let clientSecret: string | undefined;
    if (!isPublicClient) {
      clientSecret = generateRandomString(32);
      // Hash the client secret
      newClient.clientSecret = await hashSecret(clientSecret);
    }

    await this.env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(newClient));

    // Create the response object
    const clientResponse = { ...newClient };

    // Return confidential clients with their unhashed secret
    if (!isPublicClient && clientSecret) {
      clientResponse.clientSecret = clientSecret; // Return original unhashed secret
    }

    return clientResponse;
  }

  /**
   * Lists all registered OAuth clients with pagination support
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with items and optional cursor
   */
  async listClients(options?: ListOptions): Promise<ListResult<ClientInfo>> {
    // Prepare list options for KV
    const listOptions: { limit?: number; cursor?: string; prefix: string } = {
      prefix: 'client:',
    };

    if (options?.limit !== undefined) {
      listOptions.limit = options.limit;
    }

    if (options?.cursor !== undefined) {
      listOptions.cursor = options.cursor;
    }

    // Use the KV list() function to get client keys with pagination
    const response = await this.env.OAUTH_KV.list(listOptions);

    // Fetch all clients in parallel
    const clients: ClientInfo[] = [];
    const promises = response.keys.map(async (key: { name: string }) => {
      const clientId = key.name.substring('client:'.length);
      const client = await this.provider.getClient(this.env, clientId);
      if (client) {
        clients.push(client);
      }
    });

    await Promise.all(promises);

    // Return result with cursor if there are more results
    return {
      items: clients,
      cursor: response.list_complete ? undefined : response.cursor,
    };
  }

  /**
   * Updates an existing OAuth client
   * @param clientId - The ID of the client to update
   * @param updates - Partial client information with fields to update
   * @returns A Promise resolving to the updated client info, or null if not found
   */
  async updateClient(clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null> {
    const client = await this.provider.getClient(this.env, clientId);
    if (!client) {
      return null;
    }

    // Determine token endpoint auth method
    let authMethod = updates.tokenEndpointAuthMethod || client.tokenEndpointAuthMethod || 'client_secret_basic';
    const isPublicClient = authMethod === 'none';

    // Handle changes in auth method
    let secretToStore = client.clientSecret;
    let originalSecret: string | undefined = undefined;

    if (isPublicClient) {
      // Public clients don't have secrets
      secretToStore = undefined;
    } else if (updates.clientSecret) {
      // For confidential clients, handle secret updates if provided
      originalSecret = updates.clientSecret;
      secretToStore = await hashSecret(updates.clientSecret);
    }

    const updatedClient: ClientInfo = {
      ...client,
      ...updates,
      clientId: client.clientId, // Ensure clientId doesn't change
      tokenEndpointAuthMethod: authMethod, // Use determined auth method
    };

    // Only include client secret for confidential clients
    if (!isPublicClient && secretToStore) {
      updatedClient.clientSecret = secretToStore;
    } else {
      delete updatedClient.clientSecret;
    }

    await this.env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(updatedClient));

    // Create a response object
    const response = { ...updatedClient };

    // For confidential clients, return unhashed secret if a new one was provided
    if (!isPublicClient && originalSecret) {
      response.clientSecret = originalSecret;
    }

    return response;
  }

  /**
   * Deletes an OAuth client
   * @param clientId - The ID of the client to delete
   * @returns A Promise resolving when the deletion is confirmed.
   */
  async deleteClient(clientId: string): Promise<void> {
    // Delete client
    await this.env.OAUTH_KV.delete(`client:${clientId}`);
  }

  /**
   * Lists all authorization grants for a specific user with pagination support
   * Returns a summary of each grant without sensitive information
   * @param userId - The ID of the user whose grants to list
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with grant summaries and optional cursor
   */
  async listUserGrants(userId: string, options?: ListOptions): Promise<ListResult<GrantSummary>> {
    // Prepare list options for KV
    const listOptions: { limit?: number; cursor?: string; prefix: string } = {
      prefix: `grant:${userId}:`,
    };

    if (options?.limit !== undefined) {
      listOptions.limit = options.limit;
    }

    if (options?.cursor !== undefined) {
      listOptions.cursor = options.cursor;
    }

    // Use the KV list() function to get grant keys with pagination
    const response = await this.env.OAUTH_KV.list(listOptions);

    // Fetch all grants in parallel and convert to grant summaries
    const grantSummaries: GrantSummary[] = [];
    const promises = response.keys.map(async (key: { name: string }) => {
      const grantData: Grant | null = await this.env.OAUTH_KV.get(key.name, { type: 'json' });
      if (grantData) {
        // Create a summary with only the public fields
        const summary: GrantSummary = {
          id: grantData.id,
          clientId: grantData.clientId,
          userId: grantData.userId,
          scope: grantData.scope,
          metadata: grantData.metadata,
          createdAt: grantData.createdAt,
        };
        grantSummaries.push(summary);
      }
    });

    await Promise.all(promises);

    // Return result with cursor if there are more results
    return {
      items: grantSummaries,
      cursor: response.list_complete ? undefined : response.cursor,
    };
  }

  /**
   * Revokes an authorization grant and all its associated access tokens
   * @param grantId - The ID of the grant to revoke
   * @param userId - The ID of the user who owns the grant
   * @returns A Promise resolving when the revocation is confirmed.
   */
  async revokeGrant(grantId: string, userId: string): Promise<void> {
    // Construct the full grant key with user ID
    const grantKey = `grant:${userId}:${grantId}`;

    // Delete all access tokens associated with this grant
    const tokenPrefix = `token:${userId}:${grantId}:`;

    // Handle pagination to ensure we delete all tokens even if there are more than 1000
    let cursor: string | undefined;
    let allTokensDeleted = false;

    // Continue fetching and deleting tokens until we've processed all of them
    while (!allTokensDeleted) {
      const listOptions: { prefix: string; cursor?: string } = {
        prefix: tokenPrefix,
      };

      if (cursor) {
        listOptions.cursor = cursor;
      }

      const result = await this.env.OAUTH_KV.list(listOptions);

      // Delete each token in this batch
      if (result.keys.length > 0) {
        await Promise.all(
          result.keys.map((key: { name: string }) => {
            return this.env.OAUTH_KV.delete(key.name);
          })
        );
      }

      // Check if we need to fetch more tokens
      if (result.list_complete) {
        allTokensDeleted = true;
      } else {
        cursor = result.cursor;
      }
    }

    // After all tokens are deleted, delete the grant itself
    await this.env.OAUTH_KV.delete(grantKey);
  }
}

/**
 * Default export of the OAuth provider
 * This allows users to import the library and use it directly as in the example
 */
export default OAuthProvider;
