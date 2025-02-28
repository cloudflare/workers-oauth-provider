// my-oauth.ts

// Types

/**
 * Configuration options for the OAuth Provider
 */
export interface OAuthProviderOptions {
  /**
   * Base URL for API routes. Requests with URLs starting with this prefix
   * will be treated as API requests and require a valid access token.
   */
  apiRoute: string;

  /**
   * Handler function for API requests that have a valid access token.
   * This function receives the authenticated user properties along with the request.
   */
  apiHandler: ApiHandler;

  /**
   * Handler function for all non-API requests or API requests without a valid token.
   */
  defaultHandler: DefaultHandler;

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
   * Time-to-live for refresh tokens in seconds.
   * Defaults to 30 days (2592000 seconds) if not specified.
   */
  refreshTokenTTL?: number;
}

/**
 * Handler function type for authenticated API requests
 * @param request - The original HTTP request
 * @param env - Cloudflare Worker environment variables
 * @param ctx - Cloudflare Worker execution context
 * @param oauth - Helper methods for OAuth operations
 * @param props - User-specific properties from the authorization grant
 * @returns A Promise resolving to an HTTP Response
 */
export interface ApiHandler {
  (request: Request, env: any, ctx: ExecutionContext, oauth: OAuthHelpers, props: any): Promise<Response>;
}

/**
 * Handler function type for non-API or unauthenticated requests
 * @param request - The original HTTP request
 * @param env - Cloudflare Worker environment variables
 * @param ctx - Cloudflare Worker execution context
 * @param oauth - Helper methods for OAuth operations
 * @returns A Promise resolving to an HTTP Response
 */
export interface DefaultHandler {
  (request: Request, env: any, ctx: ExecutionContext, oauth: OAuthHelpers): Promise<Response>;
}

/**
 * Helper methods for OAuth operations provided to handler functions
 */
export interface OAuthHelpers {
  /**
   * Parses an OAuth authorization request from the HTTP request
   * @param request - The HTTP request containing OAuth parameters
   * @returns The parsed authorization request parameters
   */
  parseAuthRequest(request: Request): AuthRequest;

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
   * Lists all registered OAuth clients
   * @returns A Promise resolving to an array of client information
   */
  listClients(): Promise<ClientInfo[]>;

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
   * @returns A Promise resolving to true if successful, false otherwise
   */
  deleteClient(clientId: string): Promise<boolean>;

  /**
   * Lists all authorization grants for a specific user
   * @param userId - The ID of the user whose grants to list
   * @returns A Promise resolving to an array of grant information
   */
  listUserGrants(userId: string): Promise<Grant[]>;

  /**
   * Revokes an authorization grant
   * @param grantId - The ID of the grant to revoke
   * @returns A Promise resolving to true if successful, false otherwise
   */
  revokeGrant(grantId: string): Promise<boolean>;
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
   */
  clientSecret: string;

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

  /**
   * Optional custom expiration time in seconds for the tokens
   */
  expiresIn?: number;
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
   * Application-specific properties included with API requests
   */
  props: any;

  /**
   * Unix timestamp when the grant was created
   */
  createdAt: number;
}

/**
 * Token record stored in KV
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
   * Type of token (access or refresh)
   */
  type: 'access' | 'refresh';

  /**
   * Unix timestamp when the token was created
   */
  createdAt: number;

  /**
   * Unix timestamp when the token expires
   */
  expiresAt: number;
}

// Constants
const DEFAULT_ACCESS_TOKEN_TTL = 60 * 60; // 1 hour
const DEFAULT_REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60; // 30 days
const TOKEN_LENGTH = 32;

async function hashSecret(secret: string): Promise<string> {
  // Use the same approach as generateTokenId for consistency
  return generateTokenId(secret);
}

// Helper Functions
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

async function generateTokenId(token: string): Promise<string> {
  // Convert the token string to a Uint8Array
  const encoder = new TextEncoder();
  const data = encoder.encode(token);

  // Use the WebCrypto API to create a SHA-256 hash
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  // Convert the hash to a hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return hashHex;
}

function base64UrlEncode(str: string): string {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * OAuth 2.0 Provider implementation for Cloudflare Workers
 * Implements authorization code flow with support for refresh tokens
 * and dynamic client registration.
 */
export class OAuthProvider {
  /**
   * Configuration options for the provider
   */
  private options: OAuthProviderOptions;

  /**
   * Creates a new OAuth provider instance
   * @param options - Configuration options for the provider
   */
  constructor(options: OAuthProviderOptions) {
    this.options = {
      ...options,
      accessTokenTTL: options.accessTokenTTL || DEFAULT_ACCESS_TOKEN_TTL,
      refreshTokenTTL: options.refreshTokenTTL || DEFAULT_REFRESH_TOKEN_TTL
    };
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

    // Handle .well-known/oauth-authorization-server
    if (url.pathname === '/.well-known/oauth-authorization-server') {
      return this.handleMetadataDiscovery();
    }

    // Handle token endpoint
    if (this.isTokenEndpoint(url)) {
      return this.handleTokenRequest(request, env);
    }

    // Handle client registration endpoint
    if (this.options.clientRegistrationEndpoint &&
        this.isClientRegistrationEndpoint(url)) {
      return this.handleClientRegistration(request, env);
    }

    // Check if it's an API request
    if (this.isApiRequest(url)) {
      return this.handleApiRequest(request, env, ctx);
    }

    // Default handler for all other requests
    return this.options.defaultHandler(request, env, ctx, this.createOAuthHelpers(env));
  }

  /**
   * Checks if a URL matches the configured token endpoint
   * @param url - The URL to check
   * @returns True if the URL matches the token endpoint
   */
  private isTokenEndpoint(url: URL): boolean {
    const tokenUrl = new URL(this.options.tokenEndpoint);
    return url.pathname === tokenUrl.pathname;
  }

  /**
   * Checks if a URL matches the configured client registration endpoint
   * @param url - The URL to check
   * @returns True if the URL matches the client registration endpoint
   */
  private isClientRegistrationEndpoint(url: URL): boolean {
    if (!this.options.clientRegistrationEndpoint) return false;
    const registrationUrl = new URL(this.options.clientRegistrationEndpoint);
    return url.pathname === registrationUrl.pathname;
  }

  /**
   * Checks if a URL is an API request based on the configured API route
   * @param url - The URL to check
   * @returns True if the URL is an API request
   */
  private isApiRequest(url: URL): boolean {
    const apiUrl = new URL(this.options.apiRoute);
    return url.href.startsWith(apiUrl.href);
  }

  /**
   * Handles the OAuth metadata discovery endpoint
   * Implements RFC 8414 for OAuth Server Metadata
   * @returns Response with OAuth server metadata
   */
  private async handleMetadataDiscovery(): Promise<Response> {
    const metadata = {
      issuer: new URL(this.options.tokenEndpoint).origin,
      authorization_endpoint: this.options.authorizeEndpoint,
      token_endpoint: this.options.tokenEndpoint,
      registration_endpoint: this.options.clientRegistrationEndpoint,
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      response_types_supported: ["code"],
      scopes_supported: [], // This could be configured in the future
      response_modes_supported: ["query"],
      revocation_endpoint: this.options.tokenEndpoint, // Reusing token endpoint for revocation
    };

    return new Response(JSON.stringify(metadata), {
      headers: { 'Content-Type': 'application/json' }
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
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Method not allowed'
      }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    let contentType = request.headers.get('Content-Type') || '';
    let body: any = {};

    if (contentType.includes('application/json')) {
      body = await request.json();
    } else {
      // Assume application/x-www-form-urlencoded
      const formData = await request.formData();
      for (const [key, value] of formData.entries()) {
        body[key] = value;
      }
    }

    // Authenticate client
    const authHeader = request.headers.get('Authorization');
    let clientId = '';
    let clientSecret = '';

    if (authHeader && authHeader.startsWith('Basic ')) {
      // Basic auth
      const credentials = atob(authHeader.substring(6));
      const [id, secret] = credentials.split(':');
      clientId = id;
      clientSecret = secret;
    } else {
      // Form parameters
      clientId = body.client_id;
      clientSecret = body.client_secret;
    }

    if (!clientId || !clientSecret) {
      return new Response(JSON.stringify({
        error: 'invalid_client',
        error_description: 'Client authentication failed'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify client
    const clientInfo = await this.getClient(env, clientId);
    if (!clientInfo) {
      return new Response(JSON.stringify({
        error: 'invalid_client',
        error_description: 'Client not found'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Hash the provided secret and compare with stored hash
    const providedSecretHash = await hashSecret(clientSecret);
    if (providedSecretHash !== clientInfo.clientSecret) {
      return new Response(JSON.stringify({
        error: 'invalid_client',
        error_description: 'Client authentication failed'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Handle different grant types
    const grantType = body.grant_type;

    if (grantType === 'authorization_code') {
      return this.handleAuthorizationCodeGrant(body, clientInfo, env);
    } else if (grantType === 'refresh_token') {
      return this.handleRefreshTokenGrant(body, clientInfo, env);
    } else {
      return new Response(JSON.stringify({
        error: 'unsupported_grant_type',
        error_description: 'Grant type not supported'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
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
  private async handleAuthorizationCodeGrant(
    body: any,
    clientInfo: ClientInfo,
    env: any
  ): Promise<Response> {
    const code = body.code;
    const redirectUri = body.redirect_uri;

    if (!code) {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Authorization code is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify redirect URI is in the allowed list
    if (redirectUri && !clientInfo.redirectUris.includes(redirectUri)) {
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Invalid redirect URI'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify the code and get the grant
    try {
      // Hash the auth code before lookup
      const codeHash = await hashSecret(code);
      const codeKey = `auth_code:${codeHash}`;
      const grantId = await env.OAUTH_KV.get(codeKey);

      if (!grantId) {
        throw new Error('Invalid or expired code');
      }

      // Delete the code so it can't be used again
      await env.OAUTH_KV.delete(codeKey);

      // Get the grant
      const grantKey = `grant:${grantId}`;
      const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });

      if (!grantData) {
        throw new Error('Grant not found');
      }

      // Verify client ID matches
      if (grantData.clientId !== clientInfo.clientId) {
        throw new Error('Client ID mismatch');
      }

      // Generate tokens
      const accessToken = generateRandomString(TOKEN_LENGTH);
      const refreshToken = generateRandomString(TOKEN_LENGTH);

      // Use WebCrypto to generate token IDs
      const accessTokenId = await generateTokenId(accessToken);
      const refreshTokenId = await generateTokenId(refreshToken);

      const now = Math.floor(Date.now() / 1000);
      const accessTokenExpiresAt = now + this.options.accessTokenTTL!;
      const refreshTokenExpiresAt = now + this.options.refreshTokenTTL!;

      // Store access token
      const accessTokenData: Token = {
        id: accessTokenId,
        grantId: grantId,
        type: 'access',
        createdAt: now,
        expiresAt: accessTokenExpiresAt
      };

      // Store refresh token
      const refreshTokenData: Token = {
        id: refreshTokenId,
        grantId: grantId,
        type: 'refresh',
        createdAt: now,
        expiresAt: refreshTokenExpiresAt
      };

      // Save tokens with TTL
      await env.OAUTH_KV.put(
        `token:${accessTokenId}`,
        JSON.stringify(accessTokenData),
        { expirationTtl: this.options.accessTokenTTL }
      );

      await env.OAUTH_KV.put(
        `token:${refreshTokenId}`,
        JSON.stringify(refreshTokenData),
        { expirationTtl: this.options.refreshTokenTTL }
      );

      // Return the tokens
      return new Response(JSON.stringify({
        access_token: accessToken,
        token_type: 'bearer',
        expires_in: this.options.accessTokenTTL,
        refresh_token: refreshToken,
        scope: grantData.scope.join(' ')
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: error instanceof Error ? error.message : 'Invalid authorization code'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  /**
   * Handles the refresh token grant type
   * Issues a new access token using a refresh token
   * @param body - The parsed request body
   * @param clientInfo - The authenticated client information
   * @param env - Cloudflare Worker environment variables
   * @returns Response with token data or error
   */
  private async handleRefreshTokenGrant(
    body: any,
    clientInfo: ClientInfo,
    env: any
  ): Promise<Response> {
    const refreshToken = body.refresh_token;

    if (!refreshToken) {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Refresh token is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      // Get refresh token from storage
      const refreshTokenId = await generateTokenId(refreshToken);
      const tokenKey = `token:${refreshTokenId}`;
      const tokenData = await env.OAUTH_KV.get(tokenKey, { type: 'json' });

      if (!tokenData || tokenData.type !== 'refresh') {
        throw new Error('Invalid refresh token');
      }

      // Get the associated grant
      const grantKey = `grant:${tokenData.grantId}`;
      const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });

      if (!grantData) {
        throw new Error('Grant not found');
      }

      // Verify client ID matches
      if (grantData.clientId !== clientInfo.clientId) {
        throw new Error('Client ID mismatch');
      }

      // Generate new access token
      const newAccessToken = generateRandomString(TOKEN_LENGTH);
      const accessTokenId = await generateTokenId(newAccessToken);

      const now = Math.floor(Date.now() / 1000);
      const accessTokenExpiresAt = now + this.options.accessTokenTTL!;

      // Store new access token
      const accessTokenData: Token = {
        id: accessTokenId,
        grantId: tokenData.grantId,
        type: 'access',
        createdAt: now,
        expiresAt: accessTokenExpiresAt
      };

      await env.OAUTH_KV.put(
        `token:${accessTokenId}`,
        JSON.stringify(accessTokenData),
        { expirationTtl: this.options.accessTokenTTL }
      );

      // Return the new access token
      return new Response(JSON.stringify({
        access_token: newAccessToken,
        token_type: 'bearer',
        expires_in: this.options.accessTokenTTL,
        scope: grantData.scope.join(' ')
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: error instanceof Error ? error.message : 'Invalid refresh token'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  /**
   * Handles the dynamic client registration endpoint (RFC 7591)
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @returns Response with client registration data or error
   */
  private async handleClientRegistration(request: Request, env: any): Promise<Response> {
    if (!this.options.clientRegistrationEndpoint) {
      return new Response(JSON.stringify({
        error: 'not_implemented',
        error_description: 'Client registration is not enabled'
      }), {
        status: 501,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check method
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Method not allowed'
      }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      // Parse client metadata
      const clientMetadata = await request.json();

      // Validate redirect URIs
      if (!clientMetadata.redirect_uris || !Array.isArray(clientMetadata.redirect_uris) || clientMetadata.redirect_uris.length === 0) {
        return new Response(JSON.stringify({
          error: 'invalid_redirect_uri',
          error_description: 'At least one redirect URI is required'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // Create client
      const clientId = generateRandomString(16);
      const clientSecret = generateRandomString(32);

      // Hash the client secret before storing
      const hashedSecret = await hashSecret(clientSecret);

      const clientInfo: ClientInfo = {
        clientId,
        clientSecret: hashedSecret, // Store the hashed secret
        redirectUris: clientMetadata.redirect_uris,
        clientName: clientMetadata.client_name,
        logoUri: clientMetadata.logo_uri,
        clientUri: clientMetadata.client_uri,
        policyUri: clientMetadata.policy_uri,
        tosUri: clientMetadata.tos_uri,
        jwksUri: clientMetadata.jwks_uri,
        contacts: clientMetadata.contacts,
        grantTypes: clientMetadata.grant_types || ['authorization_code', 'refresh_token'],
        responseTypes: clientMetadata.response_types || ['code'],
        registrationDate: Math.floor(Date.now() / 1000)
      };

      // Store client info
      await env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(clientInfo));

      // Return client information with the original unhashed secret
      const response = {
        client_id: clientInfo.clientId,
        client_secret: clientSecret, // Return the original unhashed secret
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
        registration_client_uri: `${this.options.clientRegistrationEndpoint}/${clientId}`,
        client_id_issued_at: clientInfo.registrationDate,
      };

      return new Response(JSON.stringify(response), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Invalid client metadata'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
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
      return new Response(JSON.stringify({
        error: 'invalid_token',
        error_description: 'Missing or invalid access token'
      }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token"'
        }
      });
    }

    const accessToken = authHeader.substring(7);

    try {
      // Verify token and get associated grant
      const accessTokenId = await generateTokenId(accessToken);
      const tokenKey = `token:${accessTokenId}`;
      const tokenData = await env.OAUTH_KV.get(tokenKey, { type: 'json' });

      if (!tokenData || tokenData.type !== 'access') {
        throw new Error('Invalid access token');
      }

      // Check if token is expired (should be auto-deleted by KV TTL, but double-check)
      const now = Math.floor(Date.now() / 1000);
      if (tokenData.expiresAt < now) {
        throw new Error('Access token expired');
      }

      // Get the associated grant
      const grantKey = `grant:${tokenData.grantId}`;
      const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });

      if (!grantData) {
        throw new Error('Grant not found');
      }

      // Call the API handler with the grant props
      return this.options.apiHandler(
        request,
        env,
        ctx,
        this.createOAuthHelpers(env),
        grantData.props
      );
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'invalid_token',
        error_description: error instanceof Error ? error.message : 'Invalid access token'
      }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token"'
        }
      });
    }
  }

  /**
   * Fetches client information from KV storage
   * @param env - Cloudflare Worker environment variables
   * @param clientId - The client ID to look up
   * @returns The client information, or null if not found
   */
  private async getClient(env: any, clientId: string): Promise<ClientInfo | null> {
    try {
      const clientKey = `client:${clientId}`;
      const clientData = await env.OAUTH_KV.get(clientKey, { type: 'json' });
      return clientData;
    } catch (error) {
      return null;
    }
  }

  /**
   * Creates the helper methods object for OAuth operations
   * This is passed to the handler functions to allow them to interact with the OAuth system
   * @param env - Cloudflare Worker environment variables
   * @returns An object containing OAuth helper methods
   */
  private createOAuthHelpers(env: any): OAuthHelpers {
    return {
      /**
       * Parses an OAuth authorization request from the HTTP request
       * @param request - The HTTP request containing OAuth parameters
       * @returns The parsed authorization request parameters
       */
      parseAuthRequest: (request: Request): AuthRequest => {
        const url = new URL(request.url);
        const responseType = url.searchParams.get('response_type') || '';
        const clientId = url.searchParams.get('client_id') || '';
        const redirectUri = url.searchParams.get('redirect_uri') || '';
        const scope = (url.searchParams.get('scope') || '').split(' ').filter(Boolean);
        const state = url.searchParams.get('state') || '';

        return {
          responseType,
          clientId,
          redirectUri,
          scope,
          state
        };
      },

      /**
       * Looks up a client by its client ID
       * @param clientId - The client ID to look up
       * @returns A Promise resolving to the client info, or null if not found
       */
      lookupClient: async (clientId: string): Promise<ClientInfo | null> => {
        return await this.getClient(env, clientId);
      },

      /**
       * Completes an authorization request by creating a grant and authorization code
       * @param options - Options specifying the grant details
       * @returns A Promise resolving to an object containing the redirect URL
       */
      completeAuthorization: async (options: CompleteAuthorizationOptions): Promise<{ redirectTo: string }> => {
        // Generate a random authorization code
        const code = generateRandomString(32);

        // Generate a unique grant ID
        const grantId = generateRandomString(16);

        // Store the grant
        const grant: Grant = {
          id: grantId,
          clientId: options.request.clientId,
          userId: options.userId,
          scope: options.scope,
          metadata: options.metadata,
          props: options.props,
          createdAt: Math.floor(Date.now() / 1000)
        };

        // Store the grant with long TTL (or no expiry)
        await env.OAUTH_KV.put(`grant:${grantId}`, JSON.stringify(grant));

        // Also store in user's grants list
        await this.updateUserGrantsList(env, options.userId, grantId);

        // Hash the authorization code before storing
        const codeHash = await hashSecret(code);

        // Store the authorization code with short TTL (10 minutes)
        const codeExpiresIn = 600; // 10 minutes
        await env.OAUTH_KV.put(`auth_code:${codeHash}`, grantId, { expirationTtl: codeExpiresIn });

        // Build the redirect URL
        const redirectUrl = new URL(options.request.redirectUri);
        redirectUrl.searchParams.set('code', code);
        if (options.request.state) {
          redirectUrl.searchParams.set('state', options.request.state);
        }

        return { redirectTo: redirectUrl.toString() };
      },

      /**
       * Creates a new OAuth client
       * @param clientInfo - Partial client information to create the client with
       * @returns A Promise resolving to the created client info
       */
      createClient: async (clientInfo: Partial<ClientInfo>): Promise<ClientInfo> => {
        const clientId = generateRandomString(16);
        const clientSecret = generateRandomString(32);

        // Hash the client secret
        const hashedSecret = await hashSecret(clientSecret);

        const newClient: ClientInfo = {
          clientId,
          clientSecret: hashedSecret, // Store hashed secret
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
          registrationDate: Math.floor(Date.now() / 1000)
        };

        await env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(newClient));

        // Return client with unhashed secret
        const clientResponse = {
          ...newClient,
          clientSecret // Return original unhashed secret
        };

        return clientResponse;
      },

      /**
       * Lists all registered OAuth clients
       * @returns A Promise resolving to an array of client information
       */
      listClients: async (): Promise<ClientInfo[]> => {
        // Use the KV list() function to get all client keys with the prefix 'client:'
        const { keys } = await env.OAUTH_KV.list({ prefix: 'client:' });

        // Fetch all clients in parallel
        const clients: ClientInfo[] = [];
        const promises = keys.map(async (key: { name: string }) => {
          const clientId = key.name.substring('client:'.length);
          const client = await this.getClient(env, clientId);
          if (client) {
            clients.push(client);
          }
        });

        await Promise.all(promises);
        return clients;
      },

      /**
       * Updates an existing OAuth client
       * @param clientId - The ID of the client to update
       * @param updates - Partial client information with fields to update
       * @returns A Promise resolving to the updated client info, or null if not found
       */
      updateClient: async (clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null> => {
        const client = await this.getClient(env, clientId);
        if (!client) {
          return null;
        }

        // Handle secret updates - if a new secret is provided, hash it
        let secretToStore = client.clientSecret;
        let originalSecret: string | undefined = undefined;

        if (updates.clientSecret) {
          originalSecret = updates.clientSecret;
          secretToStore = await hashSecret(updates.clientSecret);
        }

        const updatedClient: ClientInfo = {
          ...client,
          ...updates,
          clientId: client.clientId, // Ensure clientId doesn't change
          clientSecret: secretToStore // Use hashed secret
        };

        await env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(updatedClient));

        // Return client with unhashed secret if a new one was provided
        if (originalSecret) {
          return {
            ...updatedClient,
            clientSecret: originalSecret
          };
        }

        return updatedClient;
      },

      /**
       * Deletes an OAuth client
       * @param clientId - The ID of the client to delete
       * @returns A Promise resolving to true if successful, false otherwise
       */
      deleteClient: async (clientId: string): Promise<boolean> => {
        try {
          // Delete client
          await env.OAUTH_KV.delete(`client:${clientId}`);
          return true;
        } catch (error) {
          return false;
        }
      },

      /**
       * Lists all authorization grants for a specific user
       * @param userId - The ID of the user whose grants to list
       * @returns A Promise resolving to an array of grant information
       */
      listUserGrants: async (userId: string): Promise<Grant[]> => {
        const userGrantsKey = `user_grants:${userId}`;
        const grantIds = await env.OAUTH_KV.get(userGrantsKey, { type: 'json' }) || [];

        const grants: Grant[] = [];
        for (const grantId of grantIds) {
          const grantKey = `grant:${grantId}`;
          const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });
          if (grantData) {
            grants.push(grantData);
          }
        }

        return grants;
      },

      /**
       * Revokes an authorization grant
       * @param grantId - The ID of the grant to revoke
       * @returns A Promise resolving to true if successful, false otherwise
       */
      revokeGrant: async (grantId: string): Promise<boolean> => {
        try {
          // Get grant to find user ID
          const grantKey = `grant:${grantId}`;
          const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });

          if (!grantData) {
            return false;
          }

          // Delete grant
          await env.OAUTH_KV.delete(grantKey);

          // Update user's grants list
          const userId = grantData.userId;
          const userGrantsKey = `user_grants:${userId}`;
          const userGrants = await env.OAUTH_KV.get(userGrantsKey, { type: 'json' }) || [];
          const updatedGrants = userGrants.filter((id: string) => id !== grantId);
          await env.OAUTH_KV.put(userGrantsKey, JSON.stringify(updatedGrants));

          // Note: We don't need to delete tokens as they'll expire via TTL

          return true;
        } catch (error) {
          return false;
        }
      }
    };
  }

  /**
   * Updates the list of grant IDs for a user in KV storage
   * @param env - Cloudflare Worker environment variables
   * @param userId - The user ID to update grants for
   * @param grantId - The grant ID to add to the user's list
   */
  private async updateUserGrantsList(env: any, userId: string, grantId: string): Promise<void> {
    try {
      const userGrantsKey = `user_grants:${userId}`;
      const userGrants = await env.OAUTH_KV.get(userGrantsKey, { type: 'json' }) || [];

      if (!userGrants.includes(grantId)) {
        userGrants.push(grantId);
        await env.OAUTH_KV.put(userGrantsKey, JSON.stringify(userGrants));
      }
    } catch (error) {
      // If this fails, it's not critical
      console.error('Failed to update user grants list:', error);
    }
  }
}

/**
 * Default export of the OAuth provider
 * This allows users to import the library and use it directly as in the example
 */
export default OAuthProvider;