export const CONFORMANCE_ORIGIN = 'https://mcp.example.com';
export const MCP_RESOURCE = `${CONFORMANCE_ORIGIN}/mcp`;
export const CLIENT_REDIRECT_URI = 'https://client.example.com/callback';
export const READ_SCOPE = 'mcp:read';
export const WRITE_SCOPE = 'mcp:write';
export const OFFLINE_ACCESS_SCOPE = 'offline_access';
export const INSUFFICIENT_SCOPE_TOKEN = 'valid-upstream-token-with-too-little-scope';
export const DENIED_SCOPE = 'conformance:deny';

export type TokenEndpointAuthMethod = 'none' | 'client_secret_basic' | 'client_secret_post';

export interface WorkerConfiguration {
  dynamicClientRegistration: boolean;
  origin: string;
  resource?: string;
  resourceScopes: string[];
}

export interface OAuthClientCredentials {
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
}
