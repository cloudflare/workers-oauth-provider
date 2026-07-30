export const MCP_AUTH_REVISIONS = [
  {
    version: '2025-03-26',
    authorizationUrl: 'https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization',
    resourceIndicators: false,
    protectedResourceMetadata: false,
    scopeChallenges: false,
    clientRegistrationChoices: false,
    authorizationResponseIssuer: false,
    offlineAccessGuidance: false,
  },
  {
    version: '2025-06-18',
    authorizationUrl: 'https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization',
    resourceIndicators: true,
    protectedResourceMetadata: true,
    scopeChallenges: false,
    clientRegistrationChoices: false,
    authorizationResponseIssuer: false,
    offlineAccessGuidance: false,
  },
  {
    version: '2025-11-25',
    authorizationUrl: 'https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization',
    resourceIndicators: true,
    protectedResourceMetadata: true,
    scopeChallenges: true,
    clientRegistrationChoices: true,
    authorizationResponseIssuer: false,
    offlineAccessGuidance: false,
  },
  {
    version: '2026-07-28',
    authorizationUrl: 'https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization',
    resourceIndicators: true,
    protectedResourceMetadata: true,
    scopeChallenges: true,
    clientRegistrationChoices: true,
    authorizationResponseIssuer: true,
    offlineAccessGuidance: true,
  },
] as const;

export type McpAuthRevision = (typeof MCP_AUTH_REVISIONS)[number];
export type McpAuthVersion = McpAuthRevision['version'];

export const MCP_PROTECTED_RESOURCE_REVISIONS = MCP_AUTH_REVISIONS.filter(
  (revision) => revision.protectedResourceMetadata
);

export const MCP_CLIENT_REGISTRATION_CHOICE_REVISIONS = MCP_AUTH_REVISIONS.filter(
  (revision) => revision.clientRegistrationChoices
);

export const MCP_SCOPE_CHALLENGE_REVISIONS = MCP_AUTH_REVISIONS.filter((revision) => revision.scopeChallenges);

export const MCP_AUTHORIZATION_RESPONSE_ISSUER_REVISIONS = MCP_AUTH_REVISIONS.filter(
  (revision) => revision.authorizationResponseIssuer
);

export const MCP_OFFLINE_ACCESS_GUIDANCE_REVISIONS = MCP_AUTH_REVISIONS.filter(
  (revision) => revision.offlineAccessGuidance
);

export function resourceForRevision(revision: McpAuthRevision): string | undefined {
  return revision.resourceIndicators ? 'https://mcp.example.com/mcp' : undefined;
}
