import { MCP_RESOURCE } from './shared';

export const MCP_AUTH_REVISIONS = ['2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28'] as const;

export type McpAuthRevision = (typeof MCP_AUTH_REVISIONS)[number];

export function mcpAuthRevisionsSince(first: McpAuthRevision): readonly McpAuthRevision[] {
  return MCP_AUTH_REVISIONS.slice(MCP_AUTH_REVISIONS.indexOf(first));
}

export function clientResourceForRevision(revision: McpAuthRevision): string | undefined {
  return mcpAuthRevisionsSince('2025-06-18').includes(revision) ? MCP_RESOURCE : undefined;
}
