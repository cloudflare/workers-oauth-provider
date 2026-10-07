import { describe, expect, it } from 'vitest';
import { findCoveringResource } from '../src/oauth-resource';

describe('findCoveringResource', () => {
  const mcp = 'https://mcp.example.com/mcp';

  it.each([
    ['adds a query to a resource without one', `${mcp}?codemode=false`, [mcp], mcp],
    ['adds several parameters', `${mcp}?codemode=false&truncate=false`, [mcp], mcp],
    ['keeps the resource query and adds one', `${mcp}?tenant=a&mode=x`, [`${mcp}?tenant=a`], `${mcp}?tenant=a`],
    ['prefers the most specific resource', `${mcp}?tenant=a&mode=x`, [mcp, `${mcp}?tenant=a`], `${mcp}?tenant=a`],
    ['ignores ASCII-insensitive host spelling via URL origin', 'https://MCP.example.com/mcp?x=1', [mcp], mcp],
  ])('%s', (_label, requested, configured, expected) => {
    expect(findCoveringResource(requested, configured)).toBe(expected);
  });

  it.each([
    ['has no query', mcp, [mcp]],
    ['changes the path', 'https://mcp.example.com/mcp/sub?x=1', [mcp]],
    ['changes the origin', 'https://evil.example.com/mcp?x=1', [mcp]],
    ['changes the port', 'https://mcp.example.com:8443/mcp?x=1', [mcp]],
    ['drops a resource query parameter', `${mcp}?mode=x`, [`${mcp}?tenant=a`]],
    ['changes a resource query value', `${mcp}?tenant=b`, [`${mcp}?tenant=a`]],
    ['is covered equally by two resources', `${mcp}?tenant=a&region=eu`, [`${mcp}?tenant=a`, `${mcp}?region=eu`]],
    ['is not a URL', 'not a url?x=1', [mcp]],
  ])('names no resource when the value %s', (_label, requested, configured) => {
    expect(findCoveringResource(requested, configured)).toBeUndefined();
  });
});
