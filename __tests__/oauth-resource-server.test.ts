import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createOAuthResourceServer,
  type OAuthResourceServerOptions,
  type OAuthResourceTokenValidation,
} from '../src/oauth-resource-server';
import type { ExecutionContext } from '@cloudflare/workers-types';

const RESOURCE = 'https://mcp.example.com/mcp';
const METADATA_URL = 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp';

interface TestEnv {
  deployment: string;
}

interface TestProps {
  userId: string;
  scopes: string[];
}

class MockExecutionContext<Props = unknown> implements ExecutionContext<Props> {
  readonly exports = {} as Cloudflare.Exports;
  readonly tracing = {} as Tracing;
  props: Props;

  constructor(props: Props = undefined as Props) {
    this.props = props;
  }

  waitUntil(_promise: Promise<unknown>): void {}
  passThroughOnException(): void {}
}

function createTestServer(
  overrides: Partial<OAuthResourceServerOptions<TestEnv, TestProps>> = {}
): ReturnType<typeof createOAuthResourceServer<TestEnv, TestProps>> {
  return createOAuthResourceServer<TestEnv, TestProps>({
    resourceMetadata: {
      resource: RESOURCE,
      authorization_servers: ['https://auth.example.com'],
      scopes_supported: ['mcp:read'],
      resource_name: 'Example MCP',
    },
    validateToken: async () => ({
      props: { userId: 'user-123', scopes: ['mcp:read'] },
      audience: RESOURCE,
      expiresAt: Date.now() / 1000 + 300,
    }),
    handler: {
      fetch(_request, env, ctx) {
        return Response.json({ env: env.deployment, props: ctx.props });
      },
    },
    ...overrides,
  });
}

describe('createOAuthResourceServer', () => {
  const env: TestEnv = { deployment: 'resource-worker' };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('publishes path-aware RFC 9728 protected resource metadata', async () => {
    const server = createTestServer();
    const response = await server.fetch(new Request(METADATA_URL), env, new MockExecutionContext());

    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toMatch(/^application\/json\b/i);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    await expect(response.json()).resolves.toEqual({
      resource: RESOURCE,
      authorization_servers: ['https://auth.example.com'],
      scopes_supported: ['mcp:read'],
      bearer_methods_supported: ['header'],
      resource_name: 'Example MCP',
    });
  });

  it('omits an empty scopes_supported array from metadata', async () => {
    const server = createTestServer({
      resourceMetadata: {
        resource: RESOURCE,
        authorization_servers: ['https://auth.example.com'],
        scopes_supported: [],
      },
    });
    const response = await server.fetch(new Request(METADATA_URL), env, new MockExecutionContext());

    await expect(response.json()).resolves.not.toHaveProperty('scopes_supported');
  });

  it('deduplicates resource scopes and removes offline_access', async () => {
    const server = createTestServer({
      resourceMetadata: {
        resource: RESOURCE,
        authorization_servers: ['https://auth.example.com'],
        scopes_supported: ['mcp:read', 'offline_access', 'mcp:read'],
      },
    });
    const response = await server.fetch(new Request(METADATA_URL), env, new MockExecutionContext());

    await expect(response.json()).resolves.toMatchObject({ scopes_supported: ['mcp:read'] });
  });

  it('serves metadata only from the well-known URL derived from the canonical resource', async () => {
    const server = createTestServer();
    const ctx = new MockExecutionContext();

    for (const alias of [
      'https://other.example.com/.well-known/oauth-protected-resource/mcp',
      'https://mcp.example.com/.well-known/oauth-protected-resource',
      'https://mcp.example.com/.well-known/oauth-protected-resource/other',
    ]) {
      expect((await server.fetch(new Request(alias), env, ctx)).status).toBe(404);
    }
  });

  it('challenges an unauthenticated request to the canonical resource with its metadata URL', async () => {
    const server = createTestServer();
    const response = await server.fetch(new Request(RESOURCE), env, new MockExecutionContext());

    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toBe(`Bearer realm="OAuth", resource_metadata="${METADATA_URL}"`);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('Pragma')).toBe('no-cache');
  });

  it('does not advertise mismatched canonical metadata from a descendant challenge', async () => {
    const server = createTestServer();
    const response = await server.fetch(new Request(`${RESOURCE}/tools`), env, new MockExecutionContext());

    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toBe('Bearer realm="OAuth"');
  });

  it('validates a bearer token and exposes validator props to the protected handler', async () => {
    const request = new Request(`${RESOURCE}/tools`, {
      headers: { Authorization: 'Bearer opaque-access-token' },
    });
    const validateToken = vi.fn(
      async (): Promise<OAuthResourceTokenValidation<TestProps>> => ({
        props: { userId: 'validated-user', scopes: ['mcp:read'] },
        audience: RESOURCE,
        expiresAt: Date.now() / 1000 + 60,
      })
    );
    const server = createTestServer({ validateToken });
    const ctx = new MockExecutionContext<TestProps>();

    const response = await server.fetch(request, env, ctx);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      env: 'resource-worker',
      props: { userId: 'validated-user', scopes: ['mcp:read'] },
    });
    expect(ctx.props).toEqual({ userId: 'validated-user', scopes: ['mcp:read'] });
    expect(validateToken).toHaveBeenCalledWith({ token: 'opaque-access-token', request, env });
  });

  it('preserves handler CORS exposure and varies reflected origins', async () => {
    const server = createTestServer({
      handler: {
        fetch() {
          return new Response('ok', {
            headers: {
              'Access-Control-Expose-Headers': 'X-MCP-Result',
              Vary: 'Accept-Encoding',
            },
          });
        },
      },
    });
    const response = await server.fetch(
      new Request(RESOURCE, {
        headers: {
          Authorization: 'Bearer valid-token',
          Origin: 'https://client.example.com',
        },
      }),
      env,
      new MockExecutionContext()
    );

    expect(response.headers.get('Access-Control-Expose-Headers')).toBe('X-MCP-Result, WWW-Authenticate, Retry-After');
    expect(response.headers.get('Vary')).toBe('Accept-Encoding, Origin');
  });

  it('accepts a case-insensitive Bearer scheme', async () => {
    const validateToken = vi.fn(async () => ({
      props: { userId: 'user-123', scopes: [] },
      audience: RESOURCE,
    }));
    const server = createTestServer({ validateToken });

    const response = await server.fetch(
      new Request(RESOURCE, { headers: { Authorization: 'bearer token-value' } }),
      env,
      new MockExecutionContext()
    );

    expect(response.status).toBe(200);
    expect(validateToken).toHaveBeenCalledOnce();
  });

  it('rejects a token whose validated audience is not the exact canonical resource', async () => {
    const handler = { fetch: vi.fn(() => new Response('should not run')) };
    const server = createTestServer({
      handler,
      validateToken: async () => ({
        props: { userId: 'user-123', scopes: [] },
        audience: `${RESOURCE}/other`,
      }),
    });

    const response = await server.fetch(
      new Request(RESOURCE, { headers: { Authorization: 'Bearer wrong-audience' } }),
      env,
      new MockExecutionContext()
    );

    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');
    expect(handler.fetch).not.toHaveBeenCalled();
  });

  it.each([
    ['expired', 1_999_999_999],
    ['invalid', Number.NaN],
  ])('rejects a token with an %s expiresAt value', async (_label, expiresAt) => {
    vi.spyOn(Date, 'now').mockReturnValue(2_000_000_000_000);
    const server = createTestServer({
      validateToken: async () => ({
        props: { userId: 'user-123', scopes: [] },
        audience: RESOURCE,
        expiresAt,
      }),
    });

    const response = await server.fetch(
      new Request(RESOURCE, { headers: { Authorization: 'Bearer expired-token' } }),
      env,
      new MockExecutionContext()
    );

    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');
  });

  it('returns invalid_token when the validator rejects a token', async () => {
    const handler = { fetch: vi.fn(() => new Response('should not run')) };
    const server = createTestServer({ handler, validateToken: async () => null });

    const response = await server.fetch(
      new Request(RESOURCE, { headers: { Authorization: 'Bearer untrusted-token' } }),
      env,
      new MockExecutionContext()
    );

    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');
    expect(handler.fetch).not.toHaveBeenCalled();
  });

  it('returns an uncacheable 503 without invalid_token when validation infrastructure fails', async () => {
    const handler = { fetch: vi.fn(() => new Response('should not run')) };
    const server = createTestServer({
      handler,
      validateToken: async () => {
        throw new Error('introspection unavailable');
      },
    });

    const response = await server.fetch(
      new Request(RESOURCE, { headers: { Authorization: 'Bearer untrusted-token' } }),
      env,
      new MockExecutionContext()
    );

    expect(response.status).toBe(503);
    expect(response.headers.get('WWW-Authenticate')).toBeNull();
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('Pragma')).toBe('no-cache');
    expect(handler.fetch).not.toHaveBeenCalled();
  });

  it('routes only the canonical resource and path-boundary descendants', async () => {
    const validateToken = vi.fn(async () => ({
      props: { userId: 'user-123', scopes: [] },
      audience: RESOURCE,
    }));
    const server = createTestServer({ validateToken });
    const ctx = new MockExecutionContext();

    for (const outside of [
      'https://mcp.example.com/',
      'https://mcp.example.com/mcp-other',
      'https://other.example.com/mcp',
    ]) {
      expect(
        (await server.fetch(new Request(outside, { headers: { Authorization: 'Bearer token' } }), env, ctx)).status
      ).toBe(404);
    }
    expect(validateToken).not.toHaveBeenCalled();
  });

  it('answers CORS preflight without validating a token', async () => {
    const validateToken = vi.fn(async () => null);
    const server = createTestServer({ validateToken });
    const response = await server.fetch(
      new Request(RESOURCE, {
        method: 'OPTIONS',
        headers: { Origin: 'https://client.example.com' },
      }),
      env,
      new MockExecutionContext()
    );

    expect(response.status).toBe(204);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://client.example.com');
    expect(response.headers.get('Access-Control-Allow-Headers')).toBe('Authorization, *');
    expect(validateToken).not.toHaveBeenCalled();
  });

  it('requires canonical resource metadata and at least one authorization server', () => {
    expect(() =>
      createTestServer({
        resourceMetadata: {
          resource: 'http://mcp.example.com/mcp',
          authorization_servers: ['https://auth.example.com'],
        },
      })
    ).toThrow('resourceMetadata.resource');

    for (const resource of ['https://mcp.example.com/x|y', 'https://mcp.example.com/x^y']) {
      expect(() =>
        createTestServer({
          resourceMetadata: {
            resource,
            authorization_servers: ['https://auth.example.com'],
          },
        })
      ).toThrow('resourceMetadata.resource');
    }

    expect(() =>
      createTestServer({
        resourceMetadata: {
          resource: RESOURCE,
          authorization_servers: [],
        },
      })
    ).toThrow('resourceMetadata.authorization_servers must contain at least one issuer');

    expect(() =>
      createTestServer({
        resourceMetadata: {
          resource: RESOURCE,
          authorization_servers: ['https://auth.example.com?tenant=a'],
        },
      })
    ).toThrow('resourceMetadata.authorization_servers must contain canonical HTTPS issuer URLs');
  });
});
