import { afterEach, describe, expect, it, vi } from 'vitest';
import { WorkerEntrypoint } from 'cloudflare:workers';
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
    validateToken: () => async () => ({
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

  it('advertises the canonical metadata from a descendant challenge', async () => {
    const server = createTestServer();
    const response = await server.fetch(new Request(`${RESOURCE}/tools`), env, new MockExecutionContext());

    // RFC 9728 §5.1: the canonical path is the base audience for its descendants, so a
    // 401 at /mcp/tools still points the client at the one canonical document.
    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toBe(`Bearer realm="OAuth", resource_metadata="${METADATA_URL}"`);
  });

  it('hosts a WorkerEntrypoint class as the handler, like the combined provider does', async () => {
    class CalendarHandler extends WorkerEntrypoint<TestEnv> {
      fetch(request: Request) {
        return Response.json({
          path: new URL(request.url).pathname,
          env: this.env.deployment,
          props: (this.ctx as MockExecutionContext<TestProps>).props,
        });
      }
    }
    const server = createTestServer({ handler: CalendarHandler });
    const response = await server.fetch(
      new Request(`${RESOURCE}/tools`, { headers: { Authorization: 'Bearer opaque-access-token' } }),
      env,
      new MockExecutionContext()
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      path: '/mcp/tools',
      env: 'resource-worker',
      props: { userId: 'user-123', scopes: ['mcp:read'] },
    });

    class NotAnEntrypoint {
      fetch() {
        return new Response('no');
      }
    }
    expect(() => createTestServer({ handler: NotAnEntrypoint as any })).toThrow(
      'handler must provide a fetch function or extend WorkerEntrypoint'
    );
  });

  it('hands the binding its own canonical resource and the token, as a detached method', async () => {
    // The documented line is `validateToken: (env) => env.AUTH_SERVER.validateToken`: the host
    // calls the method it was given without its receiver, with this server's resource first.
    const binding = {
      validateToken: vi.fn(async (resource: string, token: string) => ({
        props: { userId: `${token}@${resource}`, scopes: ['mcp:read'] },
        audience: resource,
      })),
    };
    const server = createTestServer({ validateToken: () => binding.validateToken });
    const response = await server.fetch(
      new Request(`${RESOURCE}/tools`, { headers: { Authorization: 'Bearer abc' } }),
      { deployment: 'resource-worker', AUTH_SERVER: binding } as TestEnv,
      new MockExecutionContext()
    );
    expect(response.status).toBe(200);
    expect(binding.validateToken).toHaveBeenCalledWith(RESOURCE, 'abc');
    await expect(response.json()).resolves.toMatchObject({ props: { userId: `abc@${RESOURCE}` } });
  });

  it('answers 503 when the validator factory itself throws, as for a missing binding', async () => {
    const server = createTestServer({
      validateToken: (env) => (env as { AUTH_SERVER?: { validateToken: never } }).AUTH_SERVER!.validateToken,
    });
    const response = await server.fetch(
      new Request(RESOURCE, { headers: { Authorization: 'Bearer token' } }),
      env,
      new MockExecutionContext()
    );
    expect(response.status).toBe(503);
    expect(response.headers.get('WWW-Authenticate')).toBeNull();
  });

  it("serves metadata regardless of a cache-busting query, while still requiring the resource's own query", async () => {
    const plain = createTestServer();
    expect((await plain.fetch(new Request(`${METADATA_URL}?cb=1`), env, new MockExecutionContext())).status).toBe(200);

    const tenant = createTestServer({
      resourceMetadata: {
        resource: `${RESOURCE}?tenant=acme`,
        authorization_servers: ['https://auth.example.com'],
      },
    });
    const tenantMetadata = `${METADATA_URL}?tenant=acme`;
    expect((await tenant.fetch(new Request(tenantMetadata), env, new MockExecutionContext())).status).toBe(200);
    expect((await tenant.fetch(new Request(`${tenantMetadata}&cb=1`), env, new MockExecutionContext())).status).toBe(
      200
    );
    expect((await tenant.fetch(new Request(METADATA_URL), env, new MockExecutionContext())).status).toBe(404);
    expect(
      (await tenant.fetch(new Request(`${METADATA_URL}?tenant=other`), env, new MockExecutionContext())).status
    ).toBe(404);
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
    const server = createTestServer({ validateToken: () => validateToken });
    const ctx = new MockExecutionContext<TestProps>();

    const response = await server.fetch(request, env, ctx);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      env: 'resource-worker',
      props: { userId: 'validated-user', scopes: ['mcp:read'] },
    });
    expect(ctx.props).toEqual({ userId: 'validated-user', scopes: ['mcp:read'] });
    expect(validateToken).toHaveBeenCalledWith(RESOURCE, 'opaque-access-token');
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
    const server = createTestServer({ validateToken: () => validateToken });

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
      validateToken: () => async () => ({
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
      validateToken: () => async () => ({
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
    const server = createTestServer({ handler, validateToken: () => async () => null });

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
      validateToken: () => async () => {
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
    const server = createTestServer({ validateToken: () => validateToken });
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
    const server = createTestServer({ validateToken: () => validateToken });
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

  it('accepts http resource and issuer identifiers on loopback hosts for local development', async () => {
    const localResource = 'http://localhost:8788/mcp';
    const server = createTestServer({
      resourceMetadata: { resource: localResource, authorization_servers: ['http://localhost:8787'] },
      validateToken: () => async () => ({
        props: { userId: 'user-123', scopes: ['mcp:read'] },
        audience: localResource,
        expiresAt: Date.now() / 1000 + 300,
      }),
    });

    const metadata = await server.fetch(
      new Request('http://localhost:8788/.well-known/oauth-protected-resource/mcp'),
      env,
      new MockExecutionContext()
    );
    expect(metadata.status).toBe(200);
    await expect(metadata.json()).resolves.toMatchObject({
      resource: localResource,
      authorization_servers: ['http://localhost:8787'],
    });

    const challenge = await server.fetch(new Request('http://localhost:8788/mcp'), env, new MockExecutionContext());
    expect(challenge.status).toBe(401);
    expect(challenge.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="http://localhost:8788/.well-known/oauth-protected-resource/mcp"'
    );

    const authorized = await server.fetch(
      new Request('http://localhost:8788/mcp', { headers: { Authorization: 'Bearer token' } }),
      env,
      new MockExecutionContext()
    );
    expect(authorized.status).toBe(200);
  });

  it('answers OPTIONS on the metadata URL and rejects other methods with Allow', async () => {
    const server = createTestServer();
    const preflight = await server.fetch(
      new Request(METADATA_URL, { method: 'OPTIONS', headers: { Origin: 'https://spa.example.com' } }),
      env,
      new MockExecutionContext()
    );
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('Access-Control-Allow-Origin')).toBe('https://spa.example.com');

    const post = await server.fetch(new Request(METADATA_URL, { method: 'POST' }), env, new MockExecutionContext());
    expect(post.status).toBe(405);
    expect(post.headers.get('Allow')).toBe('GET, HEAD, OPTIONS');
  });

  it('protects every path of a bare-origin resource', async () => {
    const server = createTestServer({
      resourceMetadata: { resource: 'https://mcp.example.com', authorization_servers: ['https://auth.example.com'] },
      validateToken: () => async () => ({
        props: { userId: 'user-123', scopes: [] },
        audience: 'https://mcp.example.com',
      }),
    });
    const challenge = await server.fetch(
      new Request('https://mcp.example.com/anything/deep'),
      env,
      new MockExecutionContext()
    );
    expect(challenge.status).toBe(401);
    expect(challenge.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"'
    );
    const served = await server.fetch(
      new Request('https://mcp.example.com/anything/deep', { headers: { Authorization: 'Bearer token' } }),
      env,
      new MockExecutionContext()
    );
    expect(served.status).toBe(200);
  });

  it('accepts a validated audience that names the resource with an empty path or different host case', async () => {
    const server = createTestServer({
      resourceMetadata: { resource: 'https://mcp.example.com', authorization_servers: ['https://auth.example.com'] },
      // RFC 3986 §6.2: scheme and host case-fold, and an empty path equals "/".
      validateToken: () => async () => ({
        props: { userId: 'user-123', scopes: [] },
        audience: 'HTTPS://MCP.example.com/',
      }),
    });
    const served = await server.fetch(
      new Request('https://mcp.example.com/tools', { headers: { Authorization: 'Bearer token' } }),
      env,
      new MockExecutionContext()
    );
    expect(served.status).toBe(200);
  });

  it('covers descendants of a query-bearing resource that carry its query', async () => {
    const resource = 'https://mcp.example.com/mcp?tenant=acme';
    const server = createTestServer({
      resourceMetadata: { resource, authorization_servers: ['https://auth.example.com'] },
      validateToken: () => async () => ({ props: { userId: 'user-123', scopes: [] }, audience: resource }),
    });
    const covered = await server.fetch(
      new Request('https://mcp.example.com/mcp/messages?tenant=acme&sessionId=abc'),
      env,
      new MockExecutionContext()
    );
    expect(covered.status).toBe(401);
    expect(covered.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp?tenant=acme"'
    );
    const served = await server.fetch(
      new Request('https://mcp.example.com/mcp/messages?tenant=acme&sessionId=abc', {
        headers: { Authorization: 'Bearer token' },
      }),
      env,
      new MockExecutionContext()
    );
    expect(served.status).toBe(200);
    const otherTenant = await server.fetch(
      new Request('https://mcp.example.com/mcp/messages?tenant=other'),
      env,
      new MockExecutionContext()
    );
    expect(otherTenant.status).toBe(404);
  });

  it('rejects unsupported bearer methods and malformed scopes at construction', () => {
    expect(() =>
      createTestServer({
        resourceMetadata: {
          resource: RESOURCE,
          authorization_servers: ['https://auth.example.com'],
          bearer_methods_supported: ['body'],
        },
      })
    ).toThrow(TypeError);
    expect(() =>
      createTestServer({
        resourceMetadata: {
          resource: RESOURCE,
          authorization_servers: ['https://auth.example.com'],
          scopes_supported: ['scope with spaces'],
        },
      })
    ).toThrow(TypeError);
  });

  it('rejects a validation result without props', async () => {
    const server = createTestServer({
      validateToken: () => async () => ({ audience: RESOURCE }) as unknown as OAuthResourceTokenValidation<TestProps>,
    });
    const response = await server.fetch(
      new Request(RESOURCE, { headers: { Authorization: 'Bearer token' } }),
      env,
      new MockExecutionContext()
    );
    expect(response.status).toBe(401);
  });

  it('rejects a resource inside the protected-resource metadata namespace at construction', () => {
    expect(() =>
      createTestServer({
        resourceMetadata: {
          resource: 'https://mcp.example.com/.well-known/oauth-protected-resource/service',
          authorization_servers: ['https://auth.example.com'],
        },
      })
    ).toThrow('must not be inside the /.well-known/oauth-protected-resource namespace');
  });

  it('rejects http identifiers on non-loopback hosts', () => {
    expect(() =>
      createTestServer({
        resourceMetadata: {
          resource: 'http://mcp.example.com/mcp',
          authorization_servers: ['https://auth.example.com'],
        },
      })
    ).toThrow('resourceMetadata.resource must be a canonical absolute HTTPS URI');

    expect(() =>
      createTestServer({
        resourceMetadata: { resource: RESOURCE, authorization_servers: ['http://auth.example.com'] },
      })
    ).toThrow('resourceMetadata.authorization_servers must contain canonical HTTPS issuer URLs');
  });
});
