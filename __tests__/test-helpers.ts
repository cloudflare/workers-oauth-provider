import type { ExecutionContext } from '@cloudflare/workers-types';
// The actual import is mocked in setup.ts
import { WorkerEntrypoint } from 'cloudflare:workers';
import type { OAuthHelpers } from '../src/oauth-provider';

/**
 * Mock KV namespace implementation that stores data in memory
 */
export class MockKV {
  private storage: Map<string, { value: any; expiration?: number }> = new Map();

  // Offset (ms) added to the wall clock. Lets tests deterministically advance time to
  // exercise TTL expiry without real `setTimeout` sleeps. Defaults to 0 (real time).
  private timeOffsetMs = 0;

  private now(): number {
    return Date.now() + this.timeOffsetMs;
  }

  /**
   * Advance the mock clock by `ms` so TTL'd entries expire deterministically.
   * Mirrors how real KV would drop an entry once its expiration passes.
   */
  advanceTime(ms: number): void {
    this.timeOffsetMs += ms;
  }

  async put(
    key: string,
    value: string | ArrayBuffer,
    options?: { expirationTtl?: number; expiration?: number }
  ): Promise<void> {
    let expirationTime: number | undefined = undefined;

    // Mirror Cloudflare KV's validation: both relative (`expirationTtl`) and absolute
    // (`expiration`) expirations must be at least 60 seconds in the future, otherwise the
    // PUT is rejected with a 400. This is what makes near-expiry/sub-60s token writes
    // reproduce as failures here exactly as they would in production.
    if (options?.expirationTtl) {
      if (options.expirationTtl < 60) {
        throw new Error(
          `KV PUT failed: 400 Invalid expiration_ttl of ${options.expirationTtl}. Expiration TTL's must be at least 60 seconds.`
        );
      }
      expirationTime = this.now() + options.expirationTtl * 1000;
    } else if (options?.expiration) {
      const minExpiration = Math.floor(this.now() / 1000) + 60;
      if (options.expiration < minExpiration) {
        throw new Error(
          `KV PUT failed: 400 Invalid expiration of ${options.expiration}. Expiration times must be at least 60 seconds in the future.`
        );
      }
      expirationTime = options.expiration * 1000;
    }

    this.storage.set(key, { value, expiration: expirationTime });
  }

  async get(key: string, options?: { type: 'text' | 'json' | 'arrayBuffer' | 'stream' }): Promise<any> {
    const item = this.storage.get(key);

    if (!item) {
      return null;
    }

    if (item.expiration && item.expiration < this.now()) {
      this.storage.delete(key);
      return null;
    }

    if (options?.type === 'json' && typeof item.value === 'string') {
      return JSON.parse(item.value);
    }

    return item.value;
  }

  async delete(key: string): Promise<void> {
    this.storage.delete(key);
  }

  async list(options: { prefix: string; limit?: number; cursor?: string }): Promise<{
    keys: { name: string }[];
    list_complete: boolean;
    cursor?: string;
  }> {
    const { prefix, limit = 1000 } = options;
    const allKeys: string[] = [];

    // Collect all matching, non-expired keys
    for (const key of this.storage.keys()) {
      if (key.startsWith(prefix)) {
        const item = this.storage.get(key);
        if (item && (!item.expiration || item.expiration >= this.now())) {
          allKeys.push(key);
        }
      }
    }

    // Handle cursor-based pagination: cursor is the index to start from
    const startIndex = options.cursor ? parseInt(options.cursor, 10) : 0;
    const pageKeys = allKeys.slice(startIndex, startIndex + limit);
    const nextIndex = startIndex + pageKeys.length;
    const listComplete = nextIndex >= allKeys.length;

    return {
      keys: pageKeys.map((name) => ({ name })),
      list_complete: listComplete,
      cursor: listComplete ? undefined : String(nextIndex),
    };
  }

  clear() {
    this.storage.clear();
    this.timeOffsetMs = 0;
  }
}

/**
 * Mock execution context for Cloudflare Workers
 */
export class MockExecutionContext implements ExecutionContext {
  readonly exports = {} as Cloudflare.Exports;
  readonly tracing = {} as Tracing;
  props: any = {};

  waitUntil(promise: Promise<any>): void {
    // In tests, we can just ignore waitUntil
  }

  passThroughOnException(): void {
    // No-op for tests
  }
}

// Test environment type
export type TestEnv = {
  OAUTH_KV: MockKV;
  OAUTH_PROVIDER: OAuthHelpers | null;
};

// Simple API handler for testing
export class TestApiHandler extends WorkerEntrypoint<TestEnv> {
  fetch(request: Request) {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/')) {
      // Return authenticated user info from ctx.props
      return new Response(
        JSON.stringify({
          success: true,
          user: this.ctx.props,
        }),
        {
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    return new Response('Not found', { status: 404 });
  }
}

// Simple default handler for testing
export const testDefaultHandler = {
  async fetch(request: Request, env: TestEnv, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (url.pathname === '/authorize') {
      // Mock authorize endpoint
      const oauthReqInfo = await env.OAUTH_PROVIDER!.parseAuthRequest(request);
      const clientInfo = await env.OAUTH_PROVIDER!.lookupClient(oauthReqInfo.clientId);

      // Mock user consent flow - automatically grant consent
      const { redirectTo } = await env.OAUTH_PROVIDER!.completeAuthorization({
        request: oauthReqInfo,
        userId: 'test-user-123',
        metadata: { testConsent: true },
        scope: oauthReqInfo.scope,
        props: { userId: 'test-user-123', username: 'TestUser' },
      });

      return Response.redirect(redirectTo, 302);
    }

    return new Response('Default handler', { status: 200 });
  },
};

// Helper function to create mock requests
export function createMockRequest(
  url: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  body?: string | FormData
): Request {
  const requestInit: RequestInit = {
    method,
    headers,
  };

  if (body) {
    requestInit.body = body;
  }

  return new Request(url, requestInit);
}

// Create a configured mock environment
export function createMockEnv(): TestEnv {
  return {
    OAUTH_KV: new MockKV(),
    OAUTH_PROVIDER: null, // Will be populated by the OAuthProvider
  };
}
