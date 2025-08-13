/**
 * Mock for cloudflare:workers module
 * Provides a minimal implementation of WorkerEntrypoint for testing
 */
/** biome-ignore-all lint/suspicious/noExplicitAny: it's fine */

export class WorkerEntrypoint {
  ctx: any;
  env: any;

  constructor(ctx: any, env: any) {
    this.ctx = ctx;
    this.env = env;
  }

  fetch(_request: Request): Response | Promise<Response> {
    throw new Error('Method not implemented. This should be overridden by subclasses.');
  }
}
