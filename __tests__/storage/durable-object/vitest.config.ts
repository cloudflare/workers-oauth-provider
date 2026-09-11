import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

/** Runs the Durable Object adapter tests inside workerd against a real SQLite-backed Durable Object. */
export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: './__tests__/storage/durable-object/wrangler.jsonc' } })],
  test: {
    include: ['__tests__/storage/durable-object/*.test.ts'],
  },
});
