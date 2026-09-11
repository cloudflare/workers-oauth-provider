import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    setupFiles: ['./__tests__/setup.ts'],
    // The Durable Object adapter runs inside workerd; see __tests__/storage/durable-object/vitest.config.ts.
    exclude: ['**/node_modules/**', '__tests__/storage/durable-object/**'],
  },
});
