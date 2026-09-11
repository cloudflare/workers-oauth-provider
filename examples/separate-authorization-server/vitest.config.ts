import { defineConfig } from 'vitest/config';

// Present so vitest does not walk up and adopt the library's own root config.
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Each test file starts its own workerd; give it room on a cold start.
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
