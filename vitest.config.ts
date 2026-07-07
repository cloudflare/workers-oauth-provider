import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'node',
    globals: true,
    environment: 'node',
    include: ['./__tests__/*.test.ts'],
    setupFiles: ['./__tests__/setup.ts'],
  },
});
