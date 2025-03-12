import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/oauth-provider.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  external: ['cloudflare:workers'],
});
