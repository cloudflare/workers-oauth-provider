import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    'oauth-provider': 'src/oauth-provider.ts',
    'storage/index': 'src/storage/index.ts',
    'storage/kv/index': 'src/storage/kv/index.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  external: ['cloudflare:workers'],
  fixedExtension: false,
});
