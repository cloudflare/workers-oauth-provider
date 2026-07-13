import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    'oauth-provider': 'src/oauth-provider.ts',
    'storage/index': 'src/storage/index.ts',
    'storage/kv/index': 'src/storage/kv/index.ts',
    'storage/d1/index': 'src/storage/d1/index.ts',
    'storage/durable-object/index': 'src/storage/durable-object/index.ts',
    'storage/postgres/index': 'src/storage/postgres/index.ts',
    'storage/redis/index': 'src/storage/redis/index.ts',
    'storage/testing/index': 'src/storage/testing/index.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  external: ['cloudflare:workers'],
  fixedExtension: false,
});
