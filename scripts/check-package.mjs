import { access, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = new URL('..', import.meta.url);
const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const targets = new Set();

for (const entry of Object.values(packageJson.exports)) {
  if (typeof entry === 'string') {
    targets.add(entry);
    continue;
  }
  for (const target of Object.values(entry)) targets.add(target);
}

for (const target of targets) await access(new URL(`..${target.slice(1)}`, import.meta.url));
await import(pathToFileURL(new URL('../dist/storage/index.js', import.meta.url).pathname).href);
await import(pathToFileURL(new URL('../dist/storage/kv/index.js', import.meta.url).pathname).href);

const dryRun = run('npm', ['pack', '--dry-run', '--json', '--ignore-scripts']);
const files = new Set(JSON.parse(dryRun)[0].files.map((file) => `./${file.path}`));
for (const target of targets) {
  if (!files.has(target)) throw new Error(`Package export target is missing from npm pack: ${target}`);
}

const fixture = new URL('../.package-test/', import.meta.url);
let tarball;
try {
  const packed = JSON.parse(run('npm', ['pack', '--json', '--ignore-scripts']));
  tarball = new URL(`../${packed[0].filename}`, import.meta.url);
  await mkdir(fixture, { recursive: true });
  await writeFile(new URL('package.json', fixture), JSON.stringify({ private: true, type: 'module' }));
  run('npm', ['install', '--ignore-scripts', '--no-package-lock', tarball.pathname], fixture);
  await writeFile(
    new URL('consumer.ts', fixture),
    `import OAuthProvider, { OAuthProvider as NamedProvider } from '@cloudflare/workers-oauth-provider';
import DeepProvider from '@cloudflare/workers-oauth-provider/dist/oauth-provider.js';
import type { OAuthStorageProvider } from '@cloudflare/workers-oauth-provider/storage';
import { workersKvStorage } from '@cloudflare/workers-oauth-provider/storage/kv';
interface Env extends Cloudflare.Env { OAUTH_KV: KVNamespace }
const storage: OAuthStorageProvider<Env> = workersKvStorage<Env>({ binding: env => env.OAUTH_KV });
void [OAuthProvider, NamedProvider, DeepProvider, storage];
`
  );
  const common = [
    '--noEmit',
    '--strict',
    '--skipLibCheck',
    '--target',
    'ES2021',
    '--lib',
    'ES2021',
    '--types',
    '@cloudflare/workers-types',
  ];
  run(
    resolve(root.pathname, 'node_modules/.bin/tsc'),
    [...common, '--module', 'NodeNext', '--moduleResolution', 'NodeNext', 'consumer.ts'],
    fixture
  );
  run(
    resolve(root.pathname, 'node_modules/.bin/tsc'),
    [...common, '--module', 'ESNext', '--moduleResolution', 'Bundler', 'consumer.ts'],
    fixture
  );
} finally {
  await rm(fixture, { recursive: true, force: true });
  if (tarball) await rm(tarball, { force: true });
}

console.log(`Verified ${targets.size} package export targets and installed-package declarations.`);

function run(command, args, cwd = root) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout;
}
