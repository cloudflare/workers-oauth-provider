// Runs the official MCP conformance runner (@modelcontextprotocol/conformance, authorization-server
// mode) against the real conformance Worker, for every dated MCP authorization revision.
//
//   npm run test:conformance:upstream
//   CONFORMANCE_CLI=/path/to/conformance/dist/index.js npm run test:conformance:upstream   # an unreleased build
//
// The Worker runs in workerd through Wrangler's test harness, configured over RPC with a loopback
// issuer (http is accepted only on loopback), and pre-registers the public client the runner uses.
// This script plays the browser for the authorization-code scenario: it follows the authorize URL
// the runner prints, and the fixture's synthetic consent redirects to the runner's callback.
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { createTestHarness } from 'wrangler';

const REVISIONS = ['2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28'];
const CALLBACK_PORT = 3977;
const SCENARIO_TIMEOUT_MS = 90_000;

const cli =
  process.env.CONFORMANCE_CLI ??
  join(
    dirname(createRequire(import.meta.url).resolve('@modelcontextprotocol/conformance/package.json')),
    'dist/index.js'
  );

function runCli(args, onOutput) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const collect = (chunk) => {
      output += chunk;
      onOutput?.(output);
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    const timer = setTimeout(() => child.kill('SIGKILL'), SCENARIO_TIMEOUT_MS);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, output });
    });
  });
}

// Runners from before RFC 8707 support don't take --resource; newer ones send it in both requests.
const sendsResource = (await runCli(['authorization', '--help'])).output.includes('--resource');

const harness = createTestHarness({ workers: [{ configPath: './conformance/worker/wrangler.jsonc' }] });
const { url } = await harness.listen();
const origin = url.origin;
const resource = `${origin}/mcp`;
const worker = await harness.getWorker('mcp-oauth-conformance-worker').getExport();
await worker.configure({ dynamicClientRegistration: true, origin, resource, resourceScopes: ['mcp:read'] });
const client = await worker.createClient('none', `http://127.0.0.1:${CALLBACK_PORT}/callback`);
console.log(`runner ${cli}\nissuer ${origin}, resource ${sendsResource ? resource : '(not sent by this runner)'}\n`);

let failed = false;
for (const revision of REVISIONS) {
  let browsed = false;
  const args = ['authorization', '--url', origin, '--client-id', client.clientId, '--port', String(CALLBACK_PORT)];
  args.push('--spec-version', revision, ...(sendsResource ? ['--resource', resource] : []));
  const { code, output } = await runCli(args, (soFar) => {
    const authorize = /(http:\/\/127\.0\.0\.1:\d+\/authorize\?\S+)/.exec(soFar);
    if (authorize && !browsed && soFar.includes('Callback server started')) {
      browsed = true;
      fetch(authorize[1], { redirect: 'follow' }).catch((error) => console.error(`[browser] ${error}`));
    }
  });
  const summary = output.slice(output.indexOf('=== SUMMARY ==='));
  console.log(`${revision}: ${code === 0 ? 'passed' : `FAILED (exit ${code})`}\n${code === 0 ? summary : output}`);
  if (code !== 0) failed = true;
}

await harness.close();
process.exit(failed ? 1 : 0);
