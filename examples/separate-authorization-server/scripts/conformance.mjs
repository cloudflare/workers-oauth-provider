#!/usr/bin/env node
// Runs the official MCP authorization-server conformance scenarios against this example.
// It starts both `wrangler dev` sessions, registers a client, drives the placeholder
// login page in place of a browser, and reports every check the suite recorded.
//
// The local dev certificate is self-signed, so every HTTPS call made here (and by the
// conformance CLI) has certificate verification disabled. Never do this against a real
// server.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

import { spawn } from 'node:child_process';
import { readdir, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CONFORMANCE_PACKAGE = '@modelcontextprotocol/conformance@0.2.0-alpha.11';
// The `authorization` command runs these, in this order. Both run in one invocation
// because authorization-code-grant reads the metadata document that
// authorization-server-metadata-endpoint captured in the same run.
const SCENARIOS = ['authorization-server-metadata-endpoint', 'authorization-code-grant'];
const ISSUER = 'https://localhost:8787';
const CALLBACK_PORT = 3000;
const REDIRECT_URI = `http://127.0.0.1:${CALLBACK_PORT}/callback`;

const exampleRoot = fileURLToPath(new URL('..', import.meta.url));
const wranglerCli = fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url));
const resultsDir = join(exampleRoot, 'conformance-results');

const children = new Set();

process.on('SIGINT', () => shutdown(130));
process.on('SIGTERM', () => shutdown(143));

try {
  await rm(resultsDir, { recursive: true, force: true });
  await requireFreePort(8787, 'the authorization server');
  await requireFreePort(8788, 'the MCP server');
  await requireFreePort(CALLBACK_PORT, "the conformance CLI's OAuth callback server");

  startWorker('authorization-server', 8787, 9229);
  startWorker('mcp-server', 8788, 9230);
  await waitForAuthorizationServer();

  const clientId = await registerClient();
  console.log(`Registered conformance client ${clientId}`);

  const exitCode = await runConformance(clientId);
  const failed = await reportResults();
  if (exitCode !== 0) console.error(`\nThe conformance CLI exited with ${exitCode}`);
  await shutdown(failed || exitCode !== 0 ? 1 : 0);
} catch (error) {
  console.error(error);
  await shutdown(1);
}

function startWorker(directory, port, inspectorPort) {
  const child = spawn(
    process.execPath,
    [
      wranglerCli,
      'dev',
      '--config',
      `${directory}/wrangler.jsonc`,
      // The issuer and the resource identifier must be HTTPS URLs, and the library
      // compares them against the request URL, so local dev has to serve HTTPS.
      '--local-protocol',
      'https',
      '--port',
      String(port),
      // Each session needs its own inspector port, otherwise the second one exits with
      // "Address already in use".
      '--inspector-port',
      String(inspectorPort),
    ],
    { cwd: exampleRoot, detached: true, stdio: ['ignore', 'pipe', 'pipe'] }
  );
  children.add(child);
  const log = (chunk) => process.env.VERBOSE && process.stdout.write(`[${directory}] ${chunk}`);
  child.stdout.on('data', log);
  child.stderr.on('data', log);
  return child;
}

/**
 * Wait for three good metadata responses in a row. Starting the second `wrangler dev`
 * registers it in the dev registry and reloads the first, so the authorization server
 * briefly stops answering and one good response is not enough.
 */
async function waitForAuthorizationServer() {
  const url = `${ISSUER}/.well-known/oauth-authorization-server`;
  const deadline = Date.now() + 90_000;
  let consecutive = 0;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      const metadata = response.ok ? await response.json() : null;
      consecutive = metadata?.issuer === ISSUER ? consecutive + 1 : 0;
      if (consecutive === 3) return;
    } catch {
      consecutive = 0;
    }
    await sleep(500);
  }
  throw new Error(`Timed out waiting for ${url} to report issuer ${ISSUER}`);
}

async function registerClient() {
  const response = await fetch(`${ISSUER}/oauth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: 'MCP conformance suite',
      redirect_uris: [REDIRECT_URI],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    }),
  });
  if (response.status !== 201) {
    throw new Error(`Client registration failed with ${response.status}: ${await response.text()}`);
  }
  return (await response.json()).client_id;
}

function runConformance(clientId) {
  // The suite has no --resource flag, so its authorization request omits `resource`. With
  // two registered audiences, `defaultResource` is what keeps this scenario green.
  const child = spawn(
    'npx',
    [
      '-y',
      CONFORMANCE_PACKAGE,
      'authorization',
      '--url',
      ISSUER,
      '--client-id',
      clientId,
      '--port',
      String(CALLBACK_PORT),
      '-o',
      resultsDir,
    ],
    { cwd: exampleRoot, detached: true, stdio: ['ignore', 'pipe', 'pipe'] }
  );
  children.add(child);

  let buffered = '';
  let loginStarted = false;
  child.stdout.on('data', (chunk) => {
    process.stdout.write(chunk);
    buffered += chunk;
    // Require the terminating newline: a URL split across two chunks would otherwise
    // match truncated, and the login would fail into the CLI's five-minute timeout.
    const match = buffered.match(/^(https:\/\/\S+\/authorize\?\S+)\r?\n/m);
    if (match && !loginStarted) {
      loginStarted = true;
      // The scenario expects a human with a browser. Approve on its behalf.
      approveAuthorization(match[1]).catch((error) => console.error('Login failed:', error));
    }
  });
  child.stderr.on('data', (chunk) => process.stderr.write(chunk));

  return new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', (code) => {
      children.delete(child);
      resolve(code);
    });
  });
}

async function approveAuthorization(authorizeUrl) {
  const page = await fetch(authorizeUrl, { redirect: 'manual' });
  if (!page.ok) throw new Error(`Authorization page returned ${page.status}`);
  const html = await page.text();

  // A browser decodes the character references in the markup before it builds the
  // request; this script has to do the same.
  const action = new URL(decodeEntities(html.match(/<form[^>]*action="([^"]+)"/)[1]), authorizeUrl);
  const body = new URLSearchParams();
  for (const [, name, value] of html.matchAll(/<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"/g)) {
    body.set(decodeEntities(name), decodeEntities(value));
  }
  // The decision lives on the submit buttons rather than an input. The first is Approve.
  const approve = html.match(/<button[^>]*name="([^"]+)"[^>]*value="([^"]*)"/);
  body.set(decodeEntities(approve[1]), decodeEntities(approve[2]));

  const redirect = await fetch(action, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    redirect: 'manual',
  });
  const location = redirect.headers.get('location');
  if (!location) throw new Error(`Approval returned ${redirect.status} without a redirect`);

  // Hand the authorization code to the callback server the suite is running.
  await fetch(location);
}

function decodeEntities(value) {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
}

async function reportResults() {
  const files = await findChecksFiles(resultsDir);
  const checks = [];
  for (const file of files) checks.push(...collectChecks(JSON.parse(await readFile(file, 'utf8'))));
  if (checks.length === 0) throw new Error(`No checks were recorded under ${resultsDir}`);

  let failed = false;
  console.log('\nConformance results');
  for (const scenario of SCENARIOS) {
    // A scenario that recorded nothing must not pass by omission.
    if (files.some((file) => file.includes(scenario))) continue;
    failed = true;
    console.log(`  MISSING  ${scenario} recorded no results`);
  }
  for (const check of checks) {
    // Anything short of SUCCESS is a failure here: the CLI records a soft WARNING for
    // some checks and still exits 0.
    if (check.status !== 'SUCCESS') failed = true;
    console.log(`  ${check.status.padEnd(8)} ${check.id}${check.errorMessage ? ` - ${check.errorMessage}` : ''}`);
  }
  console.log(`\nResults written to ${resultsDir}`);
  return failed;
}

async function findChecksFiles(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await findChecksFiles(path)));
    else if (entry.name === 'checks.json') files.push(path);
  }
  return files;
}

function collectChecks(results) {
  if (Array.isArray(results)) return results.flatMap(collectChecks);
  if (results && typeof results === 'object') {
    if (typeof results.status === 'string' && typeof results.id === 'string') return [results];
    return Object.values(results).flatMap(collectChecks);
  }
  return [];
}

/** The ports are fixed, so a stale process gives a clearer failure up front. */
function requireFreePort(port, purpose) {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', () => reject(new Error(`Port ${port} is in use; ${purpose} needs it.`)));
    probe.once('listening', () => probe.close(() => resolve()));
    probe.listen(port, '127.0.0.1');
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function shutdown(code) {
  for (const child of children) {
    try {
      process.kill(-child.pid, 'SIGTERM');
    } catch {
      // Already gone.
    }
  }
  children.clear();
  await new Promise((resolve) => setTimeout(resolve, 500));
  process.exit(code);
}
