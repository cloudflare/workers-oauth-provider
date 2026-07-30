import { afterAll, afterEach, beforeAll } from 'vitest';
import { createTestHarness } from 'wrangler';
import type { ConformanceWorkerEnv } from '../worker';

export const harness = createTestHarness({
  workers: [{ configPath: './conformance/worker/wrangler.jsonc' }],
});

export const worker = harness.getWorker<ConformanceWorkerEnv, typeof import('../worker')>(
  'mcp-oauth-conformance-worker'
);

export type HarnessResponse = Awaited<ReturnType<typeof harness.fetch>>;

beforeAll(async () => {
  await harness.listen();
});

afterEach(async ({ task }) => {
  if (task.result?.state === 'fail') harness.debug();
  await harness.reset();
});

afterAll(async () => {
  await harness.close();
});
