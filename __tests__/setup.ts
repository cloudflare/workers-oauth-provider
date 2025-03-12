import { vi } from 'vitest';
import { WorkerEntrypoint } from './mocks/cloudflare-workers';

// Mock the 'cloudflare:workers' module
vi.mock('cloudflare:workers', () => {
  return {
    WorkerEntrypoint,
  };
});

// Add any other global setup needed for the tests
