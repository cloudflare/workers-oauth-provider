import { vi } from 'vitest';
import { WorkerEntrypoint, DurableObject } from './mocks/cloudflare-workers';

// Mock the 'cloudflare:workers' module
vi.mock('cloudflare:workers', () => {
  return {
    WorkerEntrypoint,
    DurableObject,
  };
});

// Add any other global setup needed for the tests
