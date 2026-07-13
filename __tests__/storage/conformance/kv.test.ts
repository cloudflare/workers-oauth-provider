import { describe, expect, it } from 'vitest';
import {
  createOAuthStorageConformanceCases,
  type OAuthStorageConformanceClock,
  type OAuthStorageConformanceFactory,
} from '../../../src/storage/testing';
import { workersKvStorage } from '../../../src/storage/kv';
import { MockKvNamespace } from '../helpers/mock-kv';

class Clock implements OAuthStorageConformanceClock {
  value = 100;
  constructor(private readonly onAdvance: (seconds: number) => void) {}
  now(): number {
    return this.value;
  }
  advance(seconds: number): void {
    this.value += seconds;
    this.onAdvance(seconds);
  }
}

interface Env {
  readonly KV: KVNamespace;
}

describe('published storage conformance suite', () => {
  let kv = new MockKvNamespace();
  let clock = new Clock((seconds) => (kv.now += seconds));
  const factory: OAuthStorageConformanceFactory<Env> = {
    reset() {
      kv = new MockKvNamespace();
      clock = new Clock((seconds) => (kv.now += seconds));
    },
    create(namespace) {
      const provider = workersKvStorage<Env>({
        binding: (env) => env.KV,
        namespace,
        now: () => clock.now(),
      });
      return {
        provider,
        env: { KV: kv.asNamespace() },
        clock,
        ioCount: () => kv.writes.length + kv.deletes.length,
      };
    },
  };

  for (const testCase of createOAuthStorageConformanceCases(factory)) {
    it(testCase.name, async () => {
      const result = await testCase.run();
      expect(['passed', 'skipped']).toContain(result.status);
    });
  }
});
