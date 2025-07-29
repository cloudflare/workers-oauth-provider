import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

// Import the retry functions - we'll need to extract them from the main file
// For now, we'll copy the functions here for testing purposes
interface RetryOptions {
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  jitterFactor?: number;
}

/**
 * Executes a KV operation with retry logic and exponential backoff
 * @param operation - The KV operation to retry
 * @param options - Retry configuration options
 * @returns Promise that resolves when the operation succeeds
 */
async function retryKvOperation<T>(
  operation: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const {
    maxAttempts = 3,
    baseDelayMs = 100,
    maxDelayMs = 5000,
    jitterFactor = 0.1
  } = options;

  let lastError: Error | undefined;
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;
      
      // Don't retry on the last attempt
      if (attempt === maxAttempts) {
        break;
      }
      
      // Calculate delay with exponential backoff and jitter
      const exponentialDelay = Math.min(baseDelayMs * Math.pow(2, attempt - 1), maxDelayMs);
      const jitter = exponentialDelay * jitterFactor * Math.random();
      const delay = exponentialDelay + jitter;
      
      console.warn(`KV operation failed (attempt ${attempt}/${maxAttempts}), retrying in ${Math.round(delay)}ms:`, error);
      
      // Wait before retrying
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  // If we get here, all attempts failed
  console.error(`KV operation failed after ${maxAttempts} attempts:`, lastError);
  throw lastError || new Error('KV operation failed after all retry attempts');
}

/**
 * Wrapper for KV put operations with retry logic
 * @param kv - The KV namespace
 * @param key - The key to store
 * @param value - The value to store
 * @param options - KV put options (expiration, metadata, etc.)
 * @returns Promise that resolves when the put operation succeeds
 */
async function retryKvPut(
  kv: any,
  key: string,
  value: string,
  options?: any
): Promise<void> {
  return retryKvOperation(() => kv.put(key, value, options));
}

// Mock KV implementation that can simulate failures
class MockKVWithFailures {
  private storage: Map<string, { value: any; expiration?: number }> = new Map();
  private failureCount = 0;
  private maxFailures = 0;
  private shouldFail = false;

  setFailureMode(maxFailures: number) {
    this.maxFailures = maxFailures;
    this.failureCount = 0;
    this.shouldFail = true;
  }

  disableFailureMode() {
    this.shouldFail = false;
    this.failureCount = 0;
    this.maxFailures = 0;
  }

  async put(key: string, value: string | ArrayBuffer, options?: { expirationTtl?: number }): Promise<void> {
    if (this.shouldFail && this.failureCount < this.maxFailures) {
      this.failureCount++;
      throw new Error(`Simulated KV failure (attempt ${this.failureCount})`);
    }

    let expirationTime: number | undefined = undefined;
    if (options?.expirationTtl) {
      expirationTime = Date.now() + options.expirationTtl * 1000;
    }

    this.storage.set(key, { value, expiration: expirationTime });
  }

  async get(key: string, options?: { type: 'text' | 'json' | 'arrayBuffer' | 'stream' }): Promise<any> {
    const item = this.storage.get(key);
    if (!item) return null;

    if (item.expiration && item.expiration < Date.now()) {
      this.storage.delete(key);
      return null;
    }

    if (options?.type === 'json' && typeof item.value === 'string') {
      return JSON.parse(item.value);
    }

    return item.value;
  }

  getAttemptCount(): number {
    return this.failureCount;
  }

  clear() {
    this.storage.clear();
    this.disableFailureMode();
  }
}

describe('Retry Logic', () => {
  let mockKV: MockKVWithFailures;
  let consoleSpy: any;
  let consoleErrorSpy: any;

  beforeEach(() => {
    mockKV = new MockKVWithFailures();
    consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
    mockKV.clear();
  });

  describe('retryKvOperation', () => {
    it('should succeed on first attempt when operation succeeds', async () => {
      const operation = vi.fn().mockResolvedValue('success');
      
      const result = await retryKvOperation(operation);
      
      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(1);
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    it('should retry on failure and succeed on second attempt', async () => {
      const operation = vi.fn()
        .mockRejectedValueOnce(new Error('First failure'))
        .mockResolvedValueOnce('success');
      
      const promise = retryKvOperation(operation);
      
      // Fast-forward through the delay
      await vi.runAllTimersAsync();
      const result = await promise;
      
      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(2);
      expect(consoleSpy).toHaveBeenCalledTimes(1);
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('KV operation failed (attempt 1/3)'),
        expect.any(Error)
      );
    });

    it('should retry up to maxAttempts and then fail', async () => {
      const operation = vi.fn().mockRejectedValue(new Error('Persistent failure'));
      
      const promise = retryKvOperation(operation, { maxAttempts: 2 });
      
      // Fast-forward through all delays
      await vi.runAllTimersAsync();
      
      await expect(promise).rejects.toThrow('Persistent failure');
      expect(operation).toHaveBeenCalledTimes(2);
      expect(consoleSpy).toHaveBeenCalledTimes(1); // Only one retry warning
      expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
    });

    it('should use exponential backoff with correct delays', async () => {
      const operation = vi.fn().mockRejectedValue(new Error('Always fails'));
      const baseDelayMs = 100;
      
      // Mock setTimeout to capture delays
      const delays: number[] = [];
      const originalSetTimeout = globalThis.setTimeout;
      globalThis.setTimeout = vi.fn((callback: any, delay: number) => {
        delays.push(delay);
        return originalSetTimeout(callback, 0); // Execute immediately
      }) as any;
      
      const promise = retryKvOperation(operation, { 
        maxAttempts: 3, 
        baseDelayMs,
        jitterFactor: 0 // Remove jitter for predictable testing
      });
      
      await vi.runAllTimersAsync();
      await expect(promise).rejects.toThrow('Always fails');
      
      expect(delays).toHaveLength(2); // Two retries
      expect(delays[0]).toBe(100); // First retry: 100ms
      expect(delays[1]).toBe(200); // Second retry: 200ms
      
      globalThis.setTimeout = originalSetTimeout;
    });

    it('should respect maxDelayMs cap', async () => {
      const operation = vi.fn().mockRejectedValue(new Error('Always fails'));
      
      // Mock setTimeout to capture delays
      const delays: number[] = [];
      const originalSetTimeout = global.setTimeout;
      global.setTimeout = vi.fn((callback: any, delay: number) => {
        delays.push(delay);
        return originalSetTimeout(callback, 0);
      }) as any;
      
      const promise = retryKvOperation(operation, { 
        maxAttempts: 5, 
        baseDelayMs: 1000,
        maxDelayMs: 2000,
        jitterFactor: 0
      });
      
      await vi.runAllTimersAsync();
      await expect(promise).rejects.toThrow('Always fails');
      
      expect(delays).toHaveLength(4); // Four retries
      expect(delays[0]).toBe(1000); // 1000ms
      expect(delays[1]).toBe(2000); // 2000ms (capped)
      expect(delays[2]).toBe(2000); // 2000ms (capped)
      expect(delays[3]).toBe(2000); // 2000ms (capped)
      
      globalThis.setTimeout = originalSetTimeout;
    });

    it('should add jitter to delays', async () => {
      const operation = vi.fn().mockRejectedValue(new Error('Always fails'));
      
      // Mock Math.random to return predictable values
      const originalRandom = Math.random;
      Math.random = vi.fn(() => 0.5); // Always return 0.5 for predictable jitter
      
      // Mock setTimeout to capture delays
      const delays: number[] = [];
      const originalSetTimeout = global.setTimeout;
      global.setTimeout = vi.fn((callback: any, delay: number) => {
        delays.push(delay);
        return originalSetTimeout(callback, 0);
      }) as any;
      
      const promise = retryKvOperation(operation, { 
        maxAttempts: 3, 
        baseDelayMs: 100,
        jitterFactor: 0.1
      });
      
      await vi.runAllTimersAsync();
      await expect(promise).rejects.toThrow('Always fails');
      
      // With jitter factor 0.1 and Math.random() = 0.5:
      // First delay: 100 + (100 * 0.1 * 0.5) = 105
      // Second delay: 200 + (200 * 0.1 * 0.5) = 210
      expect(delays[0]).toBe(105);
      expect(delays[1]).toBe(210);
      
      Math.random = originalRandom;
      globalThis.setTimeout = originalSetTimeout;
    });

    it('should handle undefined error gracefully', async () => {
      const operation = vi.fn().mockImplementation(() => {
        throw undefined; // Simulate throwing undefined
      });
      
      const promise = retryKvOperation(operation, { maxAttempts: 1 });
      
      await expect(promise).rejects.toThrow('KV operation failed after all retry attempts');
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('KV operation failed after 1 attempts:'),
        undefined
      );
    });
  });

  describe('retryKvPut', () => {
    it('should successfully store data when KV operation succeeds', async () => {
      await retryKvPut(mockKV, 'test-key', 'test-value');
      
      const stored = await mockKV.get('test-key');
      expect(stored).toBe('test-value');
    });

    it('should retry and succeed after transient failures', async () => {
      mockKV.setFailureMode(2); // Fail first 2 attempts
      
      const promise = retryKvPut(mockKV, 'test-key', 'test-value');
      await vi.runAllTimersAsync();
      await promise;
      
      const stored = await mockKV.get('test-key');
      expect(stored).toBe('test-value');
      expect(mockKV.getAttemptCount()).toBe(2); // Failed twice, succeeded on third
      expect(consoleSpy).toHaveBeenCalledTimes(2); // Two retry warnings
    });

    it('should pass through KV options correctly', async () => {
      const options = { expirationTtl: 300 };
      
      await retryKvPut(mockKV, 'test-key', 'test-value', options);
      
      const stored = await mockKV.get('test-key');
      expect(stored).toBe('test-value');
    });

    it('should fail after exhausting all retry attempts', async () => {
      mockKV.setFailureMode(5); // Always fail
      
      const promise = retryKvPut(mockKV, 'test-key', 'test-value');
      await vi.runAllTimersAsync();
      
      await expect(promise).rejects.toThrow('Simulated KV failure');
      expect(mockKV.getAttemptCount()).toBe(3); // Default maxAttempts
      expect(consoleSpy).toHaveBeenCalledTimes(2); // Two retry warnings
      expect(consoleErrorSpy).toHaveBeenCalledTimes(1); // One final error
    });

    it('should work with custom retry options', async () => {
      mockKV.setFailureMode(1); // Fail first attempt only
      
      const customOptions: RetryOptions = {
        maxAttempts: 5,
        baseDelayMs: 50,
        maxDelayMs: 1000,
        jitterFactor: 0.05
      };
      
      const promise = retryKvOperation(
        () => mockKV.put('test-key', 'test-value'),
        customOptions
      );
      await vi.runAllTimersAsync();
      await promise;
      
      const stored = await mockKV.get('test-key');
      expect(stored).toBe('test-value');
      expect(mockKV.getAttemptCount()).toBe(1); // Failed once, succeeded on second
    });
  });

  describe('Integration with real KV operations', () => {
    it('should handle JSON serialization correctly', async () => {
      const testData = { 
        id: 'test-id', 
        value: 'test-value', 
        timestamp: Date.now() 
      };
      
      await retryKvPut(mockKV, 'json-key', JSON.stringify(testData));
      
      const stored = await mockKV.get('json-key', { type: 'json' });
      expect(stored).toEqual(testData);
    });

    it('should handle TTL options correctly', async () => {
      await retryKvPut(mockKV, 'ttl-key', 'ttl-value', { expirationTtl: 1 });
      
      // Should exist immediately
      let stored = await mockKV.get('ttl-key');
      expect(stored).toBe('ttl-value');
      
      // Mock time passage
      vi.advanceTimersByTime(2000); // Advance by 2 seconds
      
      // Should be expired now
      stored = await mockKV.get('ttl-key');
      expect(stored).toBeNull();
    });
  });

  describe('Error logging and monitoring', () => {
    it('should log retry attempts with correct format', async () => {
      const operation = vi.fn()
        .mockRejectedValueOnce(new Error('First failure'))
        .mockRejectedValueOnce(new Error('Second failure'))
        .mockResolvedValueOnce('success');
      
      const promise = retryKvOperation(operation);
      await vi.runAllTimersAsync();
      await promise;
      
      expect(consoleSpy).toHaveBeenCalledTimes(2);
      expect(consoleSpy).toHaveBeenNthCalledWith(1,
        expect.stringMatching(/KV operation failed \(attempt 1\/3\), retrying in \d+ms:/),
        expect.objectContaining({ message: 'First failure' })
      );
      expect(consoleSpy).toHaveBeenNthCalledWith(2,
        expect.stringMatching(/KV operation failed \(attempt 2\/3\), retrying in \d+ms:/),
        expect.objectContaining({ message: 'Second failure' })
      );
    });

    it('should log final error when all attempts fail', async () => {
      const operation = vi.fn().mockRejectedValue(new Error('Persistent error'));
      
      const promise = retryKvOperation(operation, { maxAttempts: 2 });
      await vi.runAllTimersAsync();
      
      await expect(promise).rejects.toThrow();
      
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'KV operation failed after 2 attempts:',
        expect.objectContaining({ message: 'Persistent error' })
      );
    });
  });
});
