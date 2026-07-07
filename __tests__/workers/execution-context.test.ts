import { exports } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';

type CarrierInspection = {
  hadExistingValue: boolean;
  preservesIdentity: boolean;
  assignmentThrew: boolean;
  enumerable: boolean;
  writable: boolean;
  configurable: boolean;
  appearsInKeys: boolean;
  appearsInSpread: boolean;
  appearsInJson: boolean;
  clientId: string;
};

async function inspect(clientId: string): Promise<CarrierInspection> {
  const worker = exports as unknown as {
    default: { fetch(request: RequestInfo | URL): Promise<Response> };
  };
  const response = await worker.default.fetch(`https://example.com/?clientId=${clientId}`);
  return response.json<CarrierInspection>();
}

describe('ExecutionContext verified OAuth carrier', () => {
  it('supports a private immutable request-local symbol property', async () => {
    const [first, second] = await Promise.all([inspect('client-1'), inspect('client-2')]);

    expect(first).toEqual({
      hadExistingValue: false,
      preservesIdentity: true,
      assignmentThrew: true,
      enumerable: false,
      writable: false,
      configurable: false,
      appearsInKeys: false,
      appearsInSpread: false,
      appearsInJson: false,
      clientId: 'client-1',
    });
    expect(second.hadExistingValue).toBe(false);
    expect(second.clientId).toBe('client-2');
  });
});
