import { describe, expect, it } from 'vitest';
import { worker } from './support/harness';

describe('JWT access-token workerd runtime', () => {
  it.each(['RS256', 'ES256'] as const)('round-trips %s with workerd WebCrypto', async (algorithm) => {
    const api = await worker.getExport();
    expect(await api.roundTripJwt(algorithm)).toEqual({
      header: { typ: 'at+jwt', alg: algorithm, kid: `workerd-${algorithm}` },
      verified: true,
    });
  });
});
