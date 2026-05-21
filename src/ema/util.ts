/**
 * Tiny utility helpers used by EMA adapters.
 *
 * Lives in `src/ema/util.ts` rather than `src/util.ts` to keep the EMA
 * module self-contained — the main `oauth-provider.ts` reaches into here
 * only through the adapters' public interfaces.
 */

/** SHA-256 a string and return its hex digest. */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const buffer = await crypto.subtle.digest('SHA-256', data);
  const bytes = Array.from(new Uint8Array(buffer));
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}
