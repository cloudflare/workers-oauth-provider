/**
 * Pure JWT parsing for ID-JAG assertions.
 *
 * Splits a compact JWS (`<base64url-header>.<base64url-payload>.<base64url-signature>`)
 * into its three parts, decodes header and payload as JSON, and exposes the
 * raw signing input + signature bytes for downstream signature verification.
 *
 * No I/O. No `this`. Returns `Result<ParsedIdJag, EmaValidationError>`.
 */

import { err, ok, type EmaValidationError, type Result } from './result';
import type { ParsedIdJag } from './types';

/**
 * Parse a compact JWS assertion.
 *
 * @param assertion The raw assertion string from the token request body.
 * @param maxBytes Reject assertions whose length exceeds this many bytes.
 *   Guards against memory exhaustion before any JSON parsing happens.
 */
export function parseIdJag(assertion: string, maxBytes: number): Result<ParsedIdJag, EmaValidationError> {
  if (typeof assertion !== 'string' || assertion.length === 0) {
    return err({ reason: 'assertion_missing' });
  }

  // Compact JWS is ASCII-only (RFC 7515 §3.1), so `string.length` (UTF-16
  // code units) equals the UTF-8 byte count. Non-ASCII input fails the
  // base64url decode below, so the byte cap is honored without allocating
  // the UTF-8 bytes just to measure them.
  if (assertion.length > maxBytes) {
    return err({ reason: 'assertion_too_large', size: assertion.length, max: maxBytes });
  }

  const parts = assertion.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    return err({ reason: 'assertion_malformed' });
  }

  const [encodedHeader, encodedClaims, encodedSignature] = parts;

  let header: Record<string, unknown>;
  let rawClaims: Record<string, unknown>;
  let signature: Uint8Array;
  try {
    header = parseJwtJsonPart(encodedHeader);
    rawClaims = parseJwtJsonPart(encodedClaims);
    signature = base64UrlToBytes(encodedSignature);
  } catch {
    return err({ reason: 'assertion_malformed' });
  }

  const signingInput = new TextEncoder().encode(`${encodedHeader}.${encodedClaims}`);

  return ok({ header, rawClaims, signingInput, signature });
}

/**
 * Decodes a base64url-encoded string to bytes.
 */
function base64UrlToBytes(base64Url: string): Uint8Array {
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binaryString = atob(padded);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Parses a base64url-encoded JWT JSON part into an object.
 */
function parseJwtJsonPart(encoded: string): Record<string, unknown> {
  try {
    const json = new TextDecoder().decode(base64UrlToBytes(encoded));
    const parsed = JSON.parse(json);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('JWT part must be an object');
    }
    return parsed as Record<string, unknown>;
  } catch {
    throw new Error('Malformed JWT part');
  }
}
