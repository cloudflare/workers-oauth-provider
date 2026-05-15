/**
 * Pure JWT parsing for ID-JAG assertions.
 *
 * Splits a compact JWS (`<base64url-header>.<base64url-payload>.<base64url-signature>`)
 * into its three parts, decodes header and payload as JSON, and exposes the
 * raw signing input + signature bytes for downstream signature verification.
 *
 * No I/O. No `this`. Returns `Result<ParsedIdJag, EmaValidationError>`.
 */

import { base64UrlToBytes, parseJwtJsonPart } from '../oauth-provider';
import { err, ok, type EmaValidationError, type Result } from './result';
import type { ParsedIdJag } from './types';

/**
 * Parse a compact JWS assertion.
 *
 * @param assertion The raw assertion string from the token request body.
 * @param maxBytes Reject assertions whose length exceeds this many bytes.
 *   Guards against memory exhaustion before any JSON parsing happens.
 */
export function parseIdJag(
  assertion: string,
  maxBytes: number
): Result<ParsedIdJag, EmaValidationError> {
  if (typeof assertion !== 'string' || assertion.length === 0) {
    return err({ reason: 'assertion_missing' });
  }

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
