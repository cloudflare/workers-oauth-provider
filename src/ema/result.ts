/**
 * Hand-rolled Result type and EMA-specific tagged error union.
 *
 * Every pure EMA validator returns `Result<T, EmaValidationError>`. The
 * orchestrator chains them with explicit `if (!r.ok) return r` checks — no
 * library, no hidden control flow. The wire-level error string is intentionally
 * generic for security (RFC 6749 §5.2), but the rich tagged `reason` flows to
 * the deployer-supplied `onError` hook so failures are still debuggable.
 */

export type Result<T, E> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };

export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });

/**
 * Tagged union of every validation failure that can occur on the EMA token
 * endpoint path. Extend by adding a new arm; the exhaustive `switch` in
 * `emaErrorToWire` will surface unhandled cases at compile time.
 */
export type EmaValidationError =
  | { reason: 'assertion_missing' }
  | { reason: 'assertion_too_large'; size: number; max: number }
  | { reason: 'assertion_malformed' }
  | { reason: 'invalid_typ'; got?: unknown }
  | { reason: 'invalid_alg'; got?: unknown }
  | { reason: 'issuer_not_trusted'; iss: string }
  | { reason: 'no_matching_key'; kid?: string }
  | { reason: 'signature_failed' }
  | { reason: 'jwks_fetch_failed'; status?: number }
  | { reason: 'invalid_claim'; claim: string }
  | { reason: 'aud_mismatch'; expected: string; got: string | string[] }
  | { reason: 'expired'; exp: number; now: number }
  | { reason: 'iat_in_future'; iat: number; now: number; skew: number }
  | { reason: 'nbf_in_future'; nbf: number; now: number; skew: number }
  | { reason: 'lifetime_too_long'; lifetime: number; max: number }
  | { reason: 'replayed'; jti: string }
  | { reason: 'client_id_mismatch'; expected: string; got: string }
  | { reason: 'resource_invalid'; resource: string }
  | { reason: 'resource_mismatch'; expected: string; got: string }
  | { reason: 'invalid_scope_param' }
  | { reason: 'invalid_mapped_user' }
  | { reason: 'invalid_mapped_scope' }
  | { reason: 'invalid_mapped_props' }
  | { reason: 'invalid_mapped_ttl' }
  | { reason: 'mapper_denied' }
  | { reason: 'assertion_expired_after_processing' };

/** Wire-level error response that the AS returns to the client. */
export interface EmaErrorWireResponse {
  code: 'invalid_grant' | 'invalid_target' | 'invalid_request';
  message: string;
}

/**
 * Map an internal `EmaValidationError` to its public OAuth error code and
 * description. Most validation failures collapse to a single generic message
 * to avoid leaking which check failed to attackers probing the IdP. The
 * exceptions are RFC-prescribed distinct codes (`invalid_target` for
 * RFC 8707 resource issues, `invalid_request` for malformed input).
 */
export function emaErrorToWire(e: EmaValidationError): EmaErrorWireResponse {
  switch (e.reason) {
    case 'assertion_missing':
      return { code: 'invalid_request', message: 'assertion is required' };
    case 'invalid_scope_param':
      return { code: 'invalid_request', message: 'Invalid scope parameter format' };
    case 'resource_invalid':
    case 'resource_mismatch':
      return { code: 'invalid_target', message: 'Invalid resource' };
    case 'mapper_denied':
      return { code: 'invalid_grant', message: 'Assertion was not authorized' };
    case 'invalid_mapped_user':
      return { code: 'invalid_grant', message: 'Invalid mapped user' };
    case 'invalid_mapped_scope':
      return { code: 'invalid_grant', message: 'Invalid mapped scope' };
    case 'invalid_mapped_props':
      return { code: 'invalid_grant', message: 'Invalid mapped props' };
    case 'invalid_mapped_ttl':
      return { code: 'invalid_grant', message: 'Invalid access token TTL' };
    case 'assertion_expired_after_processing':
      return { code: 'invalid_grant', message: 'Assertion has expired' };
    case 'assertion_too_large':
    case 'assertion_malformed':
    case 'invalid_typ':
    case 'invalid_alg':
    case 'issuer_not_trusted':
    case 'no_matching_key':
    case 'signature_failed':
    case 'jwks_fetch_failed':
    case 'invalid_claim':
    case 'aud_mismatch':
    case 'expired':
    case 'iat_in_future':
    case 'nbf_in_future':
    case 'lifetime_too_long':
    case 'replayed':
    case 'client_id_mismatch':
      return { code: 'invalid_grant', message: 'Invalid assertion' };
  }
}

/**
 * Payload passed to the `onError` callback when an EMA assertion is rejected.
 * Carries the full tagged reason for logging/alerting/diagnostics; the wire
 * response remains generic.
 */
export interface EmaOnErrorPayload {
  category: 'enterprise-managed-authorization';
  reason: EmaValidationError['reason'];
  detail: EmaValidationError;
}

export function emaErrorToOnErrorPayload(e: EmaValidationError): EmaOnErrorPayload {
  return {
    category: 'enterprise-managed-authorization',
    reason: e.reason,
    detail: e,
  };
}
