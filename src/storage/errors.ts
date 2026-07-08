/** Backend-neutral storage failure category. */
export type OAuthStorageErrorCode =
  | 'unavailable'
  | 'timeout'
  | 'rate_limited'
  | 'conflict'
  | 'schema_mismatch'
  | 'unsupported_operation'
  | 'invalid_configuration'
  | 'internal';

/** Safe options for constructing an {@link OAuthStorageError}. */
export interface OAuthStorageErrorOptions {
  /** Whether retrying the same operation may succeed. */
  readonly retryable?: boolean;
  /** Backend error retained for diagnostics but excluded from serialization. */
  readonly cause?: unknown;
  /** Stable operation name. Values that resemble credentials are rejected. */
  readonly operation?: string;
}

/** Redacted storage error representation safe for logs and protocol mapping. */
export interface SerializedOAuthStorageError {
  readonly name: 'OAuthStorageError';
  readonly code: OAuthStorageErrorCode;
  readonly retryable: boolean;
  readonly operation?: string;
}

const DEFAULT_RETRYABILITY: Readonly<Record<OAuthStorageErrorCode, boolean>> = Object.freeze({
  unavailable: true,
  timeout: true,
  rate_limited: true,
  conflict: false,
  schema_mismatch: false,
  unsupported_operation: false,
  invalid_configuration: false,
  internal: false,
});

/** All supported storage error codes. */
export const OAUTH_STORAGE_ERROR_CODES: readonly OAuthStorageErrorCode[] = Object.freeze(
  Object.keys(DEFAULT_RETRYABILITY) as OAuthStorageErrorCode[]
);

/**
 * Typed backend-neutral failure whose public message does not include backend
 * keys, SQL, connection strings, record contents, or credentials.
 */
export class OAuthStorageError extends Error {
  /** Stable machine-readable category. */
  readonly code: OAuthStorageErrorCode;
  /** Whether a retry may succeed. */
  readonly retryable: boolean;
  /** Stable operation name, when supplied. */
  readonly operation?: string;
  /** Original backend failure, deliberately non-enumerable. */
  declare readonly cause?: unknown;

  constructor(code: OAuthStorageErrorCode, options: OAuthStorageErrorOptions = {}) {
    if (typeof code !== 'string' || !Object.prototype.hasOwnProperty.call(DEFAULT_RETRYABILITY, code)) {
      throw new TypeError('Unknown OAuth storage error code');
    }
    super(`OAuth storage operation failed (${code})`);
    this.name = 'OAuthStorageError';
    this.code = code;
    this.retryable = options.retryable ?? DEFAULT_RETRYABILITY[code];
    if (options.operation !== undefined) {
      if (typeof options.operation !== 'string' || !/^[a-z][a-zA-Z0-9.]{0,79}$/.test(options.operation)) {
        throw new TypeError('Storage operation name must be a stable non-secret identifier');
      }
      this.operation = options.operation;
    }
    if (options.cause !== undefined) {
      Object.defineProperty(this, 'cause', {
        value: options.cause,
        enumerable: false,
        configurable: false,
        writable: false,
      });
    }
  }

  /** Returns a deliberately redacted representation suitable for logs. */
  toJSON(): SerializedOAuthStorageError {
    return {
      name: 'OAuthStorageError',
      code: this.code,
      retryable: this.retryable,
      ...(this.operation === undefined ? {} : { operation: this.operation }),
    };
  }
}

/** Returns whether an unknown failure is a typed OAuth storage error. */
export function isOAuthStorageError(error: unknown): error is OAuthStorageError {
  return error instanceof OAuthStorageError;
}

/** Creates the standard failure for a domain operation an adapter cannot provide. */
export function unsupportedStorageOperation(operation: string): OAuthStorageError {
  return new OAuthStorageError('unsupported_operation', { operation });
}
