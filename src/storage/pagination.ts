/** Opaque pagination request. Cursors are adapter-specific and must not be parsed by callers. */
export interface PageRequest {
  /** Maximum number of records requested for this page. */
  readonly limit?: number;
  /** Opaque cursor returned by the same adapter and query. */
  readonly cursor?: string;
}

/** One bounded page of records. */
export interface Page<T> {
  /** Records in this page. */
  readonly items: readonly T[];
  /** Opaque cursor for the next page, absent when the scan is complete. */
  readonly cursor?: string;
}

/** Validates and freezes a pagination request. */
export function createPageRequest(input: PageRequest = {}): Readonly<PageRequest> {
  if (input.limit !== undefined && (!Number.isSafeInteger(input.limit) || input.limit < 1)) {
    throw new TypeError('Page limit must be a positive safe integer');
  }
  if (input.cursor !== undefined && input.cursor.length === 0) {
    throw new TypeError('Page cursor must not be empty');
  }
  return Object.freeze({ ...input });
}

/** Creates a frozen page without interpreting the adapter-owned cursor. */
export function createPage<T>(items: readonly T[], cursor?: string): Page<T> {
  if (cursor !== undefined && cursor.length === 0) {
    throw new TypeError('Page cursor must not be empty');
  }
  return Object.freeze({ items: Object.freeze([...items]), ...(cursor === undefined ? {} : { cursor }) });
}
