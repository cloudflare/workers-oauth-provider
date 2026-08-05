/** Validate an RFC 3986-safe HTTP(S) resource identifier for RFC 8707. */
export function validateResourceUri(uri: string): boolean {
  if (!uri || typeof uri !== 'string') return false;

  // WHATWG URL repairs several invalid producer serializations. Reject those
  // before parsing so AS and RS components compare the same identifier bytes.
  if (
    !/^[\x21-\x7e]+$/.test(uri) ||
    /["\\#]/.test(uri) ||
    !/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]+(?:\/[^?#]*)?(?:\?[^#]*)?$/.test(uri) ||
    /%(?![0-9A-Fa-f]{2})/.test(uri) ||
    !/^[A-Za-z0-9:/?@!$&'()*+,;=._~%\[\]-]+$/.test(uri)
  ) {
    return false;
  }

  try {
    const parsed = new URL(uri);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}
