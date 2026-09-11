/**
 * Loopback hosts where a plain `http` scheme is accepted for local development.
 * Matches RFC 8252 §7.3 loopback handling: 127.0.0.0/8, ::1, and `localhost`.
 */
export function isLoopbackHostname(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (host === 'localhost' || host === '::1' || host === '[::1]') return true;
  const ipv4 = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  return ipv4 !== null && ipv4.slice(1).every((octet) => Number(octet) <= 255);
}

/**
 * Whether a canonical resource, issuer, or endpoint URL uses an accepted
 * scheme: `https`, or `http` on a loopback host so `wrangler dev` works on
 * http://localhost. Workers are always served over `https`, so there is no
 * deployment in which cleartext OAuth traffic to a remote host is correct,
 * and no option exists to allow it.
 */
export function hasAcceptedCanonicalScheme(url: URL): boolean {
  return url.protocol === 'https:' || (url.protocol === 'http:' && isLoopbackHostname(url.hostname));
}

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
