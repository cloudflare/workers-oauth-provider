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

/**
 * Whether a requested resource identifies a granted or configured resource.
 * Only ASCII case in the URI scheme and host is ignored, and an empty path is
 * equivalent to `/` (RFC 3986 §6.2.3), so a client that round-trips
 * `https://example.com` through a URL parser as `https://example.com/` still
 * names it. Port, path, query, a trailing slash after a path segment, user
 * information, and every other byte remain significant.
 */
export function resourceMatches(requested: string, granted: string): boolean {
  const foldedRequested = foldResourceSchemeAndHost(requested);
  const foldedGranted = foldResourceSchemeAndHost(granted);
  if (foldedRequested === undefined || foldedGranted === undefined) return false;
  return normalizeEmptyPath(foldedRequested) === normalizeEmptyPath(foldedGranted);
}

/**
 * Fold only the URI components whose comparison is ASCII case-insensitive: the
 * scheme and the host. A configured identifier is canonical when folding it is
 * the identity.
 */
export function foldResourceSchemeAndHost(resource: string): string | undefined {
  const schemeSeparator = resource.indexOf('://');
  if (schemeSeparator <= 0) return undefined;

  const authorityStart = schemeSeparator + 3;
  const authorityEndOffset = resource.slice(authorityStart).search(/[/?#]/);
  const authorityEnd = authorityEndOffset === -1 ? resource.length : authorityStart + authorityEndOffset;
  const authority = resource.slice(authorityStart, authorityEnd);
  const userInfoEnd = authority.lastIndexOf('@');
  const hostStart = userInfoEnd + 1;

  let hostEnd: number;
  if (authority[hostStart] === '[') {
    const closingBracket = authority.indexOf(']', hostStart + 1);
    if (closingBracket === -1) return undefined;
    hostEnd = closingBracket + 1;
  } else {
    const portSeparator = authority.indexOf(':', hostStart);
    hostEnd = portSeparator === -1 ? authority.length : portSeparator;
  }

  const asciiLower = (value: string) => value.replace(/[A-Z]/g, (character) => character.toLowerCase());
  return (
    asciiLower(resource.slice(0, schemeSeparator)) +
    '://' +
    authority.slice(0, hostStart) +
    asciiLower(authority.slice(hostStart, hostEnd)) +
    authority.slice(hostEnd) +
    resource.slice(authorityEnd)
  );
}

/** RFC 3986 §6.2.3: for http and https an empty path is equivalent to "/". */
function normalizeEmptyPath(resource: string): string {
  const authorityStart = resource.indexOf('://') + 3;
  const pathOffset = resource.slice(authorityStart).search(/[/?#]/);
  if (pathOffset === -1) return `${resource}/`;
  const pathStart = authorityStart + pathOffset;
  return resource[pathStart] === '/' ? resource : `${resource.slice(0, pathStart)}/${resource.slice(pathStart)}`;
}

/**
 * Whether a request carries every query parameter of a canonical resource. A
 * query-bearing resource identifier names a more specific resource: a request
 * may add parameters of its own but must preserve the resource's.
 */
export function requestCarriesResourceQuery(requestUrl: URL, resourceUrl: URL): boolean {
  for (const [name, value] of resourceUrl.searchParams) {
    if (!requestUrl.searchParams.getAll(name).includes(value)) return false;
  }
  return true;
}
