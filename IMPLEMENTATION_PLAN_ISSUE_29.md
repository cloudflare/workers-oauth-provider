# Implementation Plan: Issue #29 - Invalid Redirect URI Error

**Status: APPROVED by OpenCode (gpt-5.2-codex)**

## Issue Summary

Users experience "Invalid redirect URI" errors when connecting MCP clients like Cursor, Windsurf, and PyCharm in production. The issue stems from strict exact-match redirect URI validation that doesn't comply with RFC 8252 Section 7.3 for loopback interface redirection.

## Root Cause

The current redirect URI validation at line 2757 uses:
```typescript
if (!clientInfo.redirectUris.includes(redirectUri)) {
  throw new Error(`Invalid redirect URI...`);
}
```

This exact string matching fails when:
1. Native clients use ephemeral ports on loopback addresses
2. Clients register with `http://127.0.0.1/callback` but request authorization with `http://127.0.0.1:3334/callback`

## RFC 8252 Section 7.3 Requirements

> The authorization server MUST allow any port to be specified at the time of the request for loopback IP redirect URIs, to accommodate clients that obtain an available ephemeral port from the operating system at the time of the request.

Loopback redirect URIs:
- `http://127.0.0.1:{port}/{path}` (IPv4 - any address in 127.0.0.0/8)
- `http://[::1]:{port}/{path}` (IPv6)

**Note:** Per RFC 8252, only the port may vary. The scheme, hostname, path, and query must match exactly. The RFC does not treat `localhost` as equivalent to `127.x.x.x` - they are distinct hostnames.

## Implementation Plan

### Phase 1: Add Loopback URI Matching Helper Functions

**File:** `/Users/matt/Documents/Github/workers-oauth-provider-misc-issues/src/oauth-provider.ts`

Add new helper functions after `validateRedirectUriScheme` (around line 2509):

```typescript
/**
 * Checks if a hostname is an IPv4 loopback address (127.0.0.0/8 range per RFC 3330)
 * @param hostname - The hostname to check
 * @returns True if the hostname is in the 127.0.0.0/8 range
 */
function isIPv4Loopback(hostname: string): boolean {
  // Must start with "127." and be a valid IPv4 address
  if (!hostname.startsWith('127.')) {
    return false;
  }
  const parts = hostname.split('.');
  if (parts.length !== 4) {
    return false;
  }
  // Validate each octet is a number 0-255
  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255 || part !== num.toString()) {
      return false;
    }
  }
  return true;
}

/**
 * Checks if a URI is a loopback redirect URI (RFC 8252 Section 7.3)
 * Loopback URIs are http:// URIs pointing to 127.0.0.0/8 (IPv4) or [::1] (IPv6)
 * Note: localhost is NOT treated as a loopback address per strict RFC 8252 interpretation
 * @param uri - The URI to check
 * @returns True if the URI is a loopback redirect URI
 */
function isLoopbackRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri);
    // Must be http scheme (not https) for loopback per RFC 8252
    if (url.protocol !== 'http:') {
      return false;
    }
    // URL.hostname returns '::1' for IPv6 (without brackets)
    // and the IP address for IPv4
    const hostname = url.hostname.toLowerCase();
    return isIPv4Loopback(hostname) || hostname === '::1';
  } catch {
    return false;
  }
}

/**
 * Extracts the port from a URI string without URL normalization.
 * Handles IPv6 bracket notation correctly.
 * @param uri - The URI string
 * @returns Object with port string and its position, or null if no explicit port
 */
function extractPortInfo(uri: string): { port: string; start: number; end: number } | null {
  // Find the authority section (after :// and before path)
  const schemeEnd = uri.indexOf('://');
  if (schemeEnd === -1) return null;

  const authorityStart = schemeEnd + 3;
  const pathStart = uri.indexOf('/', authorityStart);
  const queryStart = uri.indexOf('?', authorityStart);
  const fragmentStart = uri.indexOf('#', authorityStart);

  // Find where authority ends (earliest of path, query, fragment, or end)
  let authorityEnd = uri.length;
  if (pathStart !== -1 && pathStart < authorityEnd) authorityEnd = pathStart;
  if (queryStart !== -1 && queryStart < authorityEnd) authorityEnd = queryStart;
  if (fragmentStart !== -1 && fragmentStart < authorityEnd) authorityEnd = fragmentStart;

  const authority = uri.substring(authorityStart, authorityEnd);

  // Handle IPv6 addresses in brackets
  const bracketEnd = authority.indexOf(']');
  if (bracketEnd !== -1) {
    // IPv6: port comes after the closing bracket
    const afterBracket = authority.substring(bracketEnd + 1);
    const portMatch = afterBracket.match(/^(:\d+)/);
    if (portMatch) {
      const portStartInAuthority = bracketEnd + 1;
      return {
        port: portMatch[1],
        start: authorityStart + portStartInAuthority,
        end: authorityStart + portStartInAuthority + portMatch[1].length,
      };
    }
    return null;
  }

  // IPv4 or hostname: port comes after the last colon
  const colonIndex = authority.lastIndexOf(':');
  // Make sure it's a port and not part of userinfo (no @ after it)
  if (colonIndex !== -1 && !authority.substring(colonIndex).includes('@')) {
    const portPart = authority.substring(colonIndex);
    if (/^:\d+$/.test(portPart)) {
      return {
        port: portPart,
        start: authorityStart + colonIndex,
        end: authorityStart + colonIndex + portPart.length,
      };
    }
  }

  return null;
}

/**
 * Removes the port from a URI string without URL normalization.
 * Preserves the exact string format except for the port portion.
 * Uses position-based removal to avoid matching port-like strings elsewhere.
 * @param uri - The URI string
 * @returns The URI with the port removed
 */
function removePort(uri: string): string {
  const portInfo = extractPortInfo(uri);
  if (!portInfo) return uri;
  return uri.substring(0, portInfo.start) + uri.substring(portInfo.end);
}

/**
 * Compares two redirect URIs with RFC 8252 loopback port flexibility.
 * For loopback URIs (127.0.0.0/8, [::1]), ONLY the port is ignored during comparison.
 * All other components must match exactly (raw string comparison after port removal).
 * For all other URIs, exact string matching is used.
 *
 * IMPORTANT: This function preserves exact-match semantics by using raw string
 * comparison with port stripping, NOT URL component comparison which could
 * normalize percent-encoding or path segments.
 *
 * @param registeredUri - The redirect URI registered with the client
 * @param requestUri - The redirect URI from the authorization request
 * @returns True if the URIs match (with loopback port flexibility)
 */
function redirectUriMatches(registeredUri: string, requestUri: string): boolean {
  // Fast path: exact match always succeeds
  if (registeredUri === requestUri) {
    return true;
  }

  // For non-loopback URIs, require exact match (already checked above)
  if (!isLoopbackRedirectUri(registeredUri) || !isLoopbackRedirectUri(requestUri)) {
    return false;
  }

  // Both are loopback URIs - compare raw strings with ports removed
  // This preserves exact-match semantics for all other URI components
  const registeredWithoutPort = removePort(registeredUri);
  const requestWithoutPort = removePort(requestUri);

  return registeredWithoutPort === requestWithoutPort;
}
```

### Phase 2: Update Redirect URI Validation in parseAuthRequest

**File:** `/Users/matt/Documents/Github/workers-oauth-provider-misc-issues/src/oauth-provider.ts`

**Location:** Line 2756-2762

Change from:
```typescript
if (clientInfo && redirectUri) {
  if (!clientInfo.redirectUris.includes(redirectUri)) {
    throw new Error(
      `Invalid redirect URI. The redirect URI provided does not match any registered URI for this client.`
    );
  }
}
```

To:
```typescript
if (clientInfo && redirectUri) {
  const hasMatchingUri = clientInfo.redirectUris.some(
    (registeredUri) => redirectUriMatches(registeredUri, redirectUri)
  );
  if (!hasMatchingUri) {
    throw new Error(
      `Invalid redirect URI. The redirect URI provided does not match any registered URI for this client.`
    );
  }
}
```

### Phase 3: Update Redirect URI Validation in completeAuthorization

**File:** `/Users/matt/Documents/Github/workers-oauth-provider-misc-issues/src/oauth-provider.ts`

**Location:** Line 2800-2806

Change from:
```typescript
const clientInfo = await this.lookupClient(clientId);
if (!clientInfo || !clientInfo.redirectUris.includes(redirectUri)) {
  throw new Error(
    'Invalid redirect URI. The redirect URI provided does not match any registered URI for this client.'
  );
}
```

To:
```typescript
const clientInfo = await this.lookupClient(clientId);
const hasMatchingUri = clientInfo?.redirectUris.some(
  (registeredUri) => redirectUriMatches(registeredUri, redirectUri)
);
if (!clientInfo || !hasMatchingUri) {
  throw new Error(
    'Invalid redirect URI. The redirect URI provided does not match any registered URI for this client.'
  );
}
```

### Phase 4: Update Redirect URI Validation in handleTokenRequest

**File:** `/Users/matt/Documents/Github/workers-oauth-provider-misc-issues/src/oauth-provider.ts`

**Location:** Line 1384

Change from:
```typescript
if (redirectUri && !clientInfo.redirectUris.includes(redirectUri)) {
  return this.createErrorResponse('invalid_grant', 'Invalid redirect URI');
}
```

To:
```typescript
if (redirectUri) {
  const hasMatchingUri = clientInfo.redirectUris.some(
    (registeredUri) => redirectUriMatches(registeredUri, redirectUri)
  );
  if (!hasMatchingUri) {
    return this.createErrorResponse('invalid_grant', 'Invalid redirect URI');
  }
}
```

### Phase 5: Add Comprehensive Test Cases

**File:** `/Users/matt/Documents/Github/workers-oauth-provider-misc-issues/__tests__/oauth-provider.test.ts`

Add a new test suite for RFC 8252 loopback redirect URI handling. Tests are written to use public API behavior only (no direct helper function imports):

```typescript
describe('RFC 8252 Loopback Redirect URI Handling', () => {
  let oauthProvider: OAuthProvider;
  let mockEnv: any;
  let mockCtx: ExecutionContext;

  beforeEach(() => {
    // Setup mock environment with OAUTH_KV
    mockEnv = createMockEnv();
    mockCtx = createMockCtx();
    oauthProvider = createOAuthProvider();
  });

  describe('IPv4 Loopback Port Flexibility (127.0.0.0/8)', () => {
    let clientId: string;

    beforeEach(async () => {
      // Register a client with loopback redirect URI without port
      const registerResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            redirect_uris: ['http://127.0.0.1/oauth/callback'],
            token_endpoint_auth_method: 'none',
          }),
        }),
        mockEnv,
        mockCtx
      );
      const clientData = await registerResponse.json();
      clientId = clientData.client_id;
    });

    it('should allow authorization request with different loopback port', async () => {
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent('http://127.0.0.1:3334/oauth/callback')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      // Should not throw - the request should be parsed successfully
      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).resolves.not.toThrow();
    });

    it('should allow any address in 127.0.0.0/8 range with port flexibility', async () => {
      // Register with 127.0.1.1
      const registerResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            redirect_uris: ['http://127.0.1.1/callback'],
            token_endpoint_auth_method: 'none',
          }),
        }),
        mockEnv,
        mockCtx
      );
      const clientData = await registerResponse.json();

      // Request with different port
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientData.client_id}` +
          `&redirect_uri=${encodeURIComponent('http://127.0.1.1:9999/callback')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).resolves.not.toThrow();
    });

    it('should NOT allow different loopback addresses even with same path', async () => {
      // Registered with 127.0.0.1, request with 127.0.0.2
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent('http://127.0.0.2/oauth/callback')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');
    });

    it('should reject mismatched paths even for loopback', async () => {
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent('http://127.0.0.1:3000/different-path')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');
    });

    it('should reject mismatched query strings even for loopback', async () => {
      // Register with query parameter
      const registerResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            redirect_uris: ['http://127.0.0.1/callback?client=app1'],
            token_endpoint_auth_method: 'none',
          }),
        }),
        mockEnv,
        mockCtx
      );
      const clientData = await registerResponse.json();

      // Request with different query
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientData.client_id}` +
          `&redirect_uri=${encodeURIComponent('http://127.0.0.1:5000/callback?client=app2')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');
    });

    it('should preserve exact path matching - no normalization of percent encoding', async () => {
      // Register with literal path
      const registerResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            redirect_uris: ['http://127.0.0.1/callback'],
            token_endpoint_auth_method: 'none',
          }),
        }),
        mockEnv,
        mockCtx
      );
      const clientData = await registerResponse.json();

      // Request with percent-encoded path should NOT match
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientData.client_id}` +
          `&redirect_uri=${encodeURIComponent('http://127.0.0.1:3000/%63allback')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');
    });
  });

  describe('IPv6 Loopback Port Flexibility', () => {
    it('should allow authorization request with different IPv6 loopback port', async () => {
      // Register with IPv6 loopback
      const registerResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            redirect_uris: ['http://[::1]/oauth/callback'],
            token_endpoint_auth_method: 'none',
          }),
        }),
        mockEnv,
        mockCtx
      );
      const clientData = await registerResponse.json();

      // Request with different port
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientData.client_id}` +
          `&redirect_uri=${encodeURIComponent('http://[::1]:9000/oauth/callback')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).resolves.not.toThrow();
    });
  });

  describe('localhost is NOT treated as loopback', () => {
    it('should NOT allow port flexibility for localhost (strict RFC 8252)', async () => {
      // Register with localhost and specific port
      const registerResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            redirect_uris: ['http://localhost:3000/callback'],
            token_endpoint_auth_method: 'none',
          }),
        }),
        mockEnv,
        mockCtx
      );
      const clientData = await registerResponse.json();

      // Request with different port - should FAIL because localhost is not treated as loopback
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientData.client_id}` +
          `&redirect_uri=${encodeURIComponent('http://localhost:8080/callback')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');
    });

    it('should NOT treat localhost as equivalent to 127.0.0.1', async () => {
      // Register with 127.0.0.1
      const registerResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            redirect_uris: ['http://127.0.0.1/callback'],
            token_endpoint_auth_method: 'none',
          }),
        }),
        mockEnv,
        mockCtx
      );
      const clientData = await registerResponse.json();

      // Request with localhost - should FAIL
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientData.client_id}` +
          `&redirect_uri=${encodeURIComponent('http://localhost/callback')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');
    });
  });

  describe('Token Endpoint - redirect_uri validation with loopback port flexibility', () => {
    it('should allow token exchange with different loopback port', async () => {
      // Full end-to-end test with actual auth code flow
      // Register client
      const registerResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            redirect_uris: ['http://127.0.0.1/callback'],
            token_endpoint_auth_method: 'none',
          }),
        }),
        mockEnv,
        mockCtx
      );
      const clientData = await registerResponse.json();

      // Simulate authorization flow with ephemeral port
      const redirectUriWithPort = 'http://127.0.0.1:54321/callback';

      // ... Complete authorization to get auth code ...
      // ... Then exchange code for token ...

      // Token request with redirect_uri that has port
      const tokenRequest = createMockRequest('https://example.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'test-auth-code',
          redirect_uri: redirectUriWithPort,
          client_id: clientData.client_id,
        }).toString(),
      });

      const response = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const errorBody = await response.json();

      // If there's an error, it should NOT be about redirect_uri mismatch
      if (errorBody.error) {
        expect(errorBody.error_description).not.toMatch(/redirect/i);
      }
    });
  });

  describe('Non-loopback URIs use exact matching', () => {
    it('should reject non-loopback URIs with port mismatch', async () => {
      // Register client with external host
      const registerResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            redirect_uris: ['https://myapp.example.com/callback'],
            token_endpoint_auth_method: 'none',
          }),
        }),
        mockEnv,
        mockCtx
      );
      const clientData = await registerResponse.json();

      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientData.client_id}` +
          `&redirect_uri=${encodeURIComponent('https://myapp.example.com:8443/callback')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow('Invalid redirect URI');
    });

    it('should allow exact match for custom schemes', async () => {
      // Register with custom scheme
      const registerResponse = await oauthProvider.fetch(
        createMockRequest('https://example.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            redirect_uris: ['cursor://oauth/callback'],
            token_endpoint_auth_method: 'none',
          }),
        }),
        mockEnv,
        mockCtx
      );
      const clientData = await registerResponse.json();

      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientData.client_id}` +
          `&redirect_uri=${encodeURIComponent('cursor://oauth/callback')}` +
          `&code_challenge=test&code_challenge_method=S256&state=test`
      );

      await expect(oauthProvider.fetch(authRequest, mockEnv, mockCtx)).resolves.not.toThrow();
    });
  });
});
```

## Security Considerations

1. **Loopback Only**: Port flexibility is ONLY applied to loopback IP addresses (127.0.0.0/8 for IPv4, [::1] for IPv6). External URLs and localhost hostname continue to use exact matching.

2. **Full 127/8 Range**: The implementation correctly handles the entire IPv4 loopback range (127.0.0.0/8) per RFC 3330.

3. **HTTP Only for Loopback**: Per RFC 8252, loopback redirect URIs use `http://` scheme (not `https://`), as the traffic never leaves the device. HTTPS loopback URIs use exact matching.

4. **Raw String Comparison**: The implementation uses raw string comparison with port stripping, NOT URL component comparison. This preserves exact-match semantics and prevents normalization attacks (percent-encoding variants, dot segments, etc.).

5. **Position-Based Port Removal**: The `removePort()` function uses position-based removal within the authority section to avoid accidentally matching port-like substrings elsewhere in the URI (e.g., in userinfo).

6. **Path and Query Matching**: The path and query components must match exactly to prevent redirect attacks.

7. **No localhost Equivalence**: `localhost` is NOT treated as equivalent to `127.0.0.1`. This is stricter than some implementations but prevents potential DNS rebinding attacks where localhost could resolve to unexpected addresses.

## Testing Strategy

1. **Integration Tests**: Test full authorization flow with loopback port variations via public API
2. **IPv4 Tests**: Test 127.0.0.1 and other addresses in 127/8 range with various port combinations
3. **IPv6 Tests**: Test [::1] with various port combinations
4. **localhost Tests**: Verify localhost does NOT get port flexibility
5. **Query String Tests**: Verify query strings must match exactly
6. **Percent-Encoding Tests**: Verify no normalization of percent-encoded paths
7. **Token Endpoint Tests**: Verify redirect_uri validation in authorization code exchange
8. **Regression Tests**: Ensure existing non-loopback behavior is unchanged
9. **Security Tests**: Verify external URLs still require exact matching

## Deployment Notes

1. This is a backward-compatible change - existing exact-match URIs will continue to work
2. No KV schema changes required
3. Clients using ephemeral loopback ports will now work without pre-registering every port
4. localhost users must register the exact URI including port they intend to use

## Related Issues

- Issue #35: Loopback Interface Redirection best practices
- Issue #104: Auth flow broken for MCP clients
- RFC 8252 Section 7.3: Loopback Interface Redirection
- RFC 3330: Special-Use IPv4 Addresses (defines 127.0.0.0/8)

## Timeline Estimate

- Phase 1: 1.5 hours (helper functions with raw string manipulation)
- Phase 2-4: 30 minutes (update validation logic)
- Phase 5: 2.5 hours (comprehensive tests including token endpoint)
- Code Review: 1 hour
- Total: ~5.5 hours
