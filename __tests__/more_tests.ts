import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { unstable_dev } from 'wrangler';
import type { UnstableDevWorker } from 'wrangler';

describe('OAuth Provider Security Tests', () => {
  let worker: UnstableDevWorker;

  beforeAll(async () => {
    worker = await unstable_dev('src/index.ts', {
      experimental: { disableExperimentalWarning: true },
    });
  });

  afterAll(async () => {
    await worker.stop();
  });

  describe('RFC 6749 MUST Requirements', () => {
    describe('Section 2.3.1 - Client Authentication', () => {
      it('MUST support HTTP Basic authentication scheme for clients', async () => {
        const clientId = 'test-client';
        const clientSecret = 'test-secret';
        const credentials = btoa(`${clientId}:${clientSecret}`);
        
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${credentials}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=authorization_code&code=invalid',
        });
        
        // Should fail for invalid code, not auth
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).not.toBe('invalid_client');
      });

      it('MUST URL-encode client credentials in Basic auth per RFC 6749', async () => {
        // Test special characters that need encoding
        const clientId = 'client@example.com';
        const clientSecret = 'secret:with:colons';
        const encodedId = encodeURIComponent(clientId);
        const encodedSecret = encodeURIComponent(clientSecret);
        const credentials = btoa(`${encodedId}:${encodedSecret}`);
        
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${credentials}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=authorization_code&code=invalid',
        });
        
        // Should process auth correctly despite special chars
        expect(response.status).toBe(401); // No such client
      });
    });

    describe('Section 3.1 - Authorization Endpoint', () => {
      it('MUST support the response_type parameter', async () => {
        const response = await parseAuthRequest({
          // Missing response_type
          client_id: 'test',
          redirect_uri: 'https://example.com/callback',
        });
        
        expect(response).toThrow('response_type parameter is required');
      });

      it('MUST validate redirect_uri against registered URIs', async () => {
        const response = await parseAuthRequest({
          response_type: 'code',
          client_id: 'registered-client',
          redirect_uri: 'https://evil.com/callback', // Not registered
        });
        
        expect(response).toThrow('Invalid redirect URI');
      });
    });

    describe('Section 4.1.3 - Access Token Request', () => {
      it('MUST require client authentication for confidential clients', async () => {
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=authorization_code&code=valid-code&client_id=confidential-client',
          // Missing client_secret
        });
        
        expect(response.status).toBe(401);
        const body = await response.json();
        expect(body.error).toBe('invalid_client');
      });

      it('MUST invalidate authorization code after single use', async () => {
        const code = 'test-auth-code';
        
        // First use should succeed
        const response1 = await exchangeCode(code);
        expect(response1.status).toBe(200);
        
        // Second use should fail
        const response2 = await exchangeCode(code);
        expect(response2.status).toBe(400);
        const body = await response2.json();
        expect(body.error).toBe('invalid_grant');
      });

      it('MUST reject authorization codes after expiration', async () => {
        const expiredCode = 'expired-auth-code';
        // Wait 11 minutes (codes expire in 10)
        await new Promise(resolve => setTimeout(resolve, 11 * 60 * 1000));
        
        const response = await exchangeCode(expiredCode);
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe('invalid_grant');
      });
    });

    describe('Section 5.1 - Access Token Response', () => {
      it('MUST include token_type in successful response', async () => {
        const response = await exchangeCode('valid-code');
        const body = await response.json();
        
        expect(body.token_type).toBe('bearer');
      });

      it('MUST include expires_in for access tokens', async () => {
        const response = await exchangeCode('valid-code');
        const body = await response.json();
        
        expect(body.expires_in).toBeTypeOf('number');
        expect(body.expires_in).toBeGreaterThan(0);
      });
    });

    describe('Section 5.2 - Error Response', () => {
      it('MUST use 400 Bad Request for invalid_request errors', async () => {
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: '', // Missing required parameters
        });
        
        expect(response.status).toBe(400);
      });

      it('MUST use 401 Unauthorized for invalid_client errors', async () => {
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Authorization': 'Basic ' + btoa('invalid:wrong'),
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=authorization_code&code=test',
        });
        
        expect(response.status).toBe(401);
        const body = await response.json();
        expect(body.error).toBe('invalid_client');
      });
    });

    describe('Section 10.10 - PKCE', () => {
      it('MUST reject authorization without code_verifier when PKCE was used', async () => {
        // Authorization used PKCE
        const grant = await completeAuthWithPKCE({
          code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
          code_challenge_method: 'S256',
        });
        
        // Token exchange without code_verifier
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: `grant_type=authorization_code&code=${grant.code}`,
        });
        
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe('invalid_request');
        expect(body.error_description).toContain('code_verifier');
      });

      it('MUST validate code_verifier against code_challenge', async () => {
        const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        const codeChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
        
        const grant = await completeAuthWithPKCE({
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
        });
        
        // Try with wrong verifier
        const response = await exchangeCodeWithPKCE(grant.code, 'wrong-verifier');
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe('invalid_grant');
      });
    });
  });

  describe('RFC 6749 MUST NOT Requirements', () => {
    describe('Section 3.2 - Token Endpoint', () => {
      it('MUST NOT use GET for token endpoint', async () => {
        const response = await worker.fetch('/token', {
          method: 'GET',
        });
        
        expect(response.status).toBe(405);
      });
    });

    describe('Section 4.1.2 - Authorization Response', () => {
      it('MUST NOT include authorization code in URL fragment', async () => {
        const result = await completeAuthorization({
          response_type: 'code',
          redirect_uri: 'https://example.com/callback',
        });
        
        const url = new URL(result.redirectTo);
        expect(url.hash).toBe('');
        expect(url.searchParams.has('code')).toBe(true);
      });
    });

    describe('Section 10.12 - Cross-Site Request Forgery', () => {
      it('MUST NOT accept authorization codes across different clients', async () => {
        const codeForClientA = await getAuthCodeForClient('client-a');
        
        // Try to use client A's code with client B's credentials
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Authorization': 'Basic ' + btoa('client-b:secret-b'),
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: `grant_type=authorization_code&code=${codeForClientA}`,
        });
        
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe('invalid_grant');
      });
    });
  });

  describe('Abuse Cases and Security Edge Cases', () => {
    describe('Token Generation Bias Attack', () => {
      it('should generate tokens with uniform distribution', async () => {
        const tokens = [];
        for (let i = 0; i < 10000; i++) {
          const token = generateRandomString(32);
          tokens.push(token);
        }
        
        // Check character distribution
        const charCounts = new Map();
        for (const token of tokens) {
          for (const char of token) {
            charCounts.set(char, (charCounts.get(char) || 0) + 1);
          }
        }
        
        // All characters should appear with roughly equal frequency
        const counts = Array.from(charCounts.values());
        const mean = counts.reduce((a, b) => a + b) / counts.length;
        const variance = counts.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / counts.length;
        const stdDev = Math.sqrt(variance);
        
        // Standard deviation should be small relative to mean
        expect(stdDev / mean).toBeLessThan(0.1);
      });
    });

    describe('Authorization Code Injection', () => {
      it('should bind authorization codes to specific redirect URIs', async () => {
        const code = await getAuthCode({
          redirect_uri: 'https://example.com/callback',
        });
        
        // Try to exchange with different redirect_uri
        const response = await exchangeCode(code, {
          redirect_uri: 'https://example.com/different',
        });
        
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe('invalid_grant');
      });
    });

    describe('Token Substitution Attack', () => {
      it('should not allow access tokens from one grant to access another', async () => {
        const token1 = await getAccessToken({ userId: 'user1' });
        const token2 = await getAccessToken({ userId: 'user2' });
        
        // Extract grantId from token2, try to use with token1's secret
        const [_, grantId2] = token2.split(':');
        const [userId1, _, secret1] = token1.split(':');
        const forgedToken = `${userId1}:${grantId2}:${secret1}`;
        
        const response = await worker.fetch('/api/protected', {
          headers: {
            'Authorization': `Bearer ${forgedToken}`,
          },
        });
        
        expect(response.status).toBe(401);
      });
    });

    describe('Refresh Token Hijacking', () => {
      it('should invalidate refresh tokens if used from different IP', async () => {
        const { refresh_token } = await getTokens();
        
        // First refresh from IP1
        const response1 = await refreshToken(refresh_token, {
          headers: { 'CF-Connecting-IP': '1.2.3.4' },
        });
        expect(response1.status).toBe(200);
        
        // Attempt refresh from different IP with same token
        const response2 = await refreshToken(refresh_token, {
          headers: { 'CF-Connecting-IP': '5.6.7.8' },
        });
        
        // Should detect anomaly and revoke grant
        expect(response2.status).toBe(400);
      });
    });

    describe('Client Impersonation', () => {
      it('should not allow public clients to impersonate confidential clients', async () => {
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=authorization_code&code=test&client_id=confidential-client',
          // Attempting to use confidential client without secret
        });
        
        expect(response.status).toBe(401);
      });
    });

    describe('Timing Attacks', () => {
      it('should use constant-time comparison for secrets', async () => {
        const timings = [];
        
        // Test with increasingly similar secrets
        const secrets = [
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          'baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbba',
          'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        ];
        
        for (const secret of secrets) {
          const start = performance.now();
          await worker.fetch('/token', {
            method: 'POST',
            headers: {
              'Authorization': 'Basic ' + btoa(`client:${secret}`),
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'grant_type=authorization_code&code=test',
          });
          const end = performance.now();
          timings.push(end - start);
        }
        
        // Timings should not correlate with similarity
        const variance = Math.var(timings);
        expect(variance).toBeLessThan(1); // Less than 1ms variance
      });
    });

    describe('Resource Exhaustion', () => {
      it('should rate limit token requests per client', async () => {
        const promises = [];
        
        // Attempt 100 rapid requests
        for (let i = 0; i < 100; i++) {
          promises.push(exchangeCode(`code-${i}`));
        }
        
        const responses = await Promise.all(promises);
        const tooManyRequests = responses.filter(r => r.status === 429);
        
        expect(tooManyRequests.length).toBeGreaterThan(0);
      });

      it('should limit number of active tokens per grant', async () => {
        const { refresh_token } = await getTokens();
        const tokens = [];
        
        // Try to create many access tokens
        for (let i = 0; i < 100; i++) {
          const response = await refreshToken(refresh_token);
          if (response.ok) {
            const body = await response.json();
            tokens.push(body.access_token);
          }
        }
        
        // Should limit tokens per grant
        expect(tokens.length).toBeLessThan(10);
      });
    });

    describe('Malformed Input Handling', () => {
      it('should safely handle extremely long input', async () => {
        const longString = 'a'.repeat(1000000); // 1MB string
        
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: `grant_type=authorization_code&code=${longString}`,
        });
        
        expect(response.status).toBe(413); // Payload too large
      });

      it('should handle null bytes in input', async () => {
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=authorization_code&code=test\x00injected',
        });
        
        expect(response.status).toBe(400);
      });

      it('should reject non-UTF8 input', async () => {
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: Buffer.from([0xFF, 0xFE, 0xFD]), // Invalid UTF-8
        });
        
        expect(response.status).toBe(400);
      });
    });

    describe('Cache Poisoning', () => {
      it('should include appropriate cache headers', async () => {
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=authorization_code&code=test',
        });
        
        expect(response.headers.get('Cache-Control')).toBe('no-store');
        expect(response.headers.get('Pragma')).toBe('no-cache');
      });
    });

    describe('Open Redirect Protection', () => {
      it('should reject redirect URIs with dangerous schemes', async () => {
        const dangerousUris = [
          'javascript:alert(1)',
          'data:text/html,<script>alert(1)</script>',
          'file:///etc/passwd',
          'about:blank',
          'vbscript:alert(1)',
        ];
        
        for (const uri of dangerousUris) {
          const response = await completeAuthorization({
            redirect_uri: uri,
          });
          
          expect(response).toThrow('Invalid redirect URI');
        }
      });

      it('should validate redirect URI host strictly', async () => {
        // Register client with specific redirect URI
        const client = await createClient({
          redirect_uris: ['https://example.com/callback'],
        });
        
        // Attempt authorization with subdomain
        const response = await parseAuthRequest({
          client_id: client.client_id,
          redirect_uri: 'https://evil.example.com/callback',
        });
        
        expect(response).toThrow('Invalid redirect URI');
      });
    });

    describe('JSON Injection', () => {
      it('should safely handle special characters in JSON responses', async () => {
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=authorization_code&code=test</script><script>alert(1)</script>',
        });
        
        const text = await response.text();
        // Ensure < and > are escaped in JSON
        expect(text).not.toContain('<script>');
        expect(text).toContain('\\u003c');
      });
    });

    describe('State Parameter Validation', () => {
      it('should preserve state parameter exactly as provided', async () => {
        const states = [
          'simple',
          'with spaces',
          'with-special-chars!@#$%^&*()',
          '{"json":"data"}',
          'unicode-测试-тест',
        ];
        
        for (const state of states) {
          const result = await completeAuthorization({
            state: state,
          });
          
          const url = new URL(result.redirectTo);
          expect(url.searchParams.get('state')).toBe(state);
        }
      });
    });

    describe('Cryptographic Key Confusion', () => {
      it('should not allow token ID to decrypt wrapped keys', async () => {
        // This tests the HMAC-based key derivation separation
        const token = await getAccessToken();
        const tokenId = await generateTokenId(token);
        
        // Attempt to derive wrapping key from token ID
        const fakeWrapper = await crypto.subtle.digest('SHA-256', 
          new TextEncoder().encode(tokenId)
        );
        
        // Try to unwrap a key using the derived wrapper
        const wrapped = 'some-wrapped-key-data';
        await expect(
          unwrapKeyWithDerivedKey(fakeWrapper, wrapped)
        ).rejects.toThrow();
      });
    });

    describe('Grant Confusion Attack', () => {
      it('should isolate grants between users completely', async () => {
        const user1Grant = await createGrant({ userId: 'user1' });
        const user2Grant = await createGrant({ userId: 'user2' });
        
        // Try to use user1's token with user2's grant ID
        const [_, _, secret] = user1Grant.access_token.split(':');
        const forgedToken = `user1:${user2Grant.id}:${secret}`;
        
        const response = await worker.fetch('/api/protected', {
          headers: {
            'Authorization': `Bearer ${forgedToken}`,
          },
        });
        
        expect(response.status).toBe(401);
      });
    });

    describe('Content-Type Confusion', () => {
      it('should reject non-form-encoded token requests', async () => {
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            grant_type: 'authorization_code',
            code: 'test',
          }),
        });
        
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error_description).toContain('Content-Type');
      });
    });

    describe('Security Headers', () => {
      it('should include security headers in all responses', async () => {
        const response = await worker.fetch('/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=authorization_code&code=test',
        });
        
        expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
        expect(response.headers.get('X-Frame-Options')).toBe('DENY');
        expect(response.headers.get('Strict-Transport-Security')).toMatch(/max-age=/);
        expect(response.headers.get('Content-Security-Policy')).toBeTruthy();
      });
    });

    describe('Unicode Normalization Attacks', () => {
      it('should handle Unicode normalization consistently', async () => {
        // Test different Unicode representations of "é"
        const representations = [
          '\u00e9',        // é (single character)
          '\u0065\u0301',  // e + combining accent
        ];
        
        for (const repr of representations) {
          const clientId = `client-${repr}`;
          const response = await lookupClient(clientId);
          
          // Should treat both as same client
          expect(response).toBeTruthy();
        }
      });
    });
  });

  // Helper functions
  async function parseAuthRequest(params: Record<string, string>) {
    const url = new URL('https://example.com/authorize');
    Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
    
    const request = new Request(url.toString());
    return worker.fetch(request);
  }

  async function exchangeCode(code: string, options = {}) {
    return worker.fetch('/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...options.headers,
      },
      body: `grant_type=authorization_code&code=${code}&${new URLSearchParams(options).toString()}`,
    });
  }

  async function refreshToken(refreshToken: string, options = {}) {
    return worker.fetch('/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...options.headers,
      },
      body: `grant_type=refresh_token&refresh_token=${refreshToken}`,
    });
  }

  // ... Additional helper functions
});
