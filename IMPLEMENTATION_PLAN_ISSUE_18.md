# Implementation Plan: Authorization Flow Configuration Steps (Issue #18)

## Problem Statement

Users need the ability to inject custom configuration steps into the OAuth authorization flow. The primary use case is allowing users to bind additional configuration (e.g., selecting an organization) during authorization, so that subsequent API calls can be implicit without requiring additional parameters.

**Example Use Case (Sentry MCP):**
1. User initiates OAuth authorization
2. Upstream OAuth completes, returning user identity
3. **[NEW STEP]** User selects which Sentry organization to bind to this MCP client
4. Authorization completes with organization binding stored in props
5. Future MCP tool calls don't require `orgId` parameter

## Current Architecture Analysis

### Existing Flow
```
1. Client redirects to /authorize
2. defaultHandler receives request
3. App calls parseAuthRequest() to get OAuth params
4. App authenticates user (upstream OAuth, etc.)
5. App calls completeAuthorization() with props
6. User redirected back to client with auth code
```

### Existing Extension Points
- `tokenExchangeCallback`: Called during token exchange (too late for UI injection)
- `resolveExternalToken`: For external token validation (not applicable)
- `onError`: Error handling callback (not applicable)

### Gap Analysis
There is **no existing mechanism** to:
1. Pause the authorization flow for custom UI steps
2. Persist intermediate state between authorization steps
3. Provide a standard pattern for multi-step authorization

## Proposed Solution: Authorization Context Manager

Add a new `AuthorizationContext` system that allows applications to:
1. Store intermediate authorization state securely
2. Resume authorization from where it left off
3. Inject custom steps with a standardized pattern

### New Types

```typescript
/**
 * Context available during authorization steps
 */
export interface AuthorizationStepContext {
  /**
   * The parsed OAuth authorization request (immutable, stored for revalidation)
   */
  authRequest: AuthRequest;

  /**
   * The authenticated user ID
   */
  userId: string;

  /**
   * Client information
   */
  clientInfo: ClientInfo;

  /**
   * Current props (can be modified)
   */
  props: any;

  /**
   * Custom step data (for multi-step flows)
   */
  stepData: Record<string, any>;

  /**
   * Session ID this pending auth is bound to (for session binding validation)
   */
  sessionId: string;
}

/**
 * Result of starting an authorization that requires additional steps
 */
export interface PendingAuthorizationResult {
  /**
   * Unique ID for this pending authorization (cryptographically secure, unguessable)
   */
  pendingAuthId: string;

  /**
   * Context data for the UI to use
   */
  context: AuthorizationStepContext;
}

/**
 * Options for creating a pending authorization
 */
export interface CreatePendingAuthorizationOptions {
  /**
   * The parsed OAuth authorization request
   */
  request: AuthRequest;

  /**
   * The authenticated user ID
   */
  userId: string;

  /**
   * Session ID to bind this authorization to (REQUIRED for security)
   * The same sessionId must be provided when completing the authorization
   */
  sessionId: string;

  /**
   * Optional metadata for the grant
   */
  metadata?: any;

  /**
   * Scopes being granted
   */
  scope: string[];

  /**
   * Initial props (optional, can be modified in steps)
   */
  initialProps?: any;

  /**
   * How long the pending auth is valid in seconds (default: 600 = 10 minutes)
   */
  ttl?: number;
}

/**
 * Options for completing a pending authorization
 */
export interface CompletePendingAuthorizationOptions {
  /**
   * The pending authorization ID
   */
  pendingAuthId: string;

  /**
   * Session ID (must match the sessionId used when creating the pending auth)
   */
  sessionId: string;

  /**
   * The final props to store with the grant
   */
  finalProps: any;

  /**
   * Optional: Override metadata
   */
  metadata?: any;

  /**
   * Optional: Override scope (must be subset of original)
   */
  scope?: string[];
}
```

### New OAuthHelpers Methods

```typescript
export interface OAuthHelpers {
  // ... existing methods ...

  /**
   * Creates a pending authorization that can be completed later.
   * Use this when you need to inject custom steps before completing authorization.
   *
   * SECURITY: The sessionId parameter is REQUIRED and will be validated on completion.
   * The application is responsible for generating and validating session IDs.
   *
   * NOTE: If a pending authorization already exists for this user+client combination,
   * it will be automatically replaced (invalidated) by the new one.
   *
   * @param options - Pending authorization options including sessionId for binding
   * @returns A pending authorization ID and context
   */
  createPendingAuthorization(
    options: CreatePendingAuthorizationOptions
  ): Promise<PendingAuthorizationResult>;

  /**
   * Updates a pending authorization with additional step data.
   * NOTE: This does NOT extend the TTL - the original expiration time is preserved.
   *
   * SECURITY: sessionId must match the original sessionId.
   *
   * @param pendingAuthId - The pending authorization ID
   * @param sessionId - Session ID (must match original)
   * @param stepData - Data to merge into the step context
   * @throws Error if sessionId doesn't match, expired, or pending auth not found
   */
  updatePendingAuthorization(
    pendingAuthId: string,
    sessionId: string,
    stepData: Record<string, any>
  ): Promise<AuthorizationStepContext>;

  /**
   * Retrieves a pending authorization context.
   *
   * SECURITY: sessionId must match the original sessionId.
   *
   * @param pendingAuthId - The pending authorization ID
   * @param sessionId - Session ID (must match original)
   * @returns The context or null if not found/expired/session mismatch
   */
  getPendingAuthorization(
    pendingAuthId: string,
    sessionId: string
  ): Promise<AuthorizationStepContext | null>;

  /**
   * Completes a pending authorization.
   *
   * SECURITY:
   * - sessionId must match the original sessionId
   * - All OAuth parameters are revalidated from the stored authRequest
   * - Best-effort duplicate prevention via KV lock (see note below)
   * - The pending auth is invalidated after successful completion
   *
   * NOTE ON DUPLICATE PREVENTION: The KV-based lock provides best-effort protection
   * against concurrent double-submit within the same session. However, KV operations
   * are not atomic, so in rare race conditions two concurrent requests may both succeed
   * in acquiring the lock. For strict single-use enforcement, applications should either:
   * 1. Use a Durable Object for atomic locking, or
   * 2. Accept that duplicate completions are possible and handle at the application level
   *
   * In practice, the existing completeAuthorization() generates unique auth codes,
   * so duplicate completion would result in two valid codes (both usable once).
   *
   * @param options - Completion options including sessionId and finalProps
   * @returns Object with redirectTo URL
   * @throws Error if sessionId doesn't match, expired, lock held, or OAuth validation fails
   */
  completePendingAuthorization(
    options: CompletePendingAuthorizationOptions
  ): Promise<{ redirectTo: string }>;

  /**
   * Cancels/invalidates a pending authorization.
   *
   * @param pendingAuthId - The pending authorization ID
   * @param sessionId - Session ID (must match original)
   */
  cancelPendingAuthorization(
    pendingAuthId: string,
    sessionId: string
  ): Promise<void>;

  /**
   * Invalidates all pending authorizations for a user.
   * Call this on user logout.
   *
   * NOTE: This method handles up to 100 pending authorizations per user.
   * The maxPendingAuthorizationsPerUser option is capped at 100.
   *
   * @param userId - The user ID
   */
  invalidateUserPendingAuthorizations(userId: string): Promise<void>;
}
```

### Usage Example

```typescript
const defaultHandler = {
  async fetch(request: Request, env, ctx) {
    const url = new URL(request.url);

    // Get or create session ID (application's responsibility)
    const sessionId = getSessionId(request) || await createSession();

    if (url.pathname === '/authorize') {
      const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      const clientInfo = await env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId);

      // Authenticate user with upstream OAuth (simplified)
      const user = await authenticateUser(request);

      // Create pending authorization for multi-step flow
      // Pass sessionId for security binding
      // NOTE: If user already has a pending auth for this client, it will be replaced
      const { pendingAuthId, context } = await env.OAUTH_PROVIDER.createPendingAuthorization({
        request: oauthReqInfo,
        userId: user.id,
        sessionId: sessionId,  // REQUIRED: Binds to this session
        scope: oauthReqInfo.scope,
        initialProps: { userId: user.id }
      });

      // Store pendingAuthId in session or pass via URL
      // Redirect to organization selection step
      return Response.redirect(`/authorize/select-org?pending=${pendingAuthId}`, 302);
    }

    if (url.pathname === '/authorize/select-org') {
      const pendingAuthId = url.searchParams.get('pending');

      // Validate session and get context
      const context = await env.OAUTH_PROVIDER.getPendingAuthorization(
        pendingAuthId,
        sessionId  // Must match original session
      );

      if (!context) {
        return new Response('Authorization expired or invalid session', { status: 400 });
      }

      if (request.method === 'GET') {
        // Render organization selection UI with CSRF token
        const orgs = await getOrganizations(context.userId);
        return renderOrgSelector(orgs, pendingAuthId, generateCsrfToken(sessionId));
      }

      if (request.method === 'POST') {
        // Validate CSRF token
        const formData = await request.formData();
        if (!validateCsrfToken(formData.get('csrf'), sessionId)) {
          return new Response('Invalid CSRF token', { status: 403 });
        }

        const selectedOrgId = formData.get('orgId');

        // Validate selectedOrgId is allowed for this user
        if (!await userCanAccessOrg(context.userId, selectedOrgId)) {
          return new Response('Invalid organization', { status: 403 });
        }

        // Complete the authorization with the selected org in props
        const { redirectTo } = await env.OAUTH_PROVIDER.completePendingAuthorization({
          pendingAuthId,
          sessionId,  // Must match original session
          finalProps: {
            userId: context.props.userId,
            orgId: selectedOrgId,
            orgSlug: await getOrgSlug(selectedOrgId)
          }
        });

        return Response.redirect(redirectTo, 302);
      }
    }

    // On logout, invalidate all pending authorizations
    if (url.pathname === '/logout') {
      const userId = getUserId(sessionId);
      await env.OAUTH_PROVIDER.invalidateUserPendingAuthorizations(userId);
      // ... rest of logout logic
    }

    return new Response('Not found', { status: 404 });
  }
};
```

## Implementation Details

### Storage Schema

**Primary key** (for lookups by pendingAuthId):
```
pending_auth:{pendingAuthId} -> PendingAuthorizationData
```

**User index** (for invalidating all user's pending auths on logout):
```
pending_auth_user_index:{userId}:{pendingAuthId} -> clientId
```
Note: Value is `clientId` (not "1") to enable proper cleanup of client index.

**Client index** (for replacing existing pending auth for same user+client):
```
pending_auth_client_index:{userId}:{clientId} -> pendingAuthId
```

**Completion lock** (for best-effort duplicate prevention):
```
pending_auth_lock:{pendingAuthId} -> "1"
```
Short TTL (30 seconds), created at start of completion, deleted on failure.

**IMPORTANT**: The completion lock is best-effort only. KV operations are not atomic,
so concurrent requests may both succeed in acquiring the lock. See "Duplicate Prevention"
section below for details.

All keys have TTL matching the pending auth TTL for automatic cleanup.

**Cleanup on completion/cancellation** - Delete all keys:
1. `pending_auth:{pendingAuthId}`
2. `pending_auth_user_index:{userId}:{pendingAuthId}`
3. `pending_auth_client_index:{userId}:{clientId}`
4. `pending_auth_lock:{pendingAuthId}` (if exists)

### Data Structure

```typescript
interface PendingAuthorizationData {
  // Identification
  id: string;                    // The pendingAuthId
  userId: string;
  sessionId: string;             // For session binding validation

  // Original OAuth request (stored for revalidation on completion)
  // All fields preserved exactly as received
  authRequest: {
    responseType: string;
    clientId: string;
    redirectUri: string;
    scope: string[];
    state: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    resource?: string | string[];
  };

  // Grant details
  scope: string[];               // Scopes being granted (may differ from requested)
  metadata: any;
  props: any;                    // Current props (may be modified by steps)
  stepData: Record<string, any>; // Custom step data

  // Timestamps (absolute, not relative)
  createdAt: number;             // Unix timestamp
  expiresAt: number;             // Unix timestamp - used for explicit expiration checks
}
```

### Security Implementation Details

#### 1. Pending Auth ID Generation
```typescript
// Use 32 bytes (256 bits) of cryptographically secure randomness
const pendingAuthId = generateRandomString(32);
```

#### 2. Session Binding Validation
```typescript
async completePendingAuthorization(options) {
  const data = await this.env.OAUTH_KV.get(`pending_auth:${options.pendingAuthId}`, { type: 'json' });

  if (!data) {
    throw new Error('Pending authorization not found or expired');
  }

  // Explicit expiration check (KV TTL might not have purged yet)
  const now = Math.floor(Date.now() / 1000);
  if (data.expiresAt <= now) {
    // Clean up expired record
    await this.cleanupPendingAuth(data.id, data.userId, data.authRequest.clientId);
    throw new Error('Pending authorization expired');
  }

  if (data.sessionId !== options.sessionId) {
    // Log this as potential attack attempt
    console.warn('Session mismatch in pending authorization completion');
    throw new Error('Session validation failed');
  }

  // Continue with completion...
}
```

#### 3. Explicit Expiration Checks

All methods that access pending auth data perform explicit expiration checks:

```typescript
// Helper function used by getPendingAuthorization, updatePendingAuthorization, completePendingAuthorization
private async loadAndValidatePendingAuth(
  pendingAuthId: string,
  sessionId: string
): Promise<PendingAuthorizationData | null> {
  const data = await this.env.OAUTH_KV.get(`pending_auth:${pendingAuthId}`, { type: 'json' });

  if (!data) {
    return null;
  }

  // Explicit expiration check
  const now = Math.floor(Date.now() / 1000);
  if (data.expiresAt <= now) {
    // Clean up expired record proactively
    await this.cleanupPendingAuth(data.id, data.userId, data.authRequest.clientId);
    return null;
  }

  // Session validation
  if (data.sessionId !== sessionId) {
    return null;
  }

  return data;
}
```

#### 4. OAuth Parameter Revalidation on Completion

When completing a pending authorization, the following validations are performed:

```typescript
async completePendingAuthorization(options) {
  // Load and validate (includes expiration and session checks)
  const data = await this.loadAndValidatePendingAuth(options.pendingAuthId, options.sessionId);
  if (!data) {
    throw new Error('Pending authorization not found, expired, or invalid session');
  }

  // Best-effort duplicate prevention via KV lock
  const lockKey = `pending_auth_lock:${options.pendingAuthId}`;
  const lockAcquired = await this.tryAcquireLock(lockKey);
  if (!lockAcquired) {
    throw new Error('Authorization completion already in progress');
  }

  try {
    // 1. Revalidate client still exists
    const clientInfo = await this.lookupClient(data.authRequest.clientId);
    if (!clientInfo) {
      throw new Error('Client no longer exists');
    }

    // 2. Revalidate redirectUri is still registered for this client
    if (!clientInfo.redirectUris.includes(data.authRequest.redirectUri)) {
      throw new Error('Redirect URI no longer valid for client');
    }

    // 3. Validate scope override is subset of original (if provided)
    if (options.scope) {
      const originalScope = new Set(data.scope);
      for (const s of options.scope) {
        if (!originalScope.has(s)) {
          throw new Error('Cannot add scopes not in original authorization');
        }
      }
    }

    // 4. Pass stored authRequest UNMODIFIED to completeAuthorization
    // This ensures responseType, state, codeChallenge, codeChallengeMethod
    // are exactly as originally received - completeAuthorization validates these
    const result = await this.completeAuthorization({
      request: data.authRequest,  // Passed unmodified
      userId: data.userId,
      metadata: options.metadata ?? data.metadata,
      scope: options.scope ?? data.scope,
      props: options.finalProps
    });

    // 5. Only after successful completion, clean up the pending auth
    await this.cleanupPendingAuth(data.id, data.userId, data.authRequest.clientId);

    return result;
  } catch (error) {
    // Release lock on failure to allow retry
    await this.env.OAUTH_KV.delete(lockKey);
    throw error;
  }
}

// Try to acquire a lock (best-effort, not atomic)
private async tryAcquireLock(lockKey: string): Promise<boolean> {
  // Check if lock exists
  const existing = await this.env.OAUTH_KV.get(lockKey);
  if (existing) {
    return false; // Lock already held
  }

  // Create lock with short TTL (30 seconds)
  // NOTE: This is NOT atomic - concurrent requests may both succeed here
  await this.env.OAUTH_KV.put(lockKey, '1', { expirationTtl: 30 });
  return true;
}
```

#### 5. Duplicate Prevention (Best-Effort vs Strict)

The KV-based completion lock provides **best-effort** duplicate prevention:

**How it works:**
- Check if lock exists → if yes, reject
- Create lock with 30s TTL → proceed
- On failure: delete lock to allow retry
- On success: delete pending auth (lock cleaned up with it)

**Limitation:**
KV operations are not atomic. In a race condition, two concurrent requests may both:
1. See no existing lock
2. Both create the lock
3. Both proceed with completion

**Impact of duplicate completion:**
- Each completion generates a unique authorization code
- Both codes would be valid (single-use each)
- Client would receive redirect with the code from whichever request completed last
- In practice, this is unlikely to cause issues as only one code is returned to the user

**For strict single-use enforcement**, applications should use a Durable Object:

```typescript
// Alternative: Strict single-use with Durable Object
export class PendingAuthLock extends DurableObject {
  async tryComplete(pendingAuthId: string): Promise<boolean> {
    const completed = await this.ctx.storage.get(`completed:${pendingAuthId}`);
    if (completed) {
      return false;
    }
    await this.ctx.storage.put(`completed:${pendingAuthId}`, true);
    return true;
  }
}
```

**Recommendation:** The best-effort KV lock is sufficient for most use cases. Document this
limitation and let applications opt into strict enforcement if needed.

#### 6. TTL Preservation on Updates

Updates do NOT extend the TTL - they preserve the original expiration:

```typescript
async updatePendingAuthorization(
  pendingAuthId: string,
  sessionId: string,
  stepData: Record<string, any>
): Promise<AuthorizationStepContext> {
  const data = await this.loadAndValidatePendingAuth(pendingAuthId, sessionId);
  if (!data) {
    throw new Error('Pending authorization not found, expired, or invalid session');
  }

  // Merge step data
  data.stepData = { ...data.stepData, ...stepData };

  // Calculate remaining TTL from absolute expiration
  const now = Math.floor(Date.now() / 1000);
  const remainingTtl = data.expiresAt - now;

  if (remainingTtl <= 0) {
    throw new Error('Pending authorization expired');
  }

  // Update with remaining TTL (does NOT extend expiration)
  await this.env.OAUTH_KV.put(
    `pending_auth:${pendingAuthId}`,
    JSON.stringify(data),
    { expirationTtl: remainingTtl }
  );

  // Fetch client info for context
  const clientInfo = await this.lookupClient(data.authRequest.clientId);

  return {
    authRequest: data.authRequest,
    userId: data.userId,
    clientInfo: clientInfo!,
    props: data.props,
    stepData: data.stepData,
    sessionId: data.sessionId
  };
}
```

#### 7. Rate Limiting
```typescript
// Add to OAuthProviderOptions
export interface OAuthProviderOptions {
  // ... existing options ...

  /**
   * Maximum pending authorizations per user.
   * Default: 5, Maximum: 100 (hard cap to ensure invalidateUserPendingAuthorizations works)
   * Prevents resource exhaustion attacks
   */
  maxPendingAuthorizationsPerUser?: number;
}
```

Implementation:
```typescript
// Hard cap to ensure invalidation works without pagination
const MAX_PENDING_AUTHS_HARD_CAP = 100;

async createPendingAuthorization(options) {
  const clientId = options.request.clientId;

  // FIRST: Check for existing pending auth for same user+client and invalidate
  // This MUST happen BEFORE rate limit check so replacement works even at capacity
  const clientIndexKey = `pending_auth_client_index:${options.userId}:${clientId}`;
  const existingPendingAuthId = await this.env.OAUTH_KV.get(clientIndexKey);

  if (existingPendingAuthId) {
    // Invalidate the old one (no session check needed for replacement)
    await this.invalidatePendingAuthInternal(existingPendingAuthId, options.userId, clientId);
  }

  // THEN: Check rate limit (after replacement invalidation, so we have room)
  const userIndexPrefix = `pending_auth_user_index:${options.userId}:`;
  const configuredMax = this.options.maxPendingAuthorizationsPerUser ?? 5;
  const maxAllowed = Math.min(configuredMax, MAX_PENDING_AUTHS_HARD_CAP);
  const existing = await this.env.OAUTH_KV.list({ prefix: userIndexPrefix, limit: maxAllowed + 1 });

  if (existing.keys.length >= maxAllowed) {
    throw new Error('Too many pending authorizations. Please complete or cancel existing ones.');
  }

  // ... continue with creation ...
}
```

#### 8. Props Sanitization
```typescript
// Sanitize props before storing (remove potentially dangerous patterns)
function sanitizeProps(props: any): any {
  if (props === null || props === undefined) return props;

  // Deep clone to avoid mutation
  const sanitized = JSON.parse(JSON.stringify(props));

  // Remove any keys that could be problematic for logging/display
  const dangerousPatterns = ['__proto__', 'constructor', 'prototype'];

  function sanitizeObject(obj: any): any {
    if (typeof obj !== 'object' || obj === null) return obj;

    for (const key of Object.keys(obj)) {
      if (dangerousPatterns.includes(key.toLowerCase())) {
        delete obj[key];
      } else {
        obj[key] = sanitizeObject(obj[key]);
      }
    }
    return obj;
  }

  return sanitizeObject(sanitized);
}
```

### Concurrent Pending Authorization Policy

**Policy: One pending auth per user+client combination**

When creating a new pending authorization for a user+client pair that already has one:
1. The existing pending auth is invalidated FIRST (before rate limit check)
2. Then rate limit is checked (so replacement works even at capacity)
3. The new pending auth is created
4. This prevents resource exhaustion while allowing retry flows

```typescript
async createPendingAuthorization(options) {
  const clientId = options.request.clientId;

  // FIRST: Check for existing pending auth for same user+client and invalidate
  // This MUST happen BEFORE rate limit check so replacement works even at capacity
  const clientIndexKey = `pending_auth_client_index:${options.userId}:${clientId}`;
  const existingPendingAuthId = await this.env.OAUTH_KV.get(clientIndexKey);

  if (existingPendingAuthId) {
    // Invalidate the old one (no session check needed for replacement)
    await this.invalidatePendingAuthInternal(existingPendingAuthId, options.userId, clientId);
  }

  // THEN: Rate limit check happens here (see Rate Limiting section above)
  // ...rate limit code...

  // Create new pending auth
  const pendingAuthId = generateRandomString(32);
  const ttl = options.ttl ?? 600;
  const now = Math.floor(Date.now() / 1000);

  const data: PendingAuthorizationData = {
    id: pendingAuthId,
    userId: options.userId,
    sessionId: options.sessionId,
    authRequest: options.request,
    scope: options.scope,
    metadata: options.metadata ?? {},
    props: sanitizeProps(options.initialProps ?? {}),
    stepData: {},
    createdAt: now,
    expiresAt: now + ttl
  };

  // Store all KV entries with TTL
  // Note: User index value is clientId (not "1") to enable proper cleanup
  await Promise.all([
    this.env.OAUTH_KV.put(`pending_auth:${pendingAuthId}`, JSON.stringify(data), { expirationTtl: ttl }),
    this.env.OAUTH_KV.put(`pending_auth_user_index:${options.userId}:${pendingAuthId}`, clientId, { expirationTtl: ttl }),
    this.env.OAUTH_KV.put(clientIndexKey, pendingAuthId, { expirationTtl: ttl })
  ]);

  // Fetch client info for context
  const clientInfo = await this.lookupClient(clientId);

  return {
    pendingAuthId,
    context: {
      authRequest: options.request,
      userId: options.userId,
      clientInfo: clientInfo!,
      props: data.props,
      stepData: data.stepData,
      sessionId: options.sessionId
    }
  };
}

// Internal invalidation - bypasses session check, used for replacement
private async invalidatePendingAuthInternal(pendingAuthId: string, userId: string, clientId: string) {
  await Promise.all([
    this.env.OAUTH_KV.delete(`pending_auth:${pendingAuthId}`),
    this.env.OAUTH_KV.delete(`pending_auth_user_index:${userId}:${pendingAuthId}`),
    this.env.OAUTH_KV.delete(`pending_auth_client_index:${userId}:${clientId}`),
    this.env.OAUTH_KV.delete(`pending_auth_lock:${pendingAuthId}`)
  ]);
}
```

### User Logout Invalidation

```typescript
async invalidateUserPendingAuthorizations(userId: string): Promise<void> {
  const userIndexPrefix = `pending_auth_user_index:${userId}:`;
  // Use hard cap + buffer to ensure we get all entries
  // maxPendingAuthorizationsPerUser is capped at 100, so 200 is safe
  const { keys } = await this.env.OAUTH_KV.list({ prefix: userIndexPrefix, limit: 200 });

  // For each pending auth, extract pendingAuthId and clientId, then cleanup
  const cleanupPromises = keys.map(async (key) => {
    // Key format: pending_auth_user_index:{userId}:{pendingAuthId}
    const pendingAuthId = key.name.substring(userIndexPrefix.length);
    // Value is the clientId
    const clientId = await this.env.OAUTH_KV.get(key.name);

    if (clientId) {
      await this.invalidatePendingAuthInternal(pendingAuthId, userId, clientId);
    } else {
      // Fallback: just delete what we can
      await Promise.all([
        this.env.OAUTH_KV.delete(`pending_auth:${pendingAuthId}`),
        this.env.OAUTH_KV.delete(key.name),
        this.env.OAUTH_KV.delete(`pending_auth_lock:${pendingAuthId}`)
      ]);
    }
  });

  await Promise.all(cleanupPromises);
}
```

## Migration Path

1. No breaking changes - new methods are additive
2. Existing `completeAuthorization()` continues to work unchanged
3. Applications can gradually adopt pending authorization flow
4. Feature is opt-in: if you don't call `createPendingAuthorization`, nothing changes

## Testing Strategy

1. **Unit tests for new OAuthHelpers methods**
   - createPendingAuthorization with valid/invalid inputs
   - Session binding validation
   - Expiration handling (both KV TTL and explicit check)
   - Replacement of existing pending auth
   - TTL preservation on update

2. **Security tests**
   - Session mismatch rejection
   - Expired pending auth rejection (explicit check before KV purge)
   - Rate limiting enforcement (including hard cap)
   - OAuth parameter revalidation (client deleted, redirectUri changed)
   - Best-effort duplicate prevention (lock behavior)
   - Replay attack prevention

3. **Integration tests**
   - Complete multi-step authorization flow
   - Concurrent authorization handling (replacement)
   - User logout invalidation
   - Transient error recovery (retry after failure with lock release)

4. **Backwards compatibility tests**
   - Existing completeAuthorization still works
   - Existing flows unaffected

## Files to Modify

1. `/src/oauth-provider.ts`:
   - Add new interfaces (`AuthorizationStepContext`, `PendingAuthorizationResult`, etc.)
   - Add new methods to `OAuthHelpers` interface
   - Implement methods in `OAuthHelpersImpl` class
   - Add `maxPendingAuthorizationsPerUser` option to `OAuthProviderOptions` (with hard cap validation)

2. `/__tests__/oauth-provider.test.ts`:
   - Add test suite for pending authorization flow
   - Security test cases

3. `/README.md`:
   - Add documentation section for multi-step authorization
   - Document best-effort vs strict duplicate prevention

4. `/CHANGELOG.md`:
   - Add changeset for the new feature

5. `/storage-schema.md`:
   - Document new KV key patterns:
     - `pending_auth:{pendingAuthId}` -> PendingAuthorizationData
     - `pending_auth_user_index:{userId}:{pendingAuthId}` -> clientId
     - `pending_auth_client_index:{userId}:{clientId}` -> pendingAuthId
     - `pending_auth_lock:{pendingAuthId}` -> "1" (30s TTL, best-effort)

## Estimated Effort

- Implementation: 3-4 days (increased due to security requirements)
- Testing: 2 days (increased for security tests)
- Documentation: 0.5 days
- Total: 5.5-6.5 days

## Open Questions (Resolved)

1. ~~Should we support multiple pending authorizations per user?~~
   **Answer:** One per user+client combination. New ones replace old ones.

2. ~~Should `completePendingAuthorization()` also support metadata updates?~~
   **Answer:** Yes, via optional `metadata` field.

3. ~~Should we add a `listPendingAuthorizations()` method?~~
   **Answer:** Not in initial implementation. Can add later if needed.

4. ~~How to handle replacement when sessions differ?~~
   **Answer:** Use internal invalidation method that bypasses session check.

5. ~~When to mark pending auth as used?~~
   **Answer:** Use best-effort lock at start, release on failure, delete on success.

6. ~~How to handle same-session double-submit?~~
   **Answer:** Best-effort KV lock. Document that it's not atomic. Provide DO alternative for strict enforcement.

7. ~~Should TTL extend on updates?~~
   **Answer:** No, use absolute expiration and compute remaining TTL.

8. ~~How does user logout cleanup know the clientId?~~
   **Answer:** Store clientId as value in user index (not "1").

9. ~~Is the completion lock atomic?~~
   **Answer:** No, KV is not atomic. Document as best-effort. Cap maxPendingAuthorizationsPerUser at 100 to ensure invalidation works without pagination.

10. ~~How to handle rate limit vs replacement ordering?~~
    **Answer:** Invalidate existing user+client pending auth FIRST, then check rate limit. This ensures replacement works even when user is at capacity.
