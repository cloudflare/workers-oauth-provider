import type { AccessTokenKey, GrantKey } from '../records';

const DEFAULT_NAMESPACE = 'default';
const CLIENT_PREFIX = 'client:';
const GRANT_PREFIX = 'grant:';
const TOKEN_PREFIX = 'token:';
const REPLAY_PREFIX = 'enterprise-jti:';

/** Returns the collision-safe physical prefix for a logical storage namespace. */
export function kvNamespacePrefix(namespace: string): string {
  return namespace === DEFAULT_NAMESPACE ? '' : `oauth:${encodeURIComponent(namespace)}:`;
}

/** Returns the exact legacy client key in the default namespace. */
export function kvClientKey(namespace: string, clientId: string): string {
  return `${kvNamespacePrefix(namespace)}${CLIENT_PREFIX}${clientId}`;
}

/** Returns the exact legacy client-list prefix in the default namespace. */
export function kvClientPrefix(namespace: string): string {
  return `${kvNamespacePrefix(namespace)}${CLIENT_PREFIX}`;
}

/** Returns the exact legacy grant key in the default namespace. */
export function kvGrantKey(namespace: string, grant: GrantKey): string {
  return `${kvGrantPrefix(namespace, grant.userId)}${grant.grantId}`;
}

/** Returns a user-scoped or global grant prefix. */
export function kvGrantPrefix(namespace: string, userId?: string): string {
  return `${kvNamespacePrefix(namespace)}${GRANT_PREFIX}${userId === undefined ? '' : `${userId}:`}`;
}

/** Returns the exact legacy access-token key in the default namespace. */
export function kvAccessTokenKey(namespace: string, token: AccessTokenKey): string {
  return `${kvAccessTokenPrefix(namespace, token)}${token.tokenId}`;
}

/** Returns a grant-scoped or global access-token prefix. */
export function kvAccessTokenPrefix(namespace: string, grant?: GrantKey): string {
  return `${kvNamespacePrefix(namespace)}${TOKEN_PREFIX}${grant === undefined ? '' : `${grant.userId}:${grant.grantId}:`}`;
}

/** Returns the exact legacy EMA replay-marker key in the default namespace. */
export function kvReplayKey(namespace: string, reservationNamespace: string, keyHash: string): string {
  const prefix =
    reservationNamespace === 'ema-jti' ? REPLAY_PREFIX : `replay:${encodeURIComponent(reservationNamespace)}:`;
  return `${kvNamespacePrefix(namespace)}${prefix}${keyHash}`;
}
