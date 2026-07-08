import { OAuthStorageError } from './errors';

/** Strength advertised for a mutating domain operation. */
export type MutationGuarantee = 'strong' | 'best_effort' | 'unsupported';

/** Visibility advertised for a query or successful mutation. */
export type QueryGuarantee = 'strong' | 'session' | 'eventual' | 'unsupported';

/** Physical cleanup mechanism. Logical expiration remains authoritative. */
export type ExpirationCleanup = 'native' | 'scheduled' | 'manual';

/** Explicit semantic guarantees advertised before a storage connection is opened. */
export interface OAuthStorageCapabilities {
  /** Cross-request visibility of successful writes. */
  readonly consistency: {
    readonly readAfterWrite: Exclude<QueryGuarantee, 'unsupported'>;
  };
  /** Stored-client mutation guarantees. */
  readonly clients: {
    readonly create: MutationGuarantee;
    readonly replace: MutationGuarantee;
  };
  /**
   * Composite grant and access-token issuance guarantees.
   *
   * Each value covers the complete requested `grants.issue` effect set,
   * including a registered-client guard. `replaceUserClientGrants` also covers
   * an optional initial access token in the same operation.
   */
  readonly issuance: {
    readonly grantOnly: MutationGuarantee;
    readonly grantWithAccessToken: MutationGuarantee;
    readonly replaceUserClientGrants: MutationGuarantee;
    /** Creates an access token only while its backing grant revision remains active. */
    readonly existingGrantAccessToken: MutationGuarantee;
  };
  /** Single-credential grant transition guarantees. */
  readonly transitions: {
    readonly authorizationCode: MutationGuarantee;
    readonly refreshToken: MutationGuarantee;
  };
  /** Atomic set-if-absent replay reservation. */
  readonly replayReservation: MutationGuarantee;
  /** Token, grant, and client revocation guarantees. */
  readonly revocation: {
    readonly accessToken: MutationGuarantee;
    readonly grantCascade: MutationGuarantee;
    readonly clientCascade: MutationGuarantee;
  };
  /** Persistent-consent mutation guarantees. */
  readonly consents: {
    readonly compareAndSwap: MutationGuarantee;
    readonly delete: MutationGuarantee;
  };
  /** Indexed query guarantees. */
  readonly queries: {
    readonly listClients: QueryGuarantee;
    readonly grantsByUser: QueryGuarantee;
    readonly grantsByClient: QueryGuarantee;
    readonly tokensByGrant: QueryGuarantee;
    readonly consentsByUser: QueryGuarantee;
    readonly globalMaintenance: QueryGuarantee;
  };
  /** Expiration and physical-cleanup characteristics. */
  readonly expiration: {
    readonly cleanup: ExpirationCleanup;
    readonly minimumTtlSeconds: number;
  };
}

/** All paths whose values use {@link MutationGuarantee}. */
export const MUTATION_CAPABILITY_PATHS = Object.freeze([
  'clients.create',
  'clients.replace',
  'issuance.grantOnly',
  'issuance.grantWithAccessToken',
  'issuance.replaceUserClientGrants',
  'issuance.existingGrantAccessToken',
  'transitions.authorizationCode',
  'transitions.refreshToken',
  'replayReservation',
  'revocation.accessToken',
  'revocation.grantCascade',
  'revocation.clientCascade',
  'consents.compareAndSwap',
  'consents.delete',
] as const);

/** Paths whose values use {@link MutationGuarantee}. */
export type MutationCapabilityPath = (typeof MUTATION_CAPABILITY_PATHS)[number];

/** All paths whose values use {@link QueryGuarantee}. */
export const QUERY_CAPABILITY_PATHS = Object.freeze([
  'consistency.readAfterWrite',
  'queries.listClients',
  'queries.grantsByUser',
  'queries.grantsByClient',
  'queries.tokensByGrant',
  'queries.consentsByUser',
  'queries.globalMaintenance',
] as const);

/** Paths whose values use {@link QueryGuarantee}. */
export type QueryCapabilityPath = (typeof QUERY_CAPABILITY_PATHS)[number];

/** Capability paths accepted by compatibility requirements. */
export type StorageCapabilityPath = MutationCapabilityPath | QueryCapabilityPath;

/** All requirement-capable descriptor paths in stable order. */
export const STORAGE_CAPABILITY_PATHS: readonly StorageCapabilityPath[] = Object.freeze([
  ...MUTATION_CAPABILITY_PATHS,
  ...QUERY_CAPABILITY_PATHS,
]);

/**
 * Validates, copies, and deeply freezes a capability descriptor.
 *
 * Copying avoids freezing an object owned by adapter configuration code.
 */
export function defineOAuthStorageCapabilities(input: OAuthStorageCapabilities): OAuthStorageCapabilities {
  for (const path of MUTATION_CAPABILITY_PATHS) {
    assertMutationGuarantee(readCapability(input, path), path);
  }
  for (const path of QUERY_CAPABILITY_PATHS) {
    assertQueryGuarantee(readCapability(input, path), path, path === 'consistency.readAfterWrite');
  }
  if (!['native', 'scheduled', 'manual'].includes(input.expiration.cleanup)) {
    throw new TypeError('Invalid expiration cleanup capability');
  }
  if (!Number.isSafeInteger(input.expiration.minimumTtlSeconds) || input.expiration.minimumTtlSeconds < 0) {
    throw new TypeError('minimumTtlSeconds must be a non-negative safe integer');
  }

  return deepFreeze({
    consistency: { ...input.consistency },
    clients: { ...input.clients },
    issuance: { ...input.issuance },
    transitions: { ...input.transitions },
    replayReservation: input.replayReservation,
    revocation: { ...input.revocation },
    consents: { ...input.consents },
    queries: { ...input.queries },
    expiration: { ...input.expiration },
  });
}

/** Returns a capability value for a statically valid path. */
export function getStorageCapability(
  capabilities: OAuthStorageCapabilities,
  path: MutationCapabilityPath
): MutationGuarantee;
/** Returns a capability value for a statically valid path. */
export function getStorageCapability(capabilities: OAuthStorageCapabilities, path: QueryCapabilityPath): QueryGuarantee;
export function getStorageCapability(
  capabilities: OAuthStorageCapabilities,
  path: StorageCapabilityPath
): MutationGuarantee | QueryGuarantee {
  return readCapability(capabilities, path) as MutationGuarantee | QueryGuarantee;
}

/**
 * Throws the standard error before backend I/O when an operation is unavailable.
 *
 * Store methods remain structurally uniform across adapters. An adapter that
 * advertises `unsupported` must call this guard before any read or write.
 */
export function assertStorageOperationSupported(guarantee: MutationGuarantee, operation: string): void {
  if (guarantee === 'unsupported') {
    throw new OAuthStorageError('unsupported_operation', { operation });
  }
}

function readCapability(capabilities: OAuthStorageCapabilities, path: StorageCapabilityPath): unknown {
  if (path === 'replayReservation') return capabilities.replayReservation;
  const [group, member] = path.split('.') as [
    'consistency' | 'clients' | 'issuance' | 'transitions' | 'revocation' | 'consents' | 'queries',
    string,
  ];
  return (capabilities[group] as Readonly<Record<string, unknown>>)[member];
}

function assertMutationGuarantee(value: unknown, path: string): asserts value is MutationGuarantee {
  if (value !== 'strong' && value !== 'best_effort' && value !== 'unsupported') {
    throw new TypeError(`Invalid mutation guarantee at ${path}`);
  }
}

function assertQueryGuarantee(
  value: unknown,
  path: string,
  required: boolean
): asserts value is QueryGuarantee | Exclude<QueryGuarantee, 'unsupported'> {
  const valid =
    value === 'strong' || value === 'session' || value === 'eventual' || (!required && value === 'unsupported');
  if (!valid) throw new TypeError(`Invalid query guarantee at ${path}`);
}

function deepFreeze<T extends object>(value: T): T {
  for (const child of Object.values(value)) {
    if (child !== null && typeof child === 'object') deepFreeze(child as object);
  }
  return Object.freeze(value);
}
