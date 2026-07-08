import {
  getStorageCapability,
  MUTATION_CAPABILITY_PATHS,
  QUERY_CAPABILITY_PATHS,
  type MutationCapabilityPath,
  defineOAuthStorageCapabilities,
  type MutationGuarantee,
  type OAuthStorageCapabilities,
  type QueryCapabilityPath,
  type QueryGuarantee,
  type StorageCapabilityPath,
} from './capabilities';

/** Effect of an unmet requirement on a feature. */
export type StorageRequirementConsequence = 'warn' | 'reject';

/** Minimum mutation guarantee required by a feature. */
export interface MutationStorageRequirement {
  readonly capability: MutationCapabilityPath;
  readonly minimum: Exclude<MutationGuarantee, 'unsupported'>;
  readonly consequence: StorageRequirementConsequence;
}

/** Minimum query visibility required by a feature. */
export interface QueryStorageRequirement {
  readonly capability: QueryCapabilityPath;
  readonly minimum: Exclude<QueryGuarantee, 'unsupported'>;
  readonly consequence: StorageRequirementConsequence;
}

/** One semantic storage requirement. */
export type StorageRequirement = MutationStorageRequirement | QueryStorageRequirement;

/** Named feature and all storage guarantees it requires. */
export interface StorageFeatureRequirement {
  readonly feature: string;
  readonly requirements: readonly StorageRequirement[];
}

/** One unmet requirement included in a compatibility report. */
export interface UnmetStorageRequirement {
  readonly capability: StorageCapabilityPath;
  readonly minimum: Exclude<MutationGuarantee | QueryGuarantee, 'unsupported'>;
  readonly actual: MutationGuarantee | QueryGuarantee;
  readonly consequence: StorageRequirementConsequence;
}

/** Compatibility result for one OAuth feature or helper. */
export interface StorageFeatureCompatibility {
  readonly status: 'full' | 'compatibility' | 'unavailable';
  readonly missingCapabilities: readonly StorageCapabilityPath[];
  readonly unmetRequirements: readonly UnmetStorageRequirement[];
}

/** Complete static report for an adapter and enabled feature set. */
export interface OAuthStorageCompatibilityReport {
  readonly adapterId: string;
  readonly contractVersion: 1;
  readonly overall: 'full' | 'compatibility' | 'unavailable';
  readonly features: Readonly<Record<string, StorageFeatureCompatibility>>;
}

const mutationPaths = new Set<string>(MUTATION_CAPABILITY_PATHS);
const queryPaths = new Set<string>(QUERY_CAPABILITY_PATHS);
const mutationRank: Readonly<Record<MutationGuarantee, number>> = Object.freeze({
  unsupported: 0,
  best_effort: 1,
  strong: 2,
});
const queryRank: Readonly<Record<QueryGuarantee, number>> = Object.freeze({
  unsupported: 0,
  eventual: 1,
  session: 2,
  strong: 3,
});

/** Validates, copies, and freezes a feature requirement registry. */
export function defineStorageFeatureRequirements(
  features: readonly StorageFeatureRequirement[]
): readonly StorageFeatureRequirement[] {
  const names = new Set<string>();
  const copy = features.map((feature) => {
    if (!/^[a-z][a-z0-9.-]{0,79}$/.test(feature.feature)) {
      throw new TypeError('Storage feature name must be a stable lowercase identifier');
    }
    if (names.has(feature.feature)) throw new TypeError(`Duplicate storage feature: ${feature.feature}`);
    names.add(feature.feature);

    const requirements = feature.requirements.map((requirement) => {
      validateRequirement(requirement);
      return Object.freeze({ ...requirement });
    });
    return Object.freeze({ feature: feature.feature, requirements: Object.freeze(requirements) });
  });
  return Object.freeze(copy);
}

/**
 * Resolves every requirement without opening storage.
 *
 * The resolver intentionally reports all unmet requirements so one deployment
 * change is not followed by a sequence of one-at-a-time constructor failures.
 */
export function resolveOAuthStorageCompatibility(input: {
  readonly adapterId: string;
  readonly capabilities: OAuthStorageCapabilities;
  readonly features: readonly StorageFeatureRequirement[];
}): OAuthStorageCompatibilityReport {
  if (!/^[a-z][a-z0-9.-]{0,63}$/.test(input.adapterId)) {
    throw new TypeError('Storage adapter ID must be a stable lowercase identifier');
  }
  const capabilities = defineOAuthStorageCapabilities(input.capabilities);
  const features = defineStorageFeatureRequirements(input.features);
  const results: Record<string, StorageFeatureCompatibility> = Object.create(null) as Record<
    string,
    StorageFeatureCompatibility
  >;
  let overall: OAuthStorageCompatibilityReport['overall'] = 'full';

  for (const feature of features) {
    const unmet = feature.requirements.flatMap((requirement): UnmetStorageRequirement[] => {
      const actual = getCapability(capabilities, requirement.capability);
      return satisfiesRequirement(actual, requirement)
        ? []
        : [
            Object.freeze({
              capability: requirement.capability,
              minimum: requirement.minimum,
              actual,
              consequence: requirement.consequence,
            }),
          ];
    });

    const status: StorageFeatureCompatibility['status'] = unmet.some((item) => item.consequence === 'reject')
      ? 'unavailable'
      : unmet.length > 0
        ? 'compatibility'
        : 'full';
    if (status === 'unavailable') overall = 'unavailable';
    else if (status === 'compatibility' && overall === 'full') overall = 'compatibility';

    results[feature.feature] = Object.freeze({
      status,
      missingCapabilities: Object.freeze(unmet.map((item) => item.capability)),
      unmetRequirements: Object.freeze(unmet),
    });
  }

  return Object.freeze({
    adapterId: input.adapterId,
    contractVersion: 1,
    overall,
    features: Object.freeze(results),
  });
}

function getCapability(
  capabilities: OAuthStorageCapabilities,
  path: StorageCapabilityPath
): MutationGuarantee | QueryGuarantee {
  if (mutationPaths.has(path)) return getStorageCapability(capabilities, path as MutationCapabilityPath);
  return getStorageCapability(capabilities, path as QueryCapabilityPath);
}

function satisfiesRequirement(actual: MutationGuarantee | QueryGuarantee, requirement: StorageRequirement): boolean {
  if (mutationPaths.has(requirement.capability)) {
    return mutationRank[actual as MutationGuarantee] >= mutationRank[requirement.minimum as MutationGuarantee];
  }
  return queryRank[actual as QueryGuarantee] >= queryRank[requirement.minimum as QueryGuarantee];
}

function validateRequirement(requirement: StorageRequirement): void {
  if (requirement.consequence !== 'warn' && requirement.consequence !== 'reject') {
    throw new TypeError(`Invalid consequence for ${requirement.capability}`);
  }
  if (mutationPaths.has(requirement.capability)) {
    if (requirement.minimum !== 'best_effort' && requirement.minimum !== 'strong') {
      throw new TypeError(`Invalid mutation minimum for ${requirement.capability}`);
    }
    return;
  }
  if (!queryPaths.has(requirement.capability)) {
    throw new TypeError(`Unknown storage capability: ${requirement.capability}`);
  }
  if (requirement.minimum !== 'eventual' && requirement.minimum !== 'session' && requirement.minimum !== 'strong') {
    throw new TypeError(`Invalid query minimum for ${requirement.capability}`);
  }
}
