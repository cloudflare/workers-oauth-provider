import { describe, expect, it } from 'vitest';
import {
  defineOAuthStorageCapabilities,
  defineStorageFeatureRequirements,
  resolveOAuthStorageCompatibility,
  type StorageFeatureRequirement,
} from '../../src/storage';
import { storageCapabilities } from './fixtures';

describe('OAuth storage compatibility', () => {
  it('reports every unmet warning and rejection', () => {
    const report = resolveOAuthStorageCompatibility({
      adapterId: 'cloudflare-kv',
      capabilities: defineOAuthStorageCapabilities(storageCapabilities()),
      features: [
        {
          feature: 'strict-refresh',
          requirements: [
            { capability: 'transitions.refreshToken', minimum: 'strong', consequence: 'reject' },
            { capability: 'replayReservation', minimum: 'strong', consequence: 'reject' },
            { capability: 'consistency.readAfterWrite', minimum: 'session', consequence: 'warn' },
          ],
        },
        {
          feature: 'persistent-consent',
          requirements: [
            { capability: 'consents.compareAndSwap', minimum: 'best_effort', consequence: 'warn' },
            { capability: 'queries.consentsByUser', minimum: 'eventual', consequence: 'warn' },
          ],
        },
      ],
    });

    expect(report.overall).toBe('unavailable');
    expect(report.features['strict-refresh']).toEqual({
      status: 'unavailable',
      missingCapabilities: ['transitions.refreshToken', 'replayReservation', 'consistency.readAfterWrite'],
      unmetRequirements: [
        {
          capability: 'transitions.refreshToken',
          minimum: 'strong',
          actual: 'best_effort',
          consequence: 'reject',
        },
        {
          capability: 'replayReservation',
          minimum: 'strong',
          actual: 'best_effort',
          consequence: 'reject',
        },
        {
          capability: 'consistency.readAfterWrite',
          minimum: 'session',
          actual: 'eventual',
          consequence: 'warn',
        },
      ],
    });
    expect(report.features['persistent-consent'].status).toBe('compatibility');
    expect(report.features['persistent-consent'].missingCapabilities).toEqual([
      'consents.compareAndSwap',
      'queries.consentsByUser',
    ]);
  });

  it('returns full when every minimum is met', () => {
    const capabilities = defineOAuthStorageCapabilities(
      storageCapabilities({
        consistency: { readAfterWrite: 'strong' },
        transitions: { authorizationCode: 'strong', refreshToken: 'strong' },
      })
    );
    const report = resolveOAuthStorageCompatibility({
      adapterId: 'postgres',
      capabilities,
      features: [
        {
          feature: 'refresh',
          requirements: [
            { capability: 'transitions.refreshToken', minimum: 'strong', consequence: 'reject' },
            { capability: 'consistency.readAfterWrite', minimum: 'session', consequence: 'warn' },
          ],
        },
      ],
    });

    expect(report.overall).toBe('full');
    expect(report.features['refresh']).toEqual({
      status: 'full',
      missingCapabilities: [],
      unmetRequirements: [],
    });
    expect(Object.isFrozen(report)).toBe(true);
    expect(Object.isFrozen(report.features)).toBe(true);
  });

  it('copies and freezes the feature registry', () => {
    const input: StorageFeatureRequirement[] = [
      {
        feature: 'authorization-code',
        requirements: [
          {
            capability: 'transitions.authorizationCode',
            minimum: 'best_effort',
            consequence: 'warn',
          },
        ],
      },
    ];
    const registry = defineStorageFeatureRequirements(input);

    expect(registry).not.toBe(input);
    expect(registry[0]).not.toBe(input[0]);
    expect(Object.isFrozen(registry[0].requirements)).toBe(true);
    (input[0] as { feature: string }).feature = 'changed';
    expect(registry[0].feature).toBe('authorization-code');
  });

  it.each([
    [
      'empty adapter ID',
      () => resolveOAuthStorageCompatibility({ adapterId: '', capabilities: storageCapabilities(), features: [] }),
    ],
    [
      'non-canonical adapter ID',
      () =>
        resolveOAuthStorageCompatibility({
          adapterId: ' cloudflare-kv ',
          capabilities: storageCapabilities(),
          features: [],
        }),
    ],
    [
      'duplicate features',
      () =>
        defineStorageFeatureRequirements([
          { feature: 'same', requirements: [] },
          { feature: 'same', requirements: [] },
        ]),
    ],
    [
      'invalid feature name',
      () => defineStorageFeatureRequirements([{ feature: ' Invalid Feature ', requirements: [] }]),
    ],
    [
      'unknown capability',
      () =>
        defineStorageFeatureRequirements([
          {
            feature: 'bad',
            requirements: [
              {
                capability: 'queries.notReal',
                minimum: 'eventual',
                consequence: 'warn',
              } as never,
            ],
          },
        ]),
    ],
    [
      'mismatched minimum',
      () =>
        defineStorageFeatureRequirements([
          {
            feature: 'bad',
            requirements: [
              {
                capability: 'transitions.refreshToken',
                minimum: 'session',
                consequence: 'warn',
              } as never,
            ],
          },
        ]),
    ],
    [
      'malformed runtime descriptor',
      () =>
        resolveOAuthStorageCompatibility({
          adapterId: 'broken',
          capabilities: {
            ...storageCapabilities(),
            transitions: { authorizationCode: 'eventual', refreshToken: 'best_effort' },
          } as never,
          features: [],
        }),
    ],
  ])('rejects %s', (_name, action) => {
    expect(action).toThrow(TypeError);
  });
});
