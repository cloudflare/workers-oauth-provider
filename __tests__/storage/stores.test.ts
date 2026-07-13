import { describe, expect, it } from 'vitest';
import {
  assertIssueGrantSupported,
  compareAndSwapConsentInput,
  createStoredConsent,
  createClientInput,
  getIssueGrantGuarantee,
  issueAccessTokenInput,
  issueGrantInput,
  rejectUnsupportedStorageOperation,
  replaceClientInput,
} from '../../src/storage';
import { storageCapabilities, storedAccessToken, storedClient, storedGrant } from './fixtures';

describe('OAuth storage mutation plans', () => {
  it('validates initial client creation and successor replacement', () => {
    expect(createClientInput(storedClient(0)).client.metadata.revision).toBe(0);
    expect(replaceClientInput('client-1', 2, storedClient(3)).client.metadata.revision).toBe(3);
    expect(() => createClientInput(storedClient(1))).toThrow(TypeError);
    expect(() => replaceClientInput('client-1', 2, storedClient(2))).toThrow(TypeError);
    expect(() => replaceClientInput('different-client', 2, storedClient(3))).toThrow(TypeError);
    expect(() =>
      createClientInput({
        value: storedClient(0).value,
        metadata: storedClient(0).metadata,
      } as never)
    ).toThrow(TypeError);
  });

  it('validates a composite registered-client grant and token issue plan', () => {
    const input = issueGrantInput({
      client: { kind: 'registered', clientId: 'client-1', expectedRevision: 4 },
      grant: storedGrant(0),
      accessToken: storedAccessToken(0),
      replaceExistingUserClientGrants: true,
    });

    expect(input.client.kind).toBe('registered');
    expect(input.replaceExistingUserClientGrants).toBe(true);
    expect(Object.isFrozen(input)).toBe(true);
  });

  it.each([
    [
      'non-initial grant revision',
      () =>
        issueGrantInput({
          client: { kind: 'external', clientId: 'client-1' },
          grant: storedGrant(1),
        }),
    ],
    [
      'mismatched client',
      () =>
        issueGrantInput({
          client: { kind: 'external', clientId: 'client-2' },
          grant: storedGrant(0),
        }),
    ],
    [
      'mismatched token parent',
      () =>
        issueGrantInput({
          client: { kind: 'external', clientId: 'client-1' },
          grant: storedGrant(0),
          accessToken: storedAccessToken(0, { grantId: 'grant-2' }),
        }),
    ],
    [
      'non-initial token revision',
      () =>
        issueGrantInput({
          client: { kind: 'external', clientId: 'client-1' },
          grant: storedGrant(0),
          accessToken: storedAccessToken(1),
        }),
    ],
  ])('rejects %s', (_name, action) => {
    expect(action).toThrow(TypeError);
  });

  it('selects one capability for the complete requested issue effect set', () => {
    const capabilities = storageCapabilities({
      issuance: {
        grantOnly: 'strong',
        grantWithAccessToken: 'best_effort',
        replaceUserClientGrants: 'unsupported',
        existingGrantAccessToken: 'strong',
      },
    });
    const grantOnly = issueGrantInput({
      client: { kind: 'external', clientId: 'client-1' },
      grant: storedGrant(0),
    });
    const withToken = issueGrantInput({
      client: { kind: 'external', clientId: 'client-1' },
      grant: storedGrant(0),
      accessToken: storedAccessToken(0),
    });
    const replacing = issueGrantInput({
      client: { kind: 'registered', clientId: 'client-1', expectedRevision: 0 },
      grant: storedGrant(0),
      accessToken: storedAccessToken(0),
      replaceExistingUserClientGrants: true,
    });

    expect(getIssueGrantGuarantee(capabilities, grantOnly)).toBe('strong');
    expect(getIssueGrantGuarantee(capabilities, withToken)).toBe('best_effort');
    expect(getIssueGrantGuarantee(capabilities, replacing)).toBe('unsupported');
    expect(() => assertIssueGrantSupported(capabilities, replacing)).toThrowError(
      expect.objectContaining({ code: 'unsupported_operation', operation: 'grants.issue' })
    );
  });

  it('validates existing-grant access-token issuance', () => {
    const input = issueAccessTokenInput({
      grant: { userId: 'user-1', grantId: 'grant-1' },
      expectedGrantRevision: 3,
      token: storedAccessToken(0),
    });

    expect(input.expectedGrantRevision).toBe(3);
    expect(() =>
      issueAccessTokenInput({
        grant: { userId: 'user-1', grantId: 'grant-2' },
        expectedGrantRevision: 3,
        token: storedAccessToken(0),
      })
    ).toThrow(TypeError);
  });

  it('validates consent insert and immediate-successor plans', () => {
    const consent = (revision: number) =>
      createStoredConsent(
        {
          userId: 'user-1',
          clientId: 'client-1',
          scope: ['read'],
          updatedAt: 120,
        },
        { schemaVersion: 1, revision, createdAt: 100 }
      );

    expect(compareAndSwapConsentInput({ consent: consent(0) }).consent.metadata.revision).toBe(0);
    expect(compareAndSwapConsentInput({ consent: consent(3), expectedRevision: 2 }).consent.metadata.revision).toBe(3);
    expect(() => compareAndSwapConsentInput({ consent: consent(2), expectedRevision: 2 })).toThrow(TypeError);
  });

  it('provides a standard no-side-effect unsupported implementation', async () => {
    await expect(rejectUnsupportedStorageOperation('replay.reserve')).rejects.toMatchObject({
      code: 'unsupported_operation',
      operation: 'replay.reserve',
    });
  });
});
