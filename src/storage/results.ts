/** Insert-if-absent result. */
export type CreateResult = { readonly status: 'created' } | { readonly status: 'conflict' };

/** Compare-and-swap replacement result. */
export type ReplaceResult =
  | { readonly status: 'updated' }
  | { readonly status: 'conflict' }
  | { readonly status: 'not_found' };

/** Guarded deletion result. */
export type DeleteResult =
  | { readonly status: 'deleted' }
  | { readonly status: 'conflict' }
  | { readonly status: 'not_found' };

/** Atomic client and child-record cascade outcome. */
export type DeleteClientResult =
  | {
      readonly status: 'deleted';
      readonly deletedGrants: number;
      readonly deletedAccessTokens: number;
    }
  | { readonly status: 'conflict' }
  | { readonly status: 'not_found' };

/** Grant issuance outcome, including registered-client guard failures. */
export type IssueGrantResult =
  | { readonly status: 'created' }
  | { readonly status: 'conflict' }
  | { readonly status: 'client_not_found' }
  | { readonly status: 'client_conflict' };

/** Guarded access-token issuance outcome. */
export type IssueAccessTokenResult =
  | { readonly status: 'created' }
  | { readonly status: 'conflict' }
  | { readonly status: 'grant_not_found' }
  | { readonly status: 'grant_conflict' };

/** Grant and child-token cascade outcome. */
export type RevokeGrantResult =
  | { readonly status: 'revoked'; readonly deletedAccessTokens: number }
  | { readonly status: 'conflict' }
  | { readonly status: 'not_found' };

/** Compare-and-swap consent outcome. */
export type ReplaceConsentResult =
  | { readonly status: 'created' }
  | { readonly status: 'updated' }
  | { readonly status: 'conflict' };

/** Atomic replay reservation outcome. */
export type ReplayReservationResult = { readonly status: 'reserved' } | { readonly status: 'exists' };
