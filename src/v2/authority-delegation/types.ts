// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

/** First complete APS authority-delegation wire profile. */
export const AUTHORITY_DELEGATION_RECORD_TYPE = 'aps:authority-delegation:v1' as const
export const AUTHORITY_DELEGATION_VERSION = '1.0' as const

export const SCOPE_PROFILE_V1 = 'aps-hierarchical-v1' as const
export const REPUTATION_PROFILE_V1 = 'aps-score-0-100-v1' as const
export const VALUES_PROFILE_V1 = 'aps-values-identifiers-v1' as const
export const REVERSIBILITY_PROFILE_V1 = 'aps-tci-v1' as const

export interface ScopeFacetV1 {
  profile: typeof SCOPE_PROFILE_V1
  grants: string[]
}

export type SpendFacetV1 =
  | { mode: 'unbounded' }
  | {
      mode: 'bounded'
      /** Opaque, exact-match accounting unit, for example iso4217:USD:minor. */
      unit: string
      /** Canonical unsigned decimal integer. */
      per_action: string
      /** Canonical unsigned decimal integer applying to the whole delegation subtree. */
      cumulative: string
    }

export interface DepthFacetV1 {
  /** Number of further delegation hops the subject may create. */
  remaining: number
}

export interface TimeFacetV1 {
  not_before: string
  not_after: string
}

export interface ReputationFacetV1 {
  profile: typeof REPUTATION_PROFILE_V1
  ceiling: number
}

export interface ValuesFacetV1 {
  profile: typeof VALUES_PROFILE_V1
  required: string[]
}

export type ReversibilityClassV1 = 'tentative' | 'compensable' | 'irreversible'

export interface ReversibilityFacetV1 {
  profile: typeof REVERSIBILITY_PROFILE_V1
  ceiling: ReversibilityClassV1
}

export interface AuthorityVectorV1 {
  scope: ScopeFacetV1
  spend: SpendFacetV1
  depth: DepthFacetV1
  time: TimeFacetV1
  reputation: ReputationFacetV1
  values: ValuesFacetV1
  reversibility: ReversibilityFacetV1
}

export interface AuthorityDelegationBodyV1 {
  record_type: typeof AUTHORITY_DELEGATION_RECORD_TYPE
  version: typeof AUTHORITY_DELEGATION_VERSION
  /** Null only for a trust-policy-selected root. */
  parent_delegation_id: string | null
  issuer: string
  subject: string
  verification_method: string
  issued_at: string
  /** 16 random bytes encoded as 32 lowercase hexadecimal characters. */
  nonce: string
  authority: AuthorityVectorV1
}

export interface AuthorityDelegationV1 extends AuthorityDelegationBodyV1 {
  delegation_id: string
  /** Raw 64-byte Ed25519 signature encoded as 128 lowercase hexadecimal characters. */
  signature: string
}

export type AuthorityFailureCode =
  | 'SCHEMA_INVALID'
  | 'UNSUPPORTED_VERSION'
  | 'UNSUPPORTED_PROFILE'
  | 'NONCANONICAL_VALUE'
  | 'ID_MISMATCH'
  | 'KEY_RESOLUTION_FAILED'
  | 'SIGNATURE_INVALID'
  | 'ROOT_UNTRUSTED'
  | 'CHAIN_DUPLICATE_ID'
  | 'PARENT_MISMATCH'
  | 'CHAIN_CONTINUITY'
  | 'ISSUED_AT_OUTSIDE_PARENT'
  | 'SCOPE_WIDENING'
  | 'SPEND_WIDENING'
  | 'SPEND_UNIT_CHANGE'
  | 'DEPTH_EXHAUSTED'
  | 'DEPTH_WIDENING'
  | 'TIME_WIDENING'
  | 'REPUTATION_WIDENING'
  | 'VALUES_WEAKENING'
  | 'REVERSIBILITY_WIDENING'
  | 'NOT_YET_VALID'
  | 'EXPIRED'
  | 'REVOKED'
  | 'REVOCATION_UNKNOWN'

export interface AuthorityFailure {
  code: AuthorityFailureCode
  message: string
  index?: number
  facet?: keyof AuthorityVectorV1
}

export type AuthorityValidationState = 'valid' | 'invalid' | 'indeterminate' | 'unsupported'

export interface AuthorityValidationResult {
  state: AuthorityValidationState
  valid: boolean
  failures: AuthorityFailure[]
}

export type VerificationKeyResolver = (
  issuer: string,
  verificationMethod: string,
  issuedAt: string,
) => string | null

export type RevocationResolution = 'active' | 'revoked' | 'unknown'

export interface AuthorityChainVerificationOptions {
  now: string
  resolveVerificationKey: VerificationKeyResolver
  trustRoot: (root: AuthorityDelegationV1) => boolean
  resolveRevocation: (delegation: AuthorityDelegationV1) => RevocationResolution
}

export type BudgetReservationState = 'reserved' | 'dispatched' | 'committed' | 'cancelled'

export interface BudgetOperationResult {
  ok: boolean
  code: 'RESERVED' | 'DISPATCHED' | 'COMMITTED' | 'CANCELLED' | 'IDEMPOTENT' |
    'CONFLICT' | 'UNIT_MISMATCH' | 'PER_ACTION_EXCEEDED' |
    'CUMULATIVE_EXCEEDED' | 'NOT_FOUND' | 'INVALID_STATE'
  state?: BudgetReservationState
}
