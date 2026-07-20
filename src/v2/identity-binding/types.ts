// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

export type Hex32 = string
export type Hex64 = string
export type Hex128 = string

export interface PassportSelfAssertionsV2 {
  display_name?: string
  capabilities: string[]
}

/**
 * A cryptographic agent identity record. Principal authority is deliberately
 * absent; it is carried by PrincipalBindingV1 instead of being self-asserted
 * inside the passport.
 */
export interface PassportV2 {
  record_type: 'aps.agent-passport'
  version: '2.0'
  passport_id: Hex64
  agent_id: string
  verification_method: string
  public_key_multibase: string
  issued_at: string
  expires_at: string
  nonce: Hex32
  self_asserted: PassportSelfAssertionsV2
  signature: Hex128
}

export interface PrincipalBindingV1 {
  record_type: 'aps.principal-binding'
  version: '1.0'
  binding_id: Hex64
  agent_id: string
  principal_id: string
  verification_method: string
  audiences: string[]
  authority_profiles: string[]
  status_uri: string
  issued_at: string
  expires_at: string
  nonce: Hex32
  signature: Hex128
}

export interface PrincipalBindingRevocationV1 {
  record_type: 'aps.principal-binding-revocation'
  version: '1.0'
  revocation_id: Hex64
  binding_id: Hex64
  principal_id: string
  verification_method: string
  revoked_at: string
  reason_code: string
  nonce: Hex32
  signature: Hex128
}

export type PrincipalClaimLevel =
  | 'self_asserted'
  | 'principal_attested'
  | 'externally_verified_principal'

export type IdentityVerificationState =
  | 'valid'
  | 'invalid'
  | 'indeterminate'
  | 'unsupported'

export interface IdentityVerificationResult {
  state: IdentityVerificationState
  code: string
  proof_of_possession: boolean
  key_authority: 'verified' | 'unresolved' | 'rejected'
  principal_claim_level?: PrincipalClaimLevel
}

export interface HistoricalKeyResolutionRequest {
  controller: string
  verification_method: string
  at: string
}

export interface HistoricalKeyResolutionResult {
  state: 'resolved' | 'not_found' | 'ambiguous' | 'malformed' | 'unreachable' | 'unsupported'
  public_key_hex?: string
}

export type HistoricalKeyResolver = (
  request: HistoricalKeyResolutionRequest,
) => HistoricalKeyResolutionResult | Promise<HistoricalKeyResolutionResult>
