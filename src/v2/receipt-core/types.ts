// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

export type JsonPrimitive = null | boolean | number | string
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue }

export type Hex64 = string
export type Hex128 = string

export interface EvidenceRefV1 {
  artifact_type: string
  sha256: Hex64
}

export interface ReceiptSignatureV1 {
  signer: string
  key_id: string
  alg: 'Ed25519'
  value: Hex128
}

export interface ReceiptV1 {
  profile: 'aps-receipt-v1'
  receipt_id: Hex64
  receipt_type: string
  issuer: string
  subject_agent: string
  action_ref: Hex64
  delegation_ref: string
  decision_ref?: Hex64
  issued_at: string
  evidence_refs: EvidenceRefV1[]
  result: { [key: string]: JsonValue }
  prev?: Hex64
  signatures: ReceiptSignatureV1[]
}

export interface ReceiptSignerV1 {
  signer: string
  key_id: string
  private_key: string
}

export interface DecisionRefInputV1 {
  profile: 'aps-decision-ref-v1'
  action_ref: Hex64
  authority_state_ref: Hex64
  policy_ref: Hex64
  context_ref: Hex64
  decision_output_ref: Hex64
}

export interface CoreDecisionOutputV1 {
  profile: 'aps-core-decision-output-v1'
  verdict: 'permit' | 'deny' | 'narrow'
  effective_authority_ref: Hex64 | null
  constraints: string[]
  valid_until: string | null
}

export interface SupportingRecordV1 {
  profile: 'aps-supporting-record-v1'
  record_id: Hex64
  record_type: string
  issuer: string
  issuer_key_id: string
  issued_at: string
  action_ref?: Hex64
  body: { [key: string]: JsonValue }
  sig_alg: 'Ed25519'
  sig: Hex128
}

export interface EvidenceBundleMemberInputV2 {
  member_id: string
  member_type: string
  payload: JsonValue
}

export interface EvidenceBundleMemberV2 {
  member_id: string
  member_type: string
  sha256: Hex64
}

export interface EvidenceBundleBodyV2 {
  members: EvidenceBundleMemberV2[]
  merkle_root: Hex64
}

export type EvidenceBundleProofStepV2 =
  | { position: 'left' | 'right'; sha256: Hex64 }
  | { position: 'promote' }

export interface EvidenceBundleProofV2 {
  profile: 'aps-evidence-proof-v2'
  member: EvidenceBundleMemberV2
  leaf_index: number
  leaf_count: number
  path: EvidenceBundleProofStepV2[]
}
