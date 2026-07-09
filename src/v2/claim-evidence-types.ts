// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Claim → Evidence types (skeleton)
// ══════════════════════════════════════════════════════════════════
// Names a closed set of claims an APS receipt can substantiate, the
// record types the protocol can produce, and the mapping between
// them. Receipts substantiate specific claims; not every receipt
// can substitute for another. This module is the static surface of
// that mapping. Verification logic lives elsewhere.
// ══════════════════════════════════════════════════════════════════

export enum ClaimType {
  IDENTITY_VERIFIED = 'IDENTITY_VERIFIED',
  AUTHORITY_TO_EXECUTE = 'AUTHORITY_TO_EXECUTE',
  ACTION_EXECUTED = 'ACTION_EXECUTED',
  BINDING_COMMITMENT = 'BINDING_COMMITMENT',
  EFFECT_SAFETY_ATTESTED = 'EFFECT_SAFETY_ATTESTED',
  DERIVATION_TRACED = 'DERIVATION_TRACED',
  CLAIM_CONTESTED = 'CLAIM_CONTESTED',
  CLAIM_RESOLVED = 'CLAIM_RESOLVED',
  BATCH_ATTESTED = 'BATCH_ATTESTED',
  EVIDENCE_CUSTODY_HELD = 'EVIDENCE_CUSTODY_HELD',
}

/**
 * Mirrors the existing record-producing primitives the SDK ships.
 * Names match the TypeScript interfaces / class shapes already in
 * the public surface (see src/index.ts). When new primitives are
 * added, extend this enum and update EvidenceProfiles accordingly.
 */
export enum RecordType {
  ActionReceipt = 'ActionReceipt',
  AuthorityBoundaryReceipt = 'AuthorityBoundaryReceipt',
  CustodyReceipt = 'CustodyReceipt',
  ContestabilityReceipt = 'ContestabilityReceipt',
  APSBundle = 'APSBundle',
  AccessReceipt = 'AccessReceipt',
  DerivationReceipt = 'DerivationReceipt',
  DecisionReceipt = 'DecisionReceipt',
  ProvisionalStatement = 'ProvisionalStatement',
  PromotionEvent = 'PromotionEvent',
  Withdrawal = 'Withdrawal',
  InstructionProvenanceReceipt = 'InstructionProvenanceReceipt',
  CognitiveAttestation = 'CognitiveAttestation',
  /** Foundation rail receipt — proof of rail event, NOT economic entitlement.
   *  See docs/governance/payment-rails-receipt-semantics.md. */
  PaymentReceipt = 'PaymentReceipt',
  /** ACP rail receipt — proof an ACP checkout-session op was authorized. */
  AcpReceipt = 'AcpReceipt',
  /** MPP rail receipt — proof an MPP 402 challenge was satisfied. */
  MppApsReceipt = 'MppApsReceipt',
  /** AP2 mandate — proof a mandate was issued, NOT proof of payment. */
  SignedAP2Mandate = 'SignedAP2Mandate',
  /** Stripe-Issuing receipt — proof the rail's webhook gate approved a card auth. */
  StripeIssuingReceipt = 'StripeIssuingReceipt',
}

/**
 * Canonical claim_type literal for each rail receipt's evidence-class binding.
 * The same string is set on the rail receipt's `claim_type` field at signing
 * time when the new accountability-aligned signing path is used. Legacy
 * receipts (without these literals) continue to verify under the existing
 * per-rail verifier path.
 */
export const RAIL_RECEIPT_CLAIM_TYPES = {
  [RecordType.PaymentReceipt]: 'rail.payment.v1',
  [RecordType.AcpReceipt]: 'rail.acp.v1',
  [RecordType.MppApsReceipt]: 'rail.mpp.v1',
  [RecordType.SignedAP2Mandate]: 'rail.ap2.mandate.v1',
  [RecordType.StripeIssuingReceipt]: 'rail.stripe_issuing.v1',
} as const

export interface EvidenceProfile {
  required: RecordType[]
  optional?: RecordType[]
  forbiddenSubstitutions: Partial<Record<RecordType, string>>
}

export const EvidenceProfiles: Record<ClaimType, EvidenceProfile> = {
  [ClaimType.AUTHORITY_TO_EXECUTE]: {
    required: [RecordType.AuthorityBoundaryReceipt],
    optional: [RecordType.DecisionReceipt],
    forbiddenSubstitutions: {
      [RecordType.ActionReceipt]:
        'Action receipts prove execution, not authority. The boundary ruling is a separate signer (the gateway/evaluator), and conflating them collapses the trust split that makes the audit chain meaningful.',
    },
  },

  [ClaimType.BINDING_COMMITMENT]: {
    required: [RecordType.PromotionEvent, RecordType.ProvisionalStatement],
    optional: [RecordType.DecisionReceipt],
    forbiddenSubstitutions: {
      [RecordType.ActionReceipt]:
        'Action receipts prove execution or communication, not binding commitment.',
    },
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.IDENTITY_VERIFIED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.ACTION_EXECUTED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.EFFECT_SAFETY_ATTESTED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.DERIVATION_TRACED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.CLAIM_CONTESTED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.CLAIM_RESOLVED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  [ClaimType.BATCH_ATTESTED]: {
    required: [RecordType.APSBundle],
    forbiddenSubstitutions: {},
  },

  [ClaimType.EVIDENCE_CUSTODY_HELD]: {
    required: [RecordType.CustodyReceipt],
    forbiddenSubstitutions: {
      [RecordType.ActionReceipt]:
        'Action receipts prove what was done, not who held the evidence afterward.',
    },
  },
}

export function requiredEvidenceFor(claim: ClaimType): EvidenceProfile {
  return EvidenceProfiles[claim]
}
