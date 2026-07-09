// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Evidence Descriptor - a verifier OUTPUT over a receipt's evidence
// ══════════════════════════════════════════════════════════════════════
//
// THE HEADLINE: assurance is a verifier-derived OUTPUT, never an
// issuer-set INPUT. There is no issuer-written assurance field anywhere in
// this module. Nothing here is read from a receipt's body as a grade. The
// descriptor reports MECHANICAL FACTS the verifier can recompute from the
// receipt, the signatures, and the key/DID graph:
//
//   - the signer set and which DID signed which claim;
//   - the observationBasis of each witness;
//   - the presence of any WitnessConflict;
//   - multi-party signature validity, GENERALIZED from
//     verifyBilateralReceipt (not a new multi-signature checker);
//   - signer independence, derived from the key and DID graph via the
//     sharesRoot relation (two signers chaining to the same root are NOT
//     independent - witnesses sharing the gateway root of trust are still
//     self-attestation).
//
// LATTICE, NOT LADDER. The corroboration status is the four-valued Belnap
// ConstraintStatus (pass | fail | not_applicable | unknown), the same
// vocabulary the gateway constraint engine uses. It is not a 1..5 score.
//
// ONE advisory scalar sits on top, computed by the verifier FROM the
// descriptor and labelled a relying-party-policy output. It is never read
// from the receipt and never claims truth. A relying party may ignore it,
// recompute it, or replace it with its own policy.
// ══════════════════════════════════════════════════════════════════════

import type { ConstraintStatus, WitnessObservationBasis, WitnessConflict } from '../../types/gateway.js'
import type { ScopeOfClaim } from '../accountability/types/base.js'
import {
  type SignerGraph,
  type SignerNode,
  type IndependenceRelation,
  allPairwiseIndependence,
  independentSignerCount,
} from './shares-root.js'

// ── Re-export the graph surface so descriptor consumers have one import. ──
export type { SignerGraph, SignerNode, IndependenceRelation } from './shares-root.js'
export { sharesRoot, allPairwiseIndependence, independentSignerCount } from './shares-root.js'

// ══════════════════════════════════════════════════════════════════════
// Signer / claim facts
// ══════════════════════════════════════════════════════════════════════

/**
 * One mechanical fact: signer `signerId` produced a signature over `claim`
 * and the verifier checked it. `signatureValid` is the cryptographic
 * outcome; `tri-state` for an absent signer mirrors verifyBilateralReceipt,
 * where `null` means "no signature was present to check" (never `false`).
 *
 * No assurance level lives here. This is "who signed what, and did it
 * verify" - nothing more.
 */
export interface SignerClaim {
  /** Stable signer identity: Ed25519 public key hex, or a DID. */
  signerId: string
  /** Self-described role, carried through; never used for independence. */
  role?: string
  /** The claim this signature covers, named by a stable label
   *  (e.g. 'outcome', 'witness:notary', 'gateway-countersignature'). */
  claim: string
  /** Cryptographic result. `null` = signer expected but no signature
   *  present (absent-signer tri-state, matching BilateralReceiptVerification). */
  signatureValid: boolean | null
  /** How the verifier obtained the key behind this check, when the caller
   *  recorded it (src/v2/verification-source). Optional and additive: a
   *  claim without it is shaped exactly as before. One more mechanical
   *  fact; never an input to independence or corroboration. */
  verificationSource?: import('../verification-source/types.js').VerificationSource
}

/**
 * One witness's mechanical observation facts. `observationBasis` reuses the
 * existing five-valued WitnessObservationBasis enum verbatim - the
 * descriptor does not invent a new strength vocabulary. `divergence` echoes
 * predictionError.divergence (0 = matched, 1 = fully unexpected) when the
 * witness reported one.
 */
export interface WitnessObservationFact {
  witnessId: string
  /** HOW the witness observed. Categorical, not a score. */
  observationBasis: WitnessObservationBasis
  /** predictionError.divergence (0..1) if the witness reported one. */
  divergence?: number
}

// ══════════════════════════════════════════════════════════════════════
// The descriptor itself - a SET/LATTICE, not a scalar ladder
// ══════════════════════════════════════════════════════════════════════

/**
 * Evidence Descriptor: a verifier OUTPUT reporting exactly the mechanical
 * evidence facts present on one receipt.
 *
 * Every field is recomputable by the verifier from the receipt, its
 * signatures, the witness attestations, and the key/DID graph. No field is
 * read from an issuer-written assurance slot, because none exists.
 *
 * `corroborationStatus` is the lattice point: the four-valued Belnap
 * ConstraintStatus, not a 1..N score.
 */
export interface EvidenceDescriptor {
  /** Format version for additive evolution. */
  version: 'aps:evidence-descriptor:v1'
  /** Receipt this descriptor was computed over (id only; no body copied). */
  receiptId: string

  // ── Signer set / which DID signed which claim (mechanical) ──
  /** Every (signer, claim, signatureValid) fact the verifier checked. */
  signerClaims: SignerClaim[]
  /** Distinct signer identities present, sorted. Convenience view of the
   *  signer set; derivable from signerClaims. */
  signerSet: string[]

  // ── Witness observation facts (mechanical) ──
  witnessObservations: WitnessObservationFact[]

  // ── Witness conflict (first-class state, not silence) ──
  /** True iff at least one WitnessConflict was supplied for this receipt. */
  hasWitnessConflict: boolean
  /** The conflict ids surfaced, sorted. Empty iff hasWitnessConflict false. */
  witnessConflictIds: string[]

  // ── Multi-party signature validity (generalized from bilateral) ──
  /** True iff every present signature verified and no signer that was
   *  expected is missing. Generalized from BilateralReceiptVerification.valid. */
  allSignaturesValid: boolean
  /** Count of signatures that verified. */
  validSignatureCount: number
  /** Count of signers expected but with no signature present (tri-state null). */
  absentSignerCount: number

  // ── Signer independence (the sharp metric, from the key/DID graph) ──
  /** Every pairwise sharesRoot relation, in stable order. */
  independenceRelations: IndependenceRelation[]
  /** Count of signers independent of every other signer (no shared root). */
  independentSignerCount: number
  /** True iff at least two signers exist and NO pair shares a root. */
  fullyIndependent: boolean

  // ── The lattice point ──
  /** Four-valued Belnap corroboration status (pass | fail |
   *  not_applicable | unknown). NOT a scalar ladder. */
  corroborationStatus: ConstraintStatus

  // ── Honest scope (dogfooded ScopeOfClaim) ──
  /** What this descriptor claims and explicitly does NOT claim. */
  scope_of_claim: ScopeOfClaim
}

// ══════════════════════════════════════════════════════════════════════
// Builder inputs
// ══════════════════════════════════════════════════════════════════════

/**
 * A pre-checked signature fact handed to the descriptor builder. The
 * builder does NOT re-run crypto; it consumes verification results the
 * caller already produced (e.g. from verifyBilateralReceipt or
 * verifyWitnessAttestation) and arranges them as facts. This keeps signing
 * and canonicalization entirely in the existing modules and never touches
 * canonical-jcs.ts or any receipt preimage.
 *
 * `valid: null` means the signer was expected but no signature was present,
 * mirroring the absent-gateway tri-state of BilateralReceiptVerification.
 */
export interface CheckedSignature {
  signerId: string
  role?: string
  claim: string
  /** Cryptographic outcome already computed by the caller. null = absent. */
  valid: boolean | null
  /** Anchors this signer chains to (issuer DID, gateway root, JWKS origin,
   *  trust-anchor fingerprint). Feeds the independence graph. */
  chainsTo?: string[]
  /** How the caller obtained the key for this check, when it recorded that
   *  (src/v2/verification-source). Echoed onto the SignerClaim fact;
   *  never consulted by the independence graph or the corroboration
   *  status. */
  verificationSource?: import('../verification-source/types.js').VerificationSource
}

export interface BuildDescriptorInput {
  receiptId: string
  /** Pre-checked signatures (from verifyBilateralReceipt and friends). */
  signatures: CheckedSignature[]
  /** Witness observation facts (observationBasis + optional divergence). */
  witnessObservations?: WitnessObservationFact[]
  /** Any WitnessConflict events the verifier holds for this receipt. */
  witnessConflicts?: WitnessConflict[]
  /** Anchor equivalences for the independence graph (verifier-supplied). */
  anchorEdges?: Array<[string, string]>
}

// ══════════════════════════════════════════════════════════════════════
// generalizeBilateralVerification - adapter from BilateralReceiptVerification
// ══════════════════════════════════════════════════════════════════════

/**
 * The shape returned by verifyBilateralReceipt. Imported structurally
 * rather than by type-import to keep this module free of a hard dependency
 * on the bilateral type module; the fields match exactly.
 */
export interface BilateralVerificationLike {
  valid: boolean
  requestingAgentSignatureValid: boolean
  servingAgentSignatureValid: boolean
  /** null = no gateway signature present. */
  gatewaySignatureValid: boolean | null
  outcomeConsistent: boolean
  timingValid: boolean
  errors: string[]
}

/**
 * Generalize a bilateral verification into the descriptor's signature
 * facts. This is the EXTENSION point the task calls for: rather than
 * writing a new multi-signature checker, the descriptor reads the result of
 * verifyBilateralReceipt and the receipt's signer identities and reshapes
 * them as (signer, claim, valid) facts plus their key/DID anchors.
 *
 * The two agents both sign the SAME outcome, so both carry claim 'outcome'.
 * The gateway, when present, countersigns the same body and carries claim
 * 'gateway-countersignature'; when absent it surfaces as a tri-state `null`
 * signer so the descriptor can report absence rather than failure.
 */
export function generalizeBilateralVerification(opts: {
  verification: BilateralVerificationLike
  requestingAgentId: string
  servingAgentId: string
  gatewayId?: string
  /** Anchors each party chains to, keyed by signer id. Verifier-supplied. */
  anchors?: Record<string, string[]>
}): CheckedSignature[] {
  const anchorsFor = (id: string): string[] | undefined => opts.anchors?.[id]
  const out: CheckedSignature[] = [
    {
      signerId: opts.requestingAgentId,
      role: 'requesting_agent',
      claim: 'outcome',
      valid: opts.verification.requestingAgentSignatureValid,
      chainsTo: anchorsFor(opts.requestingAgentId),
    },
    {
      signerId: opts.servingAgentId,
      role: 'serving_agent',
      claim: 'outcome',
      valid: opts.verification.servingAgentSignatureValid,
      chainsTo: anchorsFor(opts.servingAgentId),
    },
  ]
  if (opts.gatewayId) {
    out.push({
      signerId: opts.gatewayId,
      role: 'gateway_witness',
      claim: 'gateway-countersignature',
      // Tri-state preserved: null = no gateway signature was present.
      valid: opts.verification.gatewaySignatureValid,
      chainsTo: anchorsFor(opts.gatewayId),
    })
  }
  return out
}

// ══════════════════════════════════════════════════════════════════════
// buildEvidenceDescriptor - the verifier OUTPUT
// ══════════════════════════════════════════════════════════════════════

/**
 * Compute the four-valued corroboration status from mechanical facts.
 *
 *   fail           - at least one present signature failed to verify, or a
 *                    witness conflict is surfaced. The evidence contradicts
 *                    itself; corroboration cannot stand.
 *   not_applicable - there is nothing to corroborate (zero or one signer
 *                    and no witnesses). A lone self-signature is not a
 *                    corroboration question.
 *   unknown        - multiple signers, none failed, but the evidence does
 *                    not establish independent corroboration (every
 *                    additional signer shares a root with another, i.e. no
 *                    independent second signer). Insufficient evidence, in
 *                    the Belnap sense, NOT a low score.
 *   pass           - at least two signers, all present signatures valid, no
 *                    conflict, and at least two mutually independent
 *                    signers corroborate.
 *
 * This is a lattice classification, not a ladder rank.
 */
function deriveCorroborationStatus(facts: {
  presentSignatureFailures: number
  hasWitnessConflict: boolean
  signerCount: number
  witnessCount: number
  independentSigners: number
}): ConstraintStatus {
  if (facts.presentSignatureFailures > 0 || facts.hasWitnessConflict) return 'fail'
  // Nothing to corroborate: lone or no signer, and no witnesses.
  if (facts.signerCount <= 1 && facts.witnessCount === 0) return 'not_applicable'
  // Two or more mutually independent signers: corroboration stands.
  if (facts.independentSigners >= 2) return 'pass'
  // Multiple signers but not independently corroborated: evidence
  // insufficient to call it corroborated. Belnap 'unknown', never a low score.
  return 'unknown'
}

/**
 * Build the Evidence Descriptor: a verifier OUTPUT over one receipt's
 * evidence. Pure over its input - identical input always yields an
 * identical descriptor, which is what makes the advisory scalar
 * reproducible.
 *
 * Reminder of the absolute rule: this reads no issuer-written assurance
 * field. Every input is either a cryptographic result the caller already
 * computed or a fact from the key/DID graph.
 */
export function buildEvidenceDescriptor(input: BuildDescriptorInput): EvidenceDescriptor {
  const signerClaims: SignerClaim[] = input.signatures.map((s) => ({
    signerId: s.signerId,
    role: s.role,
    claim: s.claim,
    signatureValid: s.valid,
    // Conditional spread: a fact without a recorded source carries no key,
    // keeping the claim shape identical to the pre-field form.
    ...(s.verificationSource !== undefined ? { verificationSource: s.verificationSource } : {}),
  }))

  // Signer set: distinct signer identities, sorted.
  const signerSet = [...new Set(input.signatures.map((s) => s.signerId))].sort()

  // Multi-party signature tally (generalized from bilateral verification).
  let validSignatureCount = 0
  let absentSignerCount = 0
  let presentSignatureFailures = 0
  for (const s of input.signatures) {
    if (s.valid === null) absentSignerCount++
    else if (s.valid === true) validSignatureCount++
    else presentSignatureFailures++
  }
  const allSignaturesValid = presentSignatureFailures === 0 && absentSignerCount === 0

  // Witness conflict (first-class state).
  const conflicts = input.witnessConflicts ?? []
  const witnessConflictIds = [...new Set(conflicts.map((c) => c.conflictId))].sort()
  const hasWitnessConflict = witnessConflictIds.length > 0

  // Witness observations, in stable order by witnessId.
  const witnessObservations = (input.witnessObservations ?? [])
    .slice()
    .sort((a, b) => (a.witnessId < b.witnessId ? -1 : a.witnessId > b.witnessId ? 1 : 0))

  // Signer independence from the key/DID graph. Build one node per distinct
  // signer, carrying the anchors the verifier assembled for it.
  const nodeById = new Map<string, SignerNode>()
  for (const s of input.signatures) {
    if (!nodeById.has(s.signerId)) {
      nodeById.set(s.signerId, { id: s.signerId, chainsTo: s.chainsTo, role: s.role })
    }
  }
  const graph: SignerGraph = { nodes: [...nodeById.values()], anchorEdges: input.anchorEdges }
  const independenceRelations = allPairwiseIndependence(graph)
  const indepCount = independentSignerCount(graph)
  const fullyIndependent =
    signerSet.length >= 2 && independenceRelations.every((r) => r.independent)

  const corroborationStatus = deriveCorroborationStatus({
    presentSignatureFailures,
    hasWitnessConflict,
    signerCount: signerSet.length,
    witnessCount: witnessObservations.length,
    independentSigners: indepCount,
  })

  const scope_of_claim: ScopeOfClaim = {
    asserts:
      'Reports the mechanical evidence on one receipt: which signers signed which claim and whether each signature verified, each witness observation basis, presence of any witness conflict, and signer independence derived from the key and DID graph.',
    does_not_assert: [
      'That any external effect described by the receipt actually occurred.',
      'That the underlying outcome is true; signature validity is not outcome truth.',
      'Any issuer-set assurance level; no such field is read.',
      'That independent signers cannot still be coordinated off-graph.',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'best_effort',
    // Self-attested when there is no independent second signer to corroborate.
    self_attested: indepCount < 2,
  }

  return {
    version: 'aps:evidence-descriptor:v1',
    receiptId: input.receiptId,
    signerClaims,
    signerSet,
    witnessObservations,
    hasWitnessConflict,
    witnessConflictIds,
    allSignaturesValid,
    validSignatureCount,
    absentSignerCount,
    independenceRelations,
    independentSignerCount: indepCount,
    fullyIndependent,
    corroborationStatus,
    scope_of_claim,
  }
}

// ══════════════════════════════════════════════════════════════════════
// The ONE advisory scalar - a relying-party-policy OUTPUT
// ══════════════════════════════════════════════════════════════════════

/**
 * Strength weights for the five-valued WitnessObservationBasis enum. These
 * grade observation STRENGTH using the existing vocabulary verbatim - no
 * new categories. They are a relying-party-policy default; a relying party
 * may substitute its own weights. Direct observation and independent
 * recomputation are the strongest bases; a receipt-only check is the weakest.
 */
export const DEFAULT_OBSERVATION_WEIGHTS: Record<WitnessObservationBasis, number> = {
  direct_observation: 1.0,
  independent_recomputation: 1.0,
  replay_verification: 0.8,
  log_derived: 0.5,
  receipt_only: 0.3,
}

/**
 * The single verifier-derived advisory scalar. It is computed PURELY from
 * an EvidenceDescriptor - it reads no receipt and no issuer field. It is a
 * RELYING-PARTY-POLICY view, not an assertion of truth: a relying party may
 * ignore it, recompute it from the descriptor, or replace the policy.
 *
 * Because it is a deterministic function of the descriptor, two parties
 * holding the same descriptor and the same weights always get the same
 * scalar. That reproducibility is the property the tests pin.
 */
export interface AdvisoryScalar {
  /** Label, hard: this is policy, not truth. */
  kind: 'relying-party-policy'
  /** 0..1 advisory corroboration strength. NOT a probability of truth. */
  value: number
  /** The Belnap status this scalar was computed against (echoed, for audit). */
  basis: ConstraintStatus
  /** One line naming what went into the scalar. Non-authoritative. */
  rationale: string
}

/**
 * Compute the advisory scalar from a descriptor.
 *
 * The scalar is grounded in the four-valued status first:
 *   fail           -> 0   (contradicted evidence)
 *   not_applicable -> 0   (nothing to corroborate)
 *   unknown        -> capped low band (signers present but not independent)
 *   pass           -> scaled by independence and observation strength
 *
 * Within `pass`/`unknown`, independence dominates (it is the sharp metric)
 * and witness observation strength modulates. Self-attestation - witnesses
 * sharing a root - cannot lift the scalar, because those signers never add
 * an independent corroborator and so never raise independentSignerCount.
 */
export function computeAdvisoryScalar(
  descriptor: EvidenceDescriptor,
  weights: Record<WitnessObservationBasis, number> = DEFAULT_OBSERVATION_WEIGHTS
): AdvisoryScalar {
  const status = descriptor.corroborationStatus

  if (status === 'fail' || status === 'not_applicable') {
    return {
      kind: 'relying-party-policy',
      value: 0,
      basis: status,
      rationale:
        status === 'fail'
          ? 'evidence contradicts itself (failed signature or witness conflict)'
          : 'nothing to corroborate (no independent second signer, no witnesses)',
    }
  }

  // Observation strength: mean weight of witness bases, or a neutral 0.5
  // when there are no witnesses (signatures alone carry the descriptor).
  const obs = descriptor.witnessObservations
  const observationStrength =
    obs.length === 0
      ? 0.5
      : obs.reduce((sum, w) => sum + (weights[w.observationBasis] ?? 0), 0) / obs.length

  // Independence factor: how many signers are mutually independent, capped.
  // 0 or 1 independent signer -> no corroboration credit.
  const indep = descriptor.independentSignerCount
  const independenceFactor = indep <= 1 ? 0 : Math.min(1, (indep - 1) / 2)

  if (status === 'unknown') {
    // Signers present but not independently corroborated. Cap the scalar in
    // a low band so policy never reads self-attestation as strong evidence.
    const value = Math.min(0.35, 0.2 + 0.15 * observationStrength)
    return {
      kind: 'relying-party-policy',
      value: round3(value),
      basis: status,
      rationale: 'multiple signers but no independent corroboration; capped low',
    }
  }

  // status === 'pass': independent corroboration present. A floor of 0.5 for
  // established independent corroboration, lifted toward 1 by independence
  // breadth and observation strength. Independence dominates (it is the
  // sharp metric); observation strength modulates the headroom above the floor.
  const headroom = independenceFactor * (0.5 + 0.5 * observationStrength)
  const value = Math.max(0, Math.min(1, 0.5 + 0.5 * headroom))
  return {
    kind: 'relying-party-policy',
    value: round3(value),
    basis: status,
    rationale: 'independent corroboration present; scaled by independence breadth and observation strength',
  }
}

/** Round to 3 decimals for stable, reproducible scalar output. */
function round3(x: number): number {
  return Math.round(x * 1000) / 1000
}
