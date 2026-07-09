// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// cognitive_attestation signal_type (v0.1): TypeScript types
// ══════════════════════════════════════════════════════════════════
// Vocabulary primitive: signal_types.cognitive_attestation.
// Spec home: aeoess/agent-governance-vocabulary, vocabulary.yaml,
// commit 3763bf9 on branch feat/cognitive-attestation-vocab-entry (PR #104).
// Long-form rationale: docs/proposed/cognitive-attestation.md (PR #93).
//
// What the primitive attests to: which cognitive content the agent
// committed to using at this decision, and at what determinability class.
// Distinct from reasoning_integrity (scoped to actions) and
// governance_attestation (attests that a declared governance requirement
// was satisfied). cognitive_attestation attests to what was reasoned over,
// not whether a policy passed.
//
// v0.1 surface: precondition_set, candidate_set, decision_path.
// v0.2 deferred: pre_commit_chain.
//
// Determinability classes are not a hierarchy of correctness. They are
// different attestor-verifier contracts. One class per envelope.
// ══════════════════════════════════════════════════════════════════

/**
 * Literal tag for envelope discrimination at the wire level.
 */
export type CognitiveAttestationSignalType = 'cognitive_attestation'

/**
 * The three v0.1 determinability classes. `pre_commit_chain` is a v0.2
 * candidate per PR #104 notes and is not in this union.
 */
export type CognitiveAttestationClass =
  | 'precondition_set'
  | 'candidate_set'
  | 'decision_path'

/**
 * Class payload for precondition_set: which preconditions were available
 * at decision time (delegation scope, policy constraints, tool availability,
 * context window). `available_preconditions` MUST be sorted lexicographically
 * to produce a stable canonical form; `precondition_hashes[i]` is the
 * sha256 hex of `available_preconditions[i]`.
 */
export interface PreconditionSetPayload {
  /** Sorted lexicographically. JCS-canonical preserves array order. */
  readonly available_preconditions: readonly string[]
  /** sha256 hex (64 lowercase chars) of each precondition string, same order. */
  readonly precondition_hashes: readonly string[]
}

/**
 * Class payload for candidate_set: which candidate actions were evaluated
 * and which were eliminated, with elimination reasons. `elimination_reason`
 * is REQUIRED when `eliminated === true` and MUST be omitted when
 * `eliminated === false`.
 */
export interface CandidateSetPayload {
  readonly evaluated_candidates: readonly EvaluatedCandidate[]
}

export interface EvaluatedCandidate {
  /** sha256 hex of the candidate description. */
  readonly candidate_ref: string
  readonly eliminated: boolean
  /** Required when eliminated, omitted otherwise. */
  readonly elimination_reason?: string
}

/**
 * Class payload for decision_path: the chosen path with confidence and
 * the structured reasoning that selected it.
 */
export interface DecisionPathPayload {
  /** sha256 hex of the chosen path description. */
  readonly chosen_path_ref: string
  /** Two decimal places max, 0.00 through 1.00. */
  readonly confidence: number
  /** sha256 hex of each reasoning step description, in evaluation order. */
  readonly reasoning_chain_hashes: readonly string[]
}

/**
 * Discriminated union of the three class-specific envelope shapes. The
 * `class` field is the discriminator; `class_payload` is narrowed by it.
 */
export type CognitiveAttestationEnvelope =
  | PreconditionSetEnvelope
  | CandidateSetEnvelope
  | DecisionPathEnvelope

export interface PreconditionSetEnvelope extends CognitiveAttestationEnvelopeBase {
  readonly class: 'precondition_set'
  readonly class_payload: PreconditionSetPayload
}

export interface CandidateSetEnvelope extends CognitiveAttestationEnvelopeBase {
  readonly class: 'candidate_set'
  readonly class_payload: CandidateSetPayload
}

export interface DecisionPathEnvelope extends CognitiveAttestationEnvelopeBase {
  readonly class: 'decision_path'
  readonly class_payload: DecisionPathPayload
}

/**
 * Shared envelope shape. The signature is computed over the JCS-canonical
 * form of the envelope with the `signature` field omitted, then attached.
 */
interface CognitiveAttestationEnvelopeBase {
  readonly signal_type: CognitiveAttestationSignalType
  /** Ed25519 public key of the attestor, lowercase hex (64 chars). */
  readonly agent_id: string
  /** sha256 hex of the decision description being attested. */
  readonly decision_ref: string
  /** Unix epoch milliseconds at the moment of attestation. */
  readonly timestamp_ms: number
  /** Ed25519 signature, lowercase hex (128 chars). Empty during signing. */
  readonly signature: string
}

/**
 * Unsigned envelope shape: same fields as the signed envelope, minus the
 * signature. The signing helper accepts this and returns a fully populated
 * envelope.
 */
export type UnsignedCognitiveAttestationEnvelope =
  | UnsignedPreconditionSetEnvelope
  | UnsignedCandidateSetEnvelope
  | UnsignedDecisionPathEnvelope

export type UnsignedPreconditionSetEnvelope = Omit<PreconditionSetEnvelope, 'signature'>
export type UnsignedCandidateSetEnvelope = Omit<CandidateSetEnvelope, 'signature'>
export type UnsignedDecisionPathEnvelope = Omit<DecisionPathEnvelope, 'signature'>

/**
 * Result of verifying an envelope. `valid: false` carries a `reason`
 * string naming the specific failure mode. Reasons:
 *   - INVALID_SIGNAL_TYPE: signal_type field is not the literal.
 *   - INVALID_CLASS: class field is not one of the v0.1 classes.
 *   - INVALID_AGENT_ID: agent_id is not 64 lowercase hex chars.
 *   - INVALID_SIGNATURE_FORMAT: signature is not 128 lowercase hex chars.
 *   - INVALID_PAYLOAD: class_payload shape does not match the declared class.
 *   - SIGNATURE_INVALID: Ed25519 verification failed.
 */
export interface CognitiveAttestationVerifyResult {
  readonly valid: boolean
  readonly reason?: CognitiveAttestationVerifyReason
}

export type CognitiveAttestationVerifyReason =
  | 'INVALID_SIGNAL_TYPE'
  | 'INVALID_CLASS'
  | 'INVALID_AGENT_ID'
  | 'INVALID_SIGNATURE_FORMAT'
  | 'INVALID_PAYLOAD'
  | 'SIGNATURE_INVALID'

const HEX_AGENT_ID = /^[0-9a-f]{64}$/
const HEX_SIGNATURE = /^[0-9a-f]{128}$/
const HEX_DIGEST = /^[0-9a-f]{64}$/

/**
 * Runtime type guard. Returns true when `value` is structurally a signed
 * cognitive_attestation envelope of any v0.1 class. Does NOT verify the
 * signature; use `verifyCognitiveAttestation` for that.
 *
 * Invariants checked:
 *   - signal_type literal matches.
 *   - class is one of the three v0.1 values.
 *   - agent_id, signature, decision_ref are lowercase hex of the expected
 *     length.
 *   - class_payload is structurally consistent with the declared class.
 *   - timestamp_ms is a finite, non-negative integer.
 */
export function isCognitiveAttestation(value: unknown): value is CognitiveAttestationEnvelope {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (v.signal_type !== 'cognitive_attestation') return false
  if (typeof v.agent_id !== 'string' || !HEX_AGENT_ID.test(v.agent_id)) return false
  if (typeof v.signature !== 'string' || !HEX_SIGNATURE.test(v.signature)) return false
  if (typeof v.decision_ref !== 'string' || !HEX_DIGEST.test(v.decision_ref)) return false
  if (typeof v.timestamp_ms !== 'number' || !Number.isFinite(v.timestamp_ms) || v.timestamp_ms < 0) return false
  if (!Number.isInteger(v.timestamp_ms)) return false
  if (typeof v.class !== 'string') return false
  if (v.class === 'precondition_set') {
    return isPreconditionSetPayload(v.class_payload)
  }
  if (v.class === 'candidate_set') {
    return isCandidateSetPayload(v.class_payload)
  }
  if (v.class === 'decision_path') {
    return isDecisionPathPayload(v.class_payload)
  }
  return false
}

/**
 * Validate a precondition_set payload shape. Exported as helper for the
 * verifier; not part of the public surface beyond the type guard.
 */
export function isPreconditionSetPayload(value: unknown): value is PreconditionSetPayload {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (!Array.isArray(v.available_preconditions)) return false
  if (!Array.isArray(v.precondition_hashes)) return false
  if (v.available_preconditions.length !== v.precondition_hashes.length) return false
  for (const p of v.available_preconditions) {
    if (typeof p !== 'string') return false
  }
  for (const h of v.precondition_hashes) {
    if (typeof h !== 'string' || !HEX_DIGEST.test(h)) return false
  }
  return true
}

export function isCandidateSetPayload(value: unknown): value is CandidateSetPayload {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (!Array.isArray(v.evaluated_candidates)) return false
  for (const item of v.evaluated_candidates) {
    if (typeof item !== 'object' || item === null) return false
    const c = item as Record<string, unknown>
    if (typeof c.candidate_ref !== 'string' || !HEX_DIGEST.test(c.candidate_ref)) return false
    if (typeof c.eliminated !== 'boolean') return false
    if (c.eliminated === true) {
      if (typeof c.elimination_reason !== 'string' || c.elimination_reason.length === 0) return false
    } else {
      if ('elimination_reason' in c) return false
    }
  }
  return true
}

export function isDecisionPathPayload(value: unknown): value is DecisionPathPayload {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (typeof v.chosen_path_ref !== 'string' || !HEX_DIGEST.test(v.chosen_path_ref)) return false
  if (typeof v.confidence !== 'number' || !Number.isFinite(v.confidence)) return false
  if (v.confidence < 0 || v.confidence > 1) return false
  // Two decimal places max: scaled value should be an integer.
  const scaled = Math.round(v.confidence * 100)
  if (Math.abs(v.confidence * 100 - scaled) > 1e-9) return false
  if (!Array.isArray(v.reasoning_chain_hashes)) return false
  for (const h of v.reasoning_chain_hashes) {
    if (typeof h !== 'string' || !HEX_DIGEST.test(h)) return false
  }
  return true
}
