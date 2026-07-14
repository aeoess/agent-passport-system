// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Reversibility fold - foundation (spec v2, reversibility-fold-design-v2.md)
//
// A new primitive that reuses the trust-domain-counting and provisional/final
// lifecycle patterns already established in APS, applied to reversibility.
//
// This module is the FOUNDATION only: the two-axis output types and their
// projection (step 1), and the versioned mapping-profile registry (step 2).
// It touches no receipt envelope, no gateway, and no existing wire shape.
// The effect-instantiation block, lifecycle records, fold, divergence, and
// admission checkpoint are later steps and are not implemented here.

import { createHash } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'

// ══════════════════════════════════════
// STEP 1 - Two-axis output (spec section 0)
// ══════════════════════════════════════
//
// v1 used ONE value to answer TWO different questions: "what may I admit" (a
// policy limit) and "what actually happened" (an execution outcome needing
// evidence). The fix is two projections.
//
//  - realized_class: honest about what evidence establishes. May say "not
//    known yet" (unresolved).
//  - enforcement_class: conservative. Admission and the gateway act on this.
//    unresolved maps to irreversible ONLY in this projection.
//
// Receipts and audits report realized_class truthfully; enforcement acts on
// enforcement_class. Keeping the two separate is what makes the async-pending
// case honest (enforcement_class = irreversible while realized_class =
// unresolved), instead of a false terminal "irreversible".

/** What evidence actually establishes about an effect's reversibility.
 *  `unresolved` is an honest "not known yet", never silently upgraded. */
export type RealizedClass = 'tentative' | 'compensable' | 'irreversible' | 'unresolved'

/** The conservative class admission and the gateway act on. There is no
 *  `unresolved` here: the projection below folds it to `irreversible`. */
export type EnforcementClass = 'tentative' | 'compensable' | 'irreversible'

/** Pure projection realized -> enforcement (spec section 0).
 *  `unresolved` becomes `irreversible` (conservative, fail-closed). Every
 *  other value is the identity. This is the ONLY place `unresolved` is
 *  mapped to `irreversible`; realized truth is never rewritten. */
export function enforcementFrom(realized: RealizedClass): EnforcementClass {
  return realized === 'unresolved' ? 'irreversible' : realized
}

// ══════════════════════════════════════
// STEP 2 - Versioned mapping-profile registry (spec section 4)
// ══════════════════════════════════════
//
// The verifier recomputes a RealizedClass from the raw facts of an effect
// using a PUBLIC mapping profile named by a classification_profile_id. Class
// is recomputable and auditable, and auto-corrected when the profile is later
// fixed, with no re-signing of historical receipts. Version-binding is
// mandatory: without the profile id, "recomputable" degrades to "recomputable
// under whatever table the verifier happens to run".
//
// This step is types + one pure classifier + the registry. It carries no
// receipt shape and does no I/O or signing. The effect-instantiation block
// (step 3) will later carry facts that map onto EffectFacts; this classifier
// consumes the facts, it does not define the wire block.
//
// Meta-law the design enforces: a fact that governs a trust decision must be
// signed from OUTSIDE the party it constrains. Where a required external
// attestation is absent, the classifier fails closed to irreversible.

/** The externality bucket an effect falls in. These values mirror the RAPV0
 *  TaskClassification.externality vocabulary (src/types/reputation-authority.ts)
 *  minus 'none'; a caller may pass RAPV0 values, and 'none' or an absent value
 *  is treated as unbound (see EffectFacts.externality). This is pattern reuse,
 *  not a shared type: reversibility is not a scalar of the effect location. */
export type EffectExternality = 'internal' | 'external-reversible' | 'external-irreversible'

/** Finality of an external effect. Used to decide whether an irreversible
 *  verdict is definitive or only an upper bound (spec section 4). */
export type FinalityState = 'settled' | 'pending' | 'expired' | 'contradicted'

/** A reversal-right attestation fact. To count, the signer MUST be a domain
 *  other than the acting principal (spec section 4). This step models the
 *  fact; it verifies no signature. A signer equal to the acting principal is
 *  self-attestation and does not establish the right. */
export interface ReversalRightFact {
  /** Identity/domain that attested the reversal right. */
  signer: string
}

/** The raw facts a classifier consumes for one effect. Every field is
 *  optional: absence is meaningful and generally fails toward unresolved or,
 *  once the externality bucket is known, toward irreversible (fail-closed).
 *  This is the classifier input, not a receipt wire shape. */
export interface EffectFacts {
  /** The externality bucket. Absent (undefined) means unbound / missing and
   *  classifies as unresolved. A caller mapping RAPV0 'none' should pass it
   *  as undefined here. */
  externality?: EffectExternality
  /** Identity of the acting principal the effect is attributed to. */
  actingPrincipal?: string
  /** Who can invoke reversal (recovery_controller). For external-reversible,
   *  compensable requires this to equal the acting principal. */
  recoveryController?: string | null
  /** External reversal-right attestation. Must be signed by a domain other
   *  than the acting principal to count. Absent fails closed to irreversible
   *  for external-reversible effects. */
  reversalRight?: ReversalRightFact | null
  /** Finality of an external-irreversible effect. Only 'settled' contributes
   *  to a definitive (non-upper-bound) irreversible verdict. */
  finalityState?: FinalityState
  /** Whether the target/counterparty binding is verified, for external-
   *  irreversible effects. Both finality and this must hold to drop the
   *  upper_bound label. */
  targetBindingVerified?: boolean
  /** Observable recovery mechanism reference for an internal effect. A present,
   *  non-empty ref is observable recovery and classifies compensable; an
   *  absent/null/empty ref (for example key destruction, un-snapshotted
   *  mutation) classifies irreversible. Internal is classified from OBSERVABLE
   *  facts, never from an asserted own-class. */
  recoveryMechanismRef?: string | null
}

/** The result of a classification. The RealizedClass is the mapping output;
 *  `label` carries the section-4 upper_bound annotation, present only when an
 *  external-irreversible verdict is not backed by verified finality and target
 *  binding (that is, the irreversible verdict is an upper bound, not a
 *  definitive finding). */
export interface ClassificationResult {
  realized: RealizedClass
  label?: 'upper_bound'
}

/** A versioned mapping profile: a pure function from raw effect facts to a
 *  RealizedClass, addressed by a stable id. */
export interface ClassificationProfile {
  id: string
  classify: (facts: EffectFacts) => ClassificationResult
}

/** Stable id of the v0 mapping profile. Chosen value; the spec fixes no
 *  literal, only that classification_profile_id must be bound. */
export const REVERSIBILITY_MAPPING_V0_ID = 'reversibility-mapping-v0'

/** The v0 mapping rules (spec section 4), as a pure function.
 *
 *  - external-irreversible -> irreversible. Upper bound (label upper_bound)
 *    unless finality is settled AND the target binding is verified.
 *  - external-reversible -> compensable ONLY IF recovery_controller is the
 *    acting principal AND a reversal-right is attested by a domain other than
 *    the acting principal. Else irreversible, fail-closed. (A counterparty who
 *    CAN reverse but is not the acting principal's controllable lever does not
 *    make the effect compensable-by-us.)
 *  - internal -> classified from observable recovery facts, never an asserted
 *    own-class. Observable recovery mechanism present -> compensable; absent
 *    (key destruction, un-snapshotted mutation) -> irreversible.
 *  - unbound / missing externality -> unresolved. */
export function classifyV0(facts: EffectFacts): ClassificationResult {
  const ext = facts.externality

  // Unbound / missing externality: we cannot even name the bucket. Honest
  // unresolved; enforcementFrom() lifts this to irreversible for admission.
  if (ext === undefined || ext === null) {
    return { realized: 'unresolved' }
  }

  // external-irreversible -> irreversible; upper bound unless finality settled
  // AND target binding verified.
  if (ext === 'external-irreversible') {
    const finalityVerified = facts.finalityState === 'settled'
    const definitive = finalityVerified && facts.targetBindingVerified === true
    return definitive
      ? { realized: 'irreversible' }
      : { realized: 'irreversible', label: 'upper_bound' }
  }

  // external-reversible -> compensable ONLY under an external mandate held by
  // the acting principal; else fail closed to irreversible.
  if (ext === 'external-reversible') {
    const controllerIsPrincipal =
      facts.actingPrincipal != null &&
      facts.recoveryController != null &&
      facts.recoveryController === facts.actingPrincipal
    const externalReversalRight =
      facts.reversalRight != null &&
      facts.reversalRight.signer !== '' &&
      facts.actingPrincipal != null &&
      facts.reversalRight.signer !== facts.actingPrincipal
    return controllerIsPrincipal && externalReversalRight
      ? { realized: 'compensable' }
      : { realized: 'irreversible' }
  }

  // internal -> classified from observable recovery facts.
  if (ext === 'internal') {
    const hasObservableRecovery =
      facts.recoveryMechanismRef != null && facts.recoveryMechanismRef !== ''
    return { realized: hasObservableRecovery ? 'compensable' : 'irreversible' }
  }

  // Unreachable for typed inputs. Any unrecognized externality bucket is
  // treated as unbound and fails to unresolved (never a compensable fall-open).
  return { realized: 'unresolved' }
}

/** The v0 profile. */
export const reversibilityMappingV0: ClassificationProfile = {
  id: REVERSIBILITY_MAPPING_V0_ID,
  classify: classifyV0,
}

const PROFILE_REGISTRY: ReadonlyMap<string, ClassificationProfile> = new Map([
  [REVERSIBILITY_MAPPING_V0_ID, reversibilityMappingV0],
])

/** Resolve a mapping profile by its classification_profile_id. Returns
 *  undefined for an unknown id; callers decide how to treat a missing profile
 *  (an unresolvable profile is not the same event as unbound facts, and this
 *  step does not conflate them). */
export function getClassificationProfile(id: string): ClassificationProfile | undefined {
  return PROFILE_REGISTRY.get(id)
}

/** The set of registered profile ids. */
export function registeredProfileIds(): string[] {
  return [...PROFILE_REGISTRY.keys()]
}

// ══════════════════════════════════════
// STEP 3a - Effect-instantiation block + recompute (spec section 3)
// ══════════════════════════════════════
//
// One action can produce several effects at once (a compensable payment
// authorization, an irreversible email, an internal irreversible key deletion).
// A single scalar collapses them to the max and loses the cause, so the block
// carries a vector of effects. Each element carries the RAW facts, never a
// trusted class: an asserted class MAY appear as a cache only, and a verifier
// recompute that disagrees FAILS.
//
// This step defines the block schema and the recompute over it. It performs no
// signing and does not bind resource_confirmation_ref (that is a later step).
// The hard rule below keeps unverified external-irreversible effects fail-closed.

/** Where an effect lands. Coarser than the classifier's externality bucket:
 *  the reversible-vs-irreversible distinction for an external effect is not a
 *  field an author sets, it is recomputed from the recovery facts (spec Q4:
 *  reversibility is not a scalar of the effect location). */
export type EffectScope = 'internal' | 'external'

/** Whether the effect's facts are established yet. Carried per section 3 and
 *  consumed by the two-stage lifecycle (a later step), not by this recompute. */
export type EvidenceStatus = 'resolved' | 'pending' | 'unavailable' | 'conflicted'

/** One instantiated effect. Raw facts only. */
export interface EffectInstantiationElement {
  effect_scope: EffectScope
  effect_target_ref: string
  finality_state: FinalityState
  recovery_mechanism_ref: string | null
  recovery_controller: string | null
  recovery_deadline: string | null
  evidence_status: EvidenceStatus
  classification_profile_id: string
  /** Optional cache ONLY. Never trusted. A verifier recomputes the realized
   *  class and any mismatch fails verification (verifyAssertedClass). */
  asserted_realized_class?: RealizedClass
}

/** The effect-instantiation block: the effect vector (v0). */
export interface EffectInstantiationBlock {
  instantiated_effects: EffectInstantiationElement[]
}

/** RAPV0 TaskClassification.externality value space. Declared here to avoid
 *  coupling this primitive to the reputation type; the values mirror
 *  src/types/reputation-authority.ts TaskClassification.externality. */
export type RapvExternality = 'none' | 'internal' | 'external-reversible' | 'external-irreversible'

/** Map an RAPV0 externality onto the value used for EffectFacts.externality.
 *  'none' or absent maps to undefined (unbound), which classifies unresolved.
 *  This is a pure adapter, not an import-and-couple. */
export function rapvExternalityToEffectFacts(
  externality: RapvExternality | null | undefined,
): EffectExternality | undefined {
  if (externality == null || externality === 'none') return undefined
  return externality
}

/** Verifier-supplied context for a recompute. Facts a verifier establishes
 *  out of band. Everything defaults to the fail-closed value when absent. */
export interface RecomputeOptions {
  /** HARD RULE: an author NEVER sets this from the block. Only a verifier that
   *  checked the resource_confirmation_ref cryptographic commitment (a later
   *  step) may pass true. Absent or false keeps an external-irreversible effect
   *  at irreversible + upper_bound. */
  targetBindingVerified?: boolean
}

/** The outcome of a recompute. An unknown classification_profile_id is a
 *  DISTINCT failure from unbound facts: it is surfaced, never silently
 *  classified as unresolved. */
export type RecomputeOutcome =
  | { status: 'recomputed'; classificationProfileId: string; result: ClassificationResult }
  | { status: 'unknown_profile'; classificationProfileId: string }

/** Derive the classifier externality bucket from an element's raw facts (v4
 *  section 4.1). internal -> internal. external -> external-irreversible,
 *  ALWAYS, in v0: there is no verified reversal right in v0, so no external
 *  effect reaches external-reversible, and a self-declared recovery_mechanism_ref
 *  derives NOTHING about the class. recovery_mechanism_ref remains a carried raw
 *  fact and still informs the INTERNAL branch's observable-recovery test; it is
 *  simply not evidence of reversibility for an external effect. Downstream, an
 *  external effect classifies to irreversible + upper_bound (target binding is
 *  not verified in v0), never bare irreversible and never compensable. */
function deriveExternality(element: EffectInstantiationElement): EffectExternality {
  if (element.effect_scope === 'internal') return 'internal'
  return 'external-irreversible'
}

/** Build classifier facts from an element plus verifier context. Note what is
 *  deliberately NOT supplied here: actingPrincipal and the external reversal-
 *  right attestation are the actor axis (a later step), so an external-
 *  reversible effect fails closed to irreversible under this recompute until
 *  that step supplies verified actor-axis facts. targetBindingVerified comes
 *  only from the verifier context, never from the element (hard rule). */
function effectFactsFromElement(
  element: EffectInstantiationElement,
  options?: RecomputeOptions,
): EffectFacts {
  return {
    externality: deriveExternality(element),
    recoveryController: element.recovery_controller,
    recoveryMechanismRef: element.recovery_mechanism_ref,
    finalityState: element.finality_state,
    targetBindingVerified: options?.targetBindingVerified === true,
  }
}

/** Recompute the realized class for one effect element. Resolves the mapping
 *  profile by classification_profile_id; an unknown id is surfaced as its own
 *  failure and is NOT classified. Otherwise runs the profile over the element's
 *  facts and returns the ClassificationResult. */
export function recomputeEffect(
  element: EffectInstantiationElement,
  options?: RecomputeOptions,
): RecomputeOutcome {
  const profile = getClassificationProfile(element.classification_profile_id)
  if (profile === undefined) {
    return { status: 'unknown_profile', classificationProfileId: element.classification_profile_id }
  }
  const facts = effectFactsFromElement(element, options)
  return {
    status: 'recomputed',
    classificationProfileId: element.classification_profile_id,
    result: profile.classify(facts),
  }
}

/** Recompute every effect in a block, per element. No folding or collapsing to
 *  a maximum here (that is the fold, a later step). */
export function recomputeBlock(
  block: EffectInstantiationBlock,
  options?: RecomputeOptions,
): RecomputeOutcome[] {
  return block.instantiated_effects.map((e) => recomputeEffect(e, options))
}

/** The result of checking an element's asserted cache class against the
 *  recompute. Absent cache passes. A present cache that differs from the
 *  recomputed realized class fails. An unknown profile cannot be verified. */
export type AssertedClassCheck =
  | { ok: true; recomputed: ClassificationResult }
  | { ok: false; reason: 'mismatch'; asserted: RealizedClass; recomputed: RealizedClass }
  | { ok: false; reason: 'unknown_profile'; classificationProfileId: string }

/** Verify an element's asserted cache class (if any) against the recompute.
 *  A cache is a convenience only and is never trusted: a mismatch fails. */
export function verifyAssertedClass(
  element: EffectInstantiationElement,
  options?: RecomputeOptions,
): AssertedClassCheck {
  const outcome = recomputeEffect(element, options)
  if (outcome.status === 'unknown_profile') {
    return { ok: false, reason: 'unknown_profile', classificationProfileId: outcome.classificationProfileId }
  }
  const recomputed = outcome.result
  if (element.asserted_realized_class === undefined) {
    return { ok: true, recomputed }
  }
  if (element.asserted_realized_class !== recomputed.realized) {
    return { ok: false, reason: 'mismatch', asserted: element.asserted_realized_class, recomputed: recomputed.realized }
  }
  return { ok: true, recomputed }
}

// ══════════════════════════════════════
// STEP 5a - Two-stage lifecycle (spec section 5)
// ══════════════════════════════════════
//
// The block gets its own lifecycle, mirroring the receipt's pending/reconciled
// states, so the async-confirmation contradiction dissolves.
//
//  - Execution receipt: provisional. evidence_status = pending, carries the
//    provisional class facts and the enforcement class that GOVERNED admission.
//    Append-only.
//  - Reconciliation receipt: hash-linked to the execution receipt, signed,
//    derives the realized facts. It MUST NOT rewrite the execution receipt, and
//    transitions are monotonic (pending refines to compensable or irreversible,
//    never an arbitrary replacement).
//
// Enforcement direction (hard rule): the PROVISIONAL binding is what governed
// admission. The reconciliation receipt is an audit-time correction with NO
// retroactive enforcement power. You cannot un-admit a settled action. A
// consumer asking "what gated the action" reads admittedEnforcementClass, which
// reads ONLY the execution receipt and never the reconciliation's realized
// class.

/** Provisional stage. Append-only. */
export interface ExecutionStageReceipt {
  stage: 'execution'
  action_ref: string
  run_id: string
  /** The provisional class facts. */
  effect_instantiation: EffectInstantiationBlock
  /** Stage-level evidence status. Provisional receipts are always pending. */
  evidence_status: 'pending'
  /** The enforcement class that GOVERNED admission, recorded by the gateway that
   *  admitted the action. Never rewritten by any later stage. */
  admitted_enforcement_class: EnforcementClass
  created_at: string
}

export interface ReconciliationSignature {
  algorithm: 'Ed25519'
  public_key: string
  value: string
}

/** Audit stage. Hash-linked to an execution receipt and signed. Carries the
 *  refined realized class, which has NO enforcement power. */
export interface ReconciliationStageReceipt {
  stage: 'reconciliation'
  /** SHA-256 hash-link to the execution receipt this refines. */
  execution_receipt_hash: string
  action_ref: string
  /** Audit-time realized class. Never gates admission. */
  realized_class: RealizedClass
  /** Refined evidence status after reconciliation. */
  evidence_status: 'resolved' | 'unavailable' | 'conflicted'
  reconciled_at: string
  signature: ReconciliationSignature
}

/** SHA-256 (over strict JCS bytes) of an execution receipt. Any change to the
 *  execution receipt changes this hash, so a hash-link detects a rewrite. */
export function hashExecutionReceipt(receipt: ExecutionStageReceipt): string {
  return 'sha256:' + createHash('sha256').update(canonicalize(receipt)).digest('hex')
}

export interface CreateReconciliationInput {
  realized_class: RealizedClass
  evidence_status: 'resolved' | 'unavailable' | 'conflicted'
  reconciled_at: string
  signerPrivateKey: string
  signerPublicKey: string
}

/** Create a reconciliation receipt hash-linked to an execution receipt and
 *  signed over its canonical body. Does not touch the execution receipt. */
export function createReconciliationReceipt(
  execution: ExecutionStageReceipt,
  input: CreateReconciliationInput,
): ReconciliationStageReceipt {
  const body = {
    stage: 'reconciliation' as const,
    execution_receipt_hash: hashExecutionReceipt(execution),
    action_ref: execution.action_ref,
    realized_class: input.realized_class,
    evidence_status: input.evidence_status,
    reconciled_at: input.reconciled_at,
  }
  const value = sign(canonicalize(body), input.signerPrivateKey)
  return { ...body, signature: { algorithm: 'Ed25519', public_key: input.signerPublicKey, value } }
}

/** The realized classes a reconciliation may refine a pending stage into.
 *  pending -> compensable and pending -> irreversible only. */
const MONOTONIC_RECONCILED_CLASSES: ReadonlySet<RealizedClass> = new Set<RealizedClass>([
  'compensable',
  'irreversible',
])

export interface TransitionCheck {
  ok: boolean
  errors: string[]
}

/** Validate a reconciliation against its execution receipt. Rejects a broken
 *  hash-link (a rewritten execution receipt), an invalid signature, a stage
 *  that is not pending, and any non-monotonic realized class. */
export function validateTransition(
  execution: ExecutionStageReceipt,
  reconciliation: ReconciliationStageReceipt,
): TransitionCheck {
  const errors: string[] = []

  // Hash-link integrity: the reconciliation must reference THIS execution
  // receipt. A post-hoc rewrite of the execution receipt breaks the link.
  if (reconciliation.execution_receipt_hash !== hashExecutionReceipt(execution)) {
    errors.push('hash-link mismatch: reconciliation does not reference this execution receipt')
  }

  if (reconciliation.action_ref !== execution.action_ref) {
    errors.push('action_ref mismatch between stages')
  }

  // Signature over the reconciliation body (excluding the signature block).
  const { signature, ...body } = reconciliation
  if (!verify(canonicalize(body), signature.value, signature.public_key)) {
    errors.push('reconciliation signature invalid')
  }

  // Monotonic transition: the execution stage is provisional (pending); the
  // reconciliation may only refine to compensable or irreversible. Anything
  // else is an arbitrary replacement and is rejected.
  if (execution.evidence_status !== 'pending') {
    errors.push('execution receipt is not in the pending stage')
  }
  if (!MONOTONIC_RECONCILED_CLASSES.has(reconciliation.realized_class)) {
    errors.push(
      `non-monotonic realized_class '${reconciliation.realized_class}' (only compensable or irreversible refine a pending stage)`,
    )
  }

  return { ok: errors.length === 0, errors }
}

/** The enforcement class that GOVERNED admission. This reads ONLY the execution
 *  receipt: the reconciliation's realized class is audit-time truth and carries
 *  no enforcement power, so a consumer cannot read the final class as the one
 *  that gated the action. */
export function admittedEnforcementClass(execution: ExecutionStageReceipt): EnforcementClass {
  return execution.admitted_enforcement_class
}
