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
