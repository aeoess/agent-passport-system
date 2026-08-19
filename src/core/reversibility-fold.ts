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
import { canonicalizeJCS, canonicalizeJCSForWrite } from './canonical-jcs.js'

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
  /** RESERVED for the deferred v4 section 10 four-object subsystem. Not consumed
   *  by the v0 classifier: v0 has no external-compensable path, so the acting
   *  principal plays no part in v0 classification. */
  actingPrincipal?: string
  /** Who can invoke reversal (recovery_controller), a carried raw fact. Not
   *  consumed by the v0 classifier (v0 external is irreversible-only). */
  recoveryController?: string | null
  /** RESERVED for the deferred v4 section 10 four-object subsystem. Not consumed
   *  by the v0 classifier. In v0 no reversal-right can ground compensability;
   *  external compensability is a future profile, not a v0 branch. */
  reversalRight?: ReversalRightFact | null
  /** Finality of an external-irreversible effect. Only 'settled' contributes
   *  to a definitive (non-upper-bound) irreversible verdict. */
  finalityState?: FinalityState
  /** Whether the target/counterparty binding is verified, for external-
   *  irreversible effects. Both finality and this must hold to drop the
   *  upper_bound label. */
  targetBindingVerified?: boolean
  /** A producer-declared recovery mechanism reference. Carried as raw data only:
   *  in v0 it derives NOTHING about the class (v4 s4 / s4.1). A self-declared ref
   *  is self-attestation, so it cannot mint compensability; internal-compensable
   *  requires a verifier-checked recovery result that v0 defers. */
  recoveryMechanismRef?: string | null
}

/** Deterministic reason codes for the v0 profile. One per mapping rule, so a
 *  verifier and an auditor read the same explanation for the same facts. Part of
 *  the profile's authoritative content (its reason-code set). */
export type ReasonCode =
  | 'RM_V0_UNBOUND'
  | 'RM_V0_INTERNAL_DEFINITIVE'
  | 'RM_V0_INTERNAL_UPPER_BOUND'
  | 'RM_V0_EXTERNAL_DEFINITIVE'
  | 'RM_V0_EXTERNAL_UPPER_BOUND'

/** The result of a classification. The RealizedClass is the mapping output;
 *  `label` carries the section-4 upper_bound annotation, present only when an
 *  external verdict is not backed by verified finality and target binding; and
 *  `reason` is the deterministic reason code for the rule that fired. */
export interface ClassificationResult {
  realized: RealizedClass
  label?: 'upper_bound'
  reason: ReasonCode
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

/** The v0 mapping rules (v4 sections 4, 4.1, 10), as a pure function.
 *
 *  v0 has NO external-compensable path. External compensability is a FUTURE
 *  profile (reversibility-mapping-v1) built on the deferred four-object subsystem
 *  of v4 section 10, never a branch inside the v0 profile. v4 section 10 rejects
 *  the domain-separation-without-authority model (a non-empty reversal-right
 *  signer different from the principal): a registration outside operator control
 *  shows only separation, not authority-over-a-mechanism, so it cannot ground
 *  compensability. This profile must not behave differently by entry point.
 *
 *  - external-irreversible AND external-reversible -> irreversible. Upper bound
 *    (label upper_bound) unless finality is settled AND the target binding is
 *    verified. The two external buckets are treated identically in v0.
 *  - internal -> irreversible, treated exactly like an external-irreversible
 *    effect (upper_bound unless finality settled AND target binding verified). A
 *    self-declared recovery_mechanism_ref derives nothing (v4 s4 / s4.1), so v0
 *    has no internal-compensable path.
 *  - unbound / missing externality -> unresolved.
 *  v0 therefore emits no compensable outcome at all. */
export function classifyV0(facts: EffectFacts): ClassificationResult {
  const ext = facts.externality

  // Unbound / missing externality: we cannot even name the bucket. Honest
  // unresolved; enforcementFrom() lifts this to irreversible for admission.
  if (ext === undefined || ext === null) {
    return { realized: 'unresolved', reason: 'RM_V0_UNBOUND' }
  }

  // Any external effect -> irreversible; upper bound unless finality is settled
  // AND target binding verified. v0 has no external-compensable path, so the
  // legacy 'external-reversible' taxonomy value is treated exactly as
  // 'external-irreversible' here (no compensable branch, no reversal-right read).
  if (ext === 'external-irreversible' || ext === 'external-reversible') {
    const finalityVerified = facts.finalityState === 'settled'
    const definitive = finalityVerified && facts.targetBindingVerified === true
    return definitive
      ? { realized: 'irreversible', reason: 'RM_V0_EXTERNAL_DEFINITIVE' }
      : { realized: 'irreversible', label: 'upper_bound', reason: 'RM_V0_EXTERNAL_UPPER_BOUND' }
  }

  // internal -> irreversible in v0. A self-declared recovery_mechanism_ref is
  // self-attestation and derives NOTHING about the class (v4 s4 / s4.1), the same
  // conflation removed for the external path: a producer cannot mint
  // compensability by naming a rollback path. v0 has no verifier-checked recovery
  // evidence (recoveryMechanismRef, recoveryController, recovery_deadline, and
  // evidence_status are all producer-declared, and the only verifier-supplied
  // signal, targetBindingVerified, is the external resource-confirmation check).
  // internal-compensable requires a verified recovery result that v0 defers, so
  // internal is treated exactly as an external-irreversible effect: irreversible
  // plus upper_bound, unless finality is settled AND the binding is verified. v0
  // therefore has no compensable outcome at all, the sound and consistent
  // position across both externality axes.
  if (ext === 'internal') {
    const finalityVerified = facts.finalityState === 'settled'
    const definitive = finalityVerified && facts.targetBindingVerified === true
    return definitive
      ? { realized: 'irreversible', reason: 'RM_V0_INTERNAL_DEFINITIVE' }
      : { realized: 'irreversible', label: 'upper_bound', reason: 'RM_V0_INTERNAL_UPPER_BOUND' }
  }

  // Unreachable for typed inputs. Any unrecognized externality bucket is
  // treated as unbound and fails to unresolved (never a compensable fall-open).
  return { realized: 'unresolved', reason: 'RM_V0_UNBOUND' }
}

/** The v0 profile function object. */
export const reversibilityMappingV0: ClassificationProfile = {
  id: REVERSIBILITY_MAPPING_V0_ID,
  classify: classifyV0,
}

/** The AUTHORITATIVE, canonical content of the v0 profile (v4 section 4): its
 *  input schema, mapping rules, reason-code set, and time semantics, and nothing
 *  else. No runtime, diagnostic, or human-facing metadata (display name,
 *  comments, timestamps) is included, so those can change without changing the
 *  content digest. This object is what the digest commits to. */
export const REVERSIBILITY_PROFILE_V0_CONTENT = {
  profile_id: REVERSIBILITY_MAPPING_V0_ID,
  input_fields: ['externality', 'finality_state', 'target_binding_verified'],
  externality_values: ['internal', 'external-reversible', 'external-irreversible'],
  finality_values: ['settled', 'pending', 'expired', 'contradicted'],
  external_compensable: false,
  internal_compensable: false,
  // label is present only when the rule emits one (upper_bound). No null values
  // anywhere in the content: the three SDK JCS implementations disagree on
  // null-valued keys (TS and Python drop them, Go keeps them), so a null-free
  // content is the parity-safe form that canonicalizes byte-identically.
  // v0 has no compensable outcome: both compensable strengths require verified
  // recovery evidence that v0 defers, and a self-declared recovery_mechanism_ref
  // derives nothing, so it is not a classification input.
  rules: [
    { id: 'unbound', when: 'externality_absent', realized: 'unresolved', reason: 'RM_V0_UNBOUND' },
    { id: 'external_definitive', when: 'externality_external AND finality_settled AND target_binding_verified', realized: 'irreversible', reason: 'RM_V0_EXTERNAL_DEFINITIVE' },
    { id: 'external_upper_bound', when: 'externality_external AND NOT(finality_settled AND target_binding_verified)', realized: 'irreversible', label: 'upper_bound', reason: 'RM_V0_EXTERNAL_UPPER_BOUND' },
    { id: 'internal_definitive', when: 'externality_internal AND finality_settled AND target_binding_verified', realized: 'irreversible', reason: 'RM_V0_INTERNAL_DEFINITIVE' },
    { id: 'internal_upper_bound', when: 'externality_internal AND NOT(finality_settled AND target_binding_verified)', realized: 'irreversible', label: 'upper_bound', reason: 'RM_V0_INTERNAL_UPPER_BOUND' },
  ],
  reason_codes: ['RM_V0_UNBOUND', 'RM_V0_EXTERNAL_DEFINITIVE', 'RM_V0_EXTERNAL_UPPER_BOUND', 'RM_V0_INTERNAL_DEFINITIVE', 'RM_V0_INTERNAL_UPPER_BOUND'],
  time_semantics: { clock_skew_ms: 0, finality_source: 'bound_input', target_binding_source: 'verifier_supplied' },
  schema_version: 'v0',
}

/** Domain-separated content digest of a profile (v4 section 4):
 *  SHA-256( UTF8("APS-REVERSIBILITY-PROFILE-V0") || 0x00 || UTF8(JCS(content)) ).
 *  Any language that JCS-canonicalizes the same content reproduces this byte-for-
 *  byte. */
export function profileContentDigest(content: unknown): string {
  const preimage = Buffer.concat([
    Buffer.from('APS-REVERSIBILITY-PROFILE-V0', 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonicalizeJCS(content), 'utf8'),
  ])
  return 'sha256:' + createHash('sha256').update(preimage).digest('hex')
}

/** The v0 profile's content digest. */
export const REVERSIBILITY_MAPPING_V0_DIGEST = profileContentDigest(REVERSIBILITY_PROFILE_V0_CONTENT)

/** A registered profile: its function object, its authoritative content, its
 *  content digest, and non-authoritative diagnostic metadata that is NOT part of
 *  the digest. */
export interface RegisteredProfile {
  profile: ClassificationProfile
  content: unknown
  digest: string
  /** Diagnostic/human-facing only. Excluded from the digest; may change freely. */
  metadata: { display_name: string; description: string }
}

/** The immutable content-addressed registry (v4 section 4). It never mutates an
 *  existing (id, digest) pair; a change to a profile's content yields a new
 *  digest and is a NEW profile with a new id. Resolving an unknown id, or an
 *  (id, digest) mismatch, is a DISTINCT failure, never a silent fallback. */
const PROFILE_REGISTRY: ReadonlyMap<string, RegisteredProfile> = new Map([
  [REVERSIBILITY_MAPPING_V0_ID, {
    profile: reversibilityMappingV0,
    content: REVERSIBILITY_PROFILE_V0_CONTENT,
    digest: REVERSIBILITY_MAPPING_V0_DIGEST,
    metadata: {
      display_name: 'Reversibility mapping v0',
      description: 'Fail-closed v0 classifier: internal and external both resolve to irreversible; no compensable outcome, since verified recovery evidence is deferred.',
    },
  }],
])

/** Resolve a mapping profile function by its classification_profile_id. Returns
 *  undefined for an unknown id (a distinct event from unbound facts). */
export function getClassificationProfile(id: string): ClassificationProfile | undefined {
  return PROFILE_REGISTRY.get(id)?.profile
}

/** Resolve the full registered profile (function, content, digest, metadata). */
export function getRegisteredProfile(id: string): RegisteredProfile | undefined {
  return PROFILE_REGISTRY.get(id)
}

/** The registry's content digest for a profile id, or undefined if unknown. */
export function getProfileDigest(id: string): string | undefined {
  return PROFILE_REGISTRY.get(id)?.digest
}

/** The set of registered profile ids. */
export function registeredProfileIds(): string[] {
  return [...PROFILE_REGISTRY.keys()]
}

/** The outcome of checking a declared (id, digest) against the registry. Unknown
 *  id and digest mismatch are DISTINCT failures, never conflated. */
export type ProfileBindingCheck =
  | { ok: true; digest: string }
  | { ok: false; reason: 'unknown_profile'; classificationProfileId: string }
  | { ok: false; reason: 'digest_mismatch'; classificationProfileId: string; declaredDigest: string; expectedDigest: string }

/** Check a declared profile id + content digest against the immutable registry.
 *  An id not in the registry fails unknown_profile; a known id whose declared
 *  digest does not equal the registry digest fails digest_mismatch. */
export function verifyProfileBinding(id: string, declaredDigest: string): ProfileBindingCheck {
  const registered = PROFILE_REGISTRY.get(id)
  if (registered === undefined) {
    return { ok: false, reason: 'unknown_profile', classificationProfileId: id }
  }
  if (declaredDigest !== registered.digest) {
    return { ok: false, reason: 'digest_mismatch', classificationProfileId: id, declaredDigest, expectedDigest: registered.digest }
  }
  return { ok: true, digest: registered.digest }
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
  /** The content digest of the profile named by classification_profile_id (v4
   *  section 4). A recompute checks it against the immutable registry: a
   *  mismatch fails distinctly from an unknown profile. Binding the id to the
   *  digest proves which profile CONTENT governed the classification. */
  classification_profile_digest: string
  /** Content-addressed request/action identity of the execution instance this
   *  effect belongs to (v4 section 2). Sourced from the carrying receipt's
   *  action_ref (ExecutionEnvelope.action_ref, the APS correlation key). A
   *  stable, signed binding so an effect state cannot be transplanted between
   *  receipts. */
  action_ref: string
  /** Stable unique id of the specific execution instance (v4 section 2). Sourced
   *  from the carrying receipt's per-instance id (ExecutionEnvelope.action_id or
   *  RAPV0.receipt_id). Distinguishes two instances that share a content-
   *  addressed action_ref. */
  action_instance_id: string
  /** Stable id for this effect across its lifecycle stages (v4 section 2).
   *  Precedence is defined by lineage under this id, never by array position. */
  effect_id: string
  /** Hash of the prior signed state of THIS effect, or null on the first state.
   *  Chains an effect's lineage so a later state references its predecessor. */
  predecessor_effect_state_hash: string | null
  /** Monotonic position within THIS effect's own lineage (not the array). */
  sequence: number
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
 *  'none' or absent -> undefined (unbound), which classifies unresolved.
 *  internal -> internal. Both external buckets -> external-irreversible: the
 *  legacy 'external-reversible' taxonomy carried a stronger meaning than v0
 *  grants, so it is NOT passed through as-is; mapping it to external-irreversible
 *  keeps it from being a backdoor into compensability (v4 s4/s10). This is a pure
 *  adapter, not an import-and-couple. */
export function rapvExternalityToEffectFacts(
  externality: RapvExternality | null | undefined,
): EffectExternality | undefined {
  if (externality == null || externality === 'none') return undefined
  if (externality === 'internal') return 'internal'
  return 'external-irreversible'
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
  | { status: 'profile_digest_mismatch'; classificationProfileId: string; declaredDigest: string; expectedDigest: string }

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
  const registered = getRegisteredProfile(element.classification_profile_id)
  if (registered === undefined) {
    return { status: 'unknown_profile', classificationProfileId: element.classification_profile_id }
  }
  // Bind id to content: a declared digest that does not match the registry is a
  // DISTINCT failure from an unknown profile, and is not classified.
  if (element.classification_profile_digest !== registered.digest) {
    return {
      status: 'profile_digest_mismatch',
      classificationProfileId: element.classification_profile_id,
      declaredDigest: element.classification_profile_digest,
      expectedDigest: registered.digest,
    }
  }
  const facts = effectFactsFromElement(element, options)
  return {
    status: 'recomputed',
    classificationProfileId: element.classification_profile_id,
    result: registered.profile.classify(facts),
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
  | { ok: false; reason: 'profile_digest_mismatch'; classificationProfileId: string; declaredDigest: string; expectedDigest: string }

/** Verify an element's asserted cache class (if any) against the recompute.
 *  A cache is a convenience only and is never trusted: a mismatch fails. An
 *  unknown profile or a profile-digest mismatch cannot be verified and surfaces
 *  distinctly. */
export function verifyAssertedClass(
  element: EffectInstantiationElement,
  options?: RecomputeOptions,
): AssertedClassCheck {
  const outcome = recomputeEffect(element, options)
  if (outcome.status === 'unknown_profile') {
    return { ok: false, reason: 'unknown_profile', classificationProfileId: outcome.classificationProfileId }
  }
  if (outcome.status === 'profile_digest_mismatch') {
    return {
      ok: false,
      reason: 'profile_digest_mismatch',
      classificationProfileId: outcome.classificationProfileId,
      declaredDigest: outcome.declaredDigest,
      expectedDigest: outcome.expectedDigest,
    }
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
  return 'sha256:' + createHash('sha256').update(canonicalizeJCS(receipt)).digest('hex')
}
/** Write-boundary twin of hashExecutionReceipt().
 *
 *  Emits the same bytes as hashExecutionReceipt() for every value it accepts. The only difference
 *  is that an integer-valued number outside the interoperable IEEE 754 range is
 *  refused instead of serialized. Use at signing and new-write boundaries ONLY:
 *  hashExecutionReceipt() stays unrestricted so an artifact signed before this rule keeps
 *  verifying. */
export function hashExecutionReceiptForWrite(receipt: ExecutionStageReceipt): string {
  return 'sha256:' + createHash('sha256').update(canonicalizeJCSForWrite(receipt)).digest('hex')
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
    execution_receipt_hash: hashExecutionReceiptForWrite(execution),
    action_ref: execution.action_ref,
    realized_class: input.realized_class,
    evidence_status: input.evidence_status,
    reconciled_at: input.reconciled_at,
  }
  const value = sign(canonicalizeJCS(body), input.signerPrivateKey)
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
  if (!verify(canonicalizeJCS(body), signature.value, signature.public_key)) {
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

// ══════════════════════════════════════
// STEP v0-2 - Effect identity and lineage (v4 section 2)
// ══════════════════════════════════════
//
// Every effect element carries a stable identity so precedence is defined
// without array position. The fold (a later step) classifies from the LATEST
// valid lineage state per effect_id, never from position in instantiated_effects
// and never from the existence of a right. This step adds and validates the
// identity fields only; it does not build the fold.

/** The signed authoritative fields of one effect state as a null-free object
 *  (v4 section 2). It commits to every signed field: effect_id, sequence,
 *  predecessor_effect_state_hash, the raw effect facts, classification_profile_id,
 *  classification_profile_digest, the evidence status, and the receipt/action
 *  binding (action_ref, action_instance_id). The asserted class is signed content
 *  and part of the state identity, so it is included when present, but it is
 *  non-authoritative for classification (a verifier recomputes). Computed
 *  verification outputs, the state hash itself, and out-of-object signatures are
 *  excluded: the builder reads only the known signed fields, so an extra property
 *  on the element object cannot enter the preimage. Only non-null fields are
 *  included, the same parity-safe rule the profile content follows, because the
 *  SDK JCS implementations diverge on null-valued keys. */
export function effectStatePreimage(el: EffectInstantiationElement): Record<string, unknown> {
  const p: Record<string, unknown> = {
    effect_scope: el.effect_scope,
    effect_target_ref: el.effect_target_ref,
    finality_state: el.finality_state,
    evidence_status: el.evidence_status,
    classification_profile_id: el.classification_profile_id,
    classification_profile_digest: el.classification_profile_digest,
    action_ref: el.action_ref,
    action_instance_id: el.action_instance_id,
    effect_id: el.effect_id,
    sequence: el.sequence,
  }
  if (el.recovery_mechanism_ref != null) p.recovery_mechanism_ref = el.recovery_mechanism_ref
  if (el.recovery_controller != null) p.recovery_controller = el.recovery_controller
  if (el.recovery_deadline != null) p.recovery_deadline = el.recovery_deadline
  if (el.predecessor_effect_state_hash != null) p.predecessor_effect_state_hash = el.predecessor_effect_state_hash
  if (el.asserted_realized_class !== undefined) p.asserted_realized_class = el.asserted_realized_class
  return p
}

/** Domain-separated hash of one effect state (v4 section 2):
 *  SHA-256( UTF8("APS-REVERSIBILITY-EFFECT-STATE-V0") || 0x00 || UTF8(JCS(preimage)) )
 *  over the null-free preimage of every signed authoritative field. Chains a
 *  lineage: a later state's predecessor_effect_state_hash references this. Any
 *  language that JCS-canonicalizes the same preimage reproduces it byte-for-byte. */
export function hashEffectState(element: EffectInstantiationElement): string {
  const preimage = Buffer.concat([
    Buffer.from('APS-REVERSIBILITY-EFFECT-STATE-V0', 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonicalizeJCS(effectStatePreimage(element)), 'utf8'),
  ])
  return 'sha256:' + createHash('sha256').update(preimage).digest('hex')
}

/** Deterministic derivation of an effect_id (v4 section 2):
 *  base64url( SHA-256( UTF8("APS-REVERSIBILITY-EFFECT-ID-V0") || 0x00 ||
 *  UTF8(JCS({action_ref, action_instance_id, local_effect_id})) ) ), where
 *  local_effect_id is unique within the receipt and STABLE across retries (an
 *  id, not a nonce). The id is a function of stable inputs, so a retry produces
 *  the same effect_id and the same lineage identity. */
export function deriveEffectId(action_ref: string, action_instance_id: string, local_effect_id: string): string {
  const preimage = Buffer.concat([
    Buffer.from('APS-REVERSIBILITY-EFFECT-ID-V0', 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonicalizeJCS({ action_ref, action_instance_id, local_effect_id }), 'utf8'),
  ])
  return createHash('sha256').update(preimage).digest('base64url')
}

/** The typed outcome of lineage validation (v4 section 2, corrected).
 *  - ok: a single rooted, gap-free, correctly chained lineage per effect_id.
 *  - lineage_incomplete: a gap in sequences, a non-zero origin, or no root
 *    (missing states).
 *  - lineage_conflicted: a fork, where one predecessor state has two distinct
 *    successors.
 *  - equivocation: two distinct roots share an effect_id (multiple-roots), or two
 *    states occupy the same (effect_id, sequence) with different hashes without a
 *    shared predecessor. Named as the provable condition; it is NOT a claim about
 *    a semantic collision between unrelated effects.
 *  - invalid_state: a state at sequence n>0 whose predecessor_effect_state_hash
 *    does not equal the hash of the state at n-1 (a broken chain link). */
export type LineageStatus = 'ok' | 'lineage_incomplete' | 'lineage_conflicted' | 'equivocation' | 'invalid_state'

export interface LineageResult {
  status: LineageStatus
  /** Exact-duplicate states (identical full effect-state hash) removed before
   *  the graph checks, aggregated across all effect_ids in the block. */
  duplicate_count: number
}

/** Validate one effect_id's lineage, order-invariant. First removes exact
 *  duplicates (same full hash), then enforces the graph invariant. */
function validateOneLineage(states: EffectInstantiationElement[]): LineageResult {
  // Deduplicate exact-duplicate states by full effect-state hash.
  const byHash = new Map<string, EffectInstantiationElement>()
  let duplicate_count = 0
  for (const s of states) {
    const h = hashEffectState(s)
    if (byHash.has(h)) duplicate_count++
    else byHash.set(h, s)
  }
  const unique = [...byHash.values()]

  // Exactly one root at sequence 0 with a null predecessor.
  const roots = unique.filter((s) => s.predecessor_effect_state_hash === null)
  if (roots.length > 1) return { status: 'equivocation', duplicate_count }
  if (roots.length === 0) return { status: 'lineage_incomplete', duplicate_count }
  if (roots[0].sequence !== 0) return { status: 'lineage_incomplete', duplicate_count }

  // Fork: no predecessor hash may have more than one distinct successor. This
  // holds regardless of the successors' sequences, so a fork whose branches sit
  // at different sequences is still a fork, not a broken link.
  const succOfPred = new Map<string, number>()
  for (const s of unique) {
    if (s.predecessor_effect_state_hash !== null) {
      succOfPred.set(s.predecessor_effect_state_hash, (succOfPred.get(s.predecessor_effect_state_hash) ?? 0) + 1)
    }
  }
  if ([...succOfPred.values()].some((c) => c > 1)) {
    return { status: 'lineage_conflicted', duplicate_count }
  }

  // At most one state per sequence. A remaining collision (not from a shared
  // predecessor, since forks were already caught) is an equivocation about the
  // position: two states claim the same sequence with different hashes.
  const bySeq = new Map<number, number>()
  for (const s of unique) bySeq.set(s.sequence, (bySeq.get(s.sequence) ?? 0) + 1)
  if ([...bySeq.values()].some((c) => c > 1)) {
    return { status: 'equivocation', duplicate_count }
  }

  // Consecutive sequences 0..n-1 (a gap is incomplete), and each state at n>0
  // references the hash of the state at n-1 (else the chain link is invalid).
  const ordered = [...unique].sort((a, b) => a.sequence - b.sequence)
  for (let i = 0; i < ordered.length; i++) {
    if (ordered[i].sequence !== i) return { status: 'lineage_incomplete', duplicate_count }
  }
  for (let i = 1; i < ordered.length; i++) {
    if (ordered[i].predecessor_effect_state_hash !== hashEffectState(ordered[i - 1])) {
      return { status: 'invalid_state', duplicate_count }
    }
  }
  return { status: 'ok', duplicate_count }
}

/** Validate the identity and lineage structure of a block, independent of array
 *  order (v4 section 2, corrected). Returns a TYPED status plus a duplicate_count.
 *  The block is ok only when every effect_id's lineage is ok; otherwise the
 *  status is that of the lexicographically first non-ok effect_id (deterministic).
 *  This validates identity only; the lineage-based fold reading (classify from
 *  the latest lineage state per effect_id) is the fold, not built here. */
export function validateEffectLineage(block: EffectInstantiationBlock): LineageResult {
  const byEffect = new Map<string, EffectInstantiationElement[]>()
  for (const el of block.instantiated_effects) {
    const states = byEffect.get(el.effect_id) ?? []
    states.push(el)
    byEffect.set(el.effect_id, states)
  }
  let duplicate_count = 0
  let firstNonOk: LineageStatus | undefined
  for (const effectId of [...byEffect.keys()].sort()) {
    const r = validateOneLineage(byEffect.get(effectId)!)
    duplicate_count += r.duplicate_count
    if (r.status !== 'ok' && firstNonOk === undefined) firstNonOk = r.status
  }
  return { status: firstNonOk ?? 'ok', duplicate_count }
}

/** The latest valid state per effect_id, but ONLY for an ok lineage. Returns
 *  undefined for any non-ok block, so a caller cannot pull a latest state from an
 *  incomplete, conflicted, equivocating, or invalid lineage. Order-invariant. */
export function latestValidEffectStates(
  block: EffectInstantiationBlock,
): Map<string, EffectInstantiationElement> | undefined {
  if (validateEffectLineage(block).status !== 'ok') return undefined
  const byEffect = new Map<string, EffectInstantiationElement[]>()
  for (const el of block.instantiated_effects) {
    const states = byEffect.get(el.effect_id) ?? []
    states.push(el)
    byEffect.set(el.effect_id, states)
  }
  const latest = new Map<string, EffectInstantiationElement>()
  for (const [id, states] of byEffect) {
    latest.set(id, [...states].sort((a, b) => b.sequence - a.sequence)[0])
  }
  return latest
}
