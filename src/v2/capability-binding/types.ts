// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Capability pins and identifier binding.
//
// NOT REQUIRED BY draft-pidlisnyi-aps-03. That document defines no pin syntax and
// states no rule pinning a tool to an implementation digest or a schema. Its nearest
// text is the section 4.1 action reference, verbatim:
//
//   "target is the exact resource, tool, or endpoint against which the action will be
//   dispatched; a profile MUST define its target string construction."
//
// A target names a resource, tool or endpoint. It carries no implementation digest and
// no metadata digest, so it cannot tell two revisions of one tool behind one endpoint
// apart. Nothing in draft-03 supplies the missing distinction, and proposed -04 excludes
// capability binding by name.
//
// Concept source: the aeoess/agent-authority-lifecycle concept document, invariant
// candidate CAND-07 as rewritten ("a stable name does not establish stable semantics"),
// and the AUTHORITY-LIFECYCLE.md concepts "Action or capability binding" and "Target
// binding". All PROPOSED. Nothing here claims otherwise.
//
// WHAT THIS MODULE DOES NOT TOUCH. `AuthorityValidationState` stays the four draft-03
// values, `verifyAuthorityDelegationChain` returns byte for byte what it returned, and
// `AuthorityVectorV1` gains no eighth facet (draft-03 section 3.2 closes it at seven and
// makes a missing facet invalid). A pin rides in the existing scope grammar or in a
// separate record. A caller that never imports this module sees exactly today's
// behaviour.

import type { BoundaryOutcome, EstablishmentGap } from '../lifecycle-state/types.js'

/** Where a pin lives.
 *
 *  - `scope_grant_v0`  further colon-separated segments under the tool grant, which keeps
 *                      the pin inside the scope grammar draft-03 section 3.2 already
 *                      defines. It has a side effect worth stating: a pin then narrows
 *                      across a chain by the ordinary covering rule, so a child carrying a
 *                      different pin fails as scope widening rather than as a binding
 *                      failure. This module's parser and writer implement this encoding.
 *  - `bound_record_v0` a separate signed record referencing `delegation_id`. Reserved as a
 *                      name so a caller can state which encoding it chose. This module
 *                      does not define its wire format.
 *
 *  draft-03 defines neither. PROPOSED. */
export type PinEncoding = 'scope_grant_v0' | 'bound_record_v0'

/** What a grant pins about one named tool.
 *
 *  Each axis is a SET, not a single value, because a grant may legitimately pin more than
 *  one acceptable revision, and because an empty array is the unambiguous way to say "this
 *  axis is not pinned". An EMPTY array on both axes is the unpinned grant, and CAND-07's
 *  rewritten statement is explicit about what happens there: the verdict records that
 *  referent continuity was not established rather than admitting silently.
 *
 *  A `CapabilityPin` of `null` at an evaluator's input is a different thing again: the
 *  grant does not name the tool at all. See `evaluateCapabilityBinding`. PROPOSED. */
export interface CapabilityPin {
  readonly tool_name: string
  /** Digests of acceptable implementations, `sha256:<64 lowercase hex>`. Empty means this
   *  axis is not pinned. */
  readonly implementation_digests: readonly string[]
  /** Digests of acceptable declared metadata blocks. Empty means this axis is not pinned.
   *  DISTINCT from `implementation_digests` on purpose: a tool can keep its name and its
   *  implementation bytes while its declared schema, description or permissions change,
   *  which is a different evidence problem from an implementation that drifted. */
  readonly metadata_digests: readonly string[]
  readonly encoding: PinEncoding
}

/** What the verifier could establish about continuity of the thing named.
 *
 *  Three values, not two, and the third is the point of this module:
 *
 *  - `established`     the referent the grant pinned is the referent now observed.
 *  - `not_established` the verifier could not reach a conclusion either way. Nothing was
 *                      pinned, or no accepted attestation covered what the answer needed.
 *                      Ignorance, never a finding about the world.
 *  - `mismatch`        the verifier DID reach a conclusion and the conclusion is that the
 *                      referent changed. This is an established negative, not ignorance.
 *
 *  Concept source: aeoess/agent-authority-lifecycle, CAND-07 v2 and the invariant
 *  candidates' section on the two uses of "not established". PROPOSED. */
export type ReferentContinuity = 'established' | 'not_established' | 'mismatch'

/** What this module decides about ONE action at ONE authorization boundary.
 *
 *  `outcome` is the `BoundaryOutcome` subject from the lifecycle state vocabulary, not an
 *  artifact verdict: nothing here makes any delegation invalid. The grant is a fine grant
 *  and the chain result is untouched. What is decided is whether the action now attempted
 *  is within it.
 *
 *  THE MAPPING FROM `continuity` TO `outcome` IS THE CONTESTED PART AND IT IS STATED HERE
 *  RATHER THAN BURIED. CAND-07 v2 reads, verbatim: "Where something pins it and the pin
 *  does not match, the action is denied with a mismatch reason rather than reported as not
 *  established." So `mismatch` maps to `denied`, and `not_established` maps to
 *  `not_established` with its limbs named. The `aps-capability-binding-drift-v0` and
 *  `aps-lifecycle-identifier-reuse-and-rename-v0` candidate fixture families label an
 *  established mismatch `not_established` instead, in a three-value vocabulary that has no
 *  denial member; CAND-07 v2's own "Tested by" note records that as the fixtures'
 *  mislabelling rather than as a second reading. This module follows CAND-07 v2. See
 *  `projectBoundaryOutcomeToCandidateV0` for reproducing the fixture labelling explicitly,
 *  and OPEN QUESTIONS in the module README block of ./binding.ts. */
export interface ReferentBindingResult {
  readonly outcome: BoundaryOutcome
  readonly continuity: ReferentContinuity
  /** Stable, module-local, SCREAMING_SNAKE_CASE, matching the lifecycle state vocabulary's
   *  convention. Every code this module emits is listed in
   *  `CAPABILITY_BINDING_REASON_CODES` or `IDENTIFIER_CONTINUITY_REASON_CODES`. */
  readonly reason_code: string
  /** Present with at least one member exactly when `outcome` is `not_established`, and
   *  absent otherwise. BROAD-L7 requires a denial on an unestablished state to record
   *  which of source, freshness or coverage was missing. */
  readonly missing?: readonly EstablishmentGap[]
  /** Free-form, for a human reading a receipt. Never parsed. */
  readonly detail?: string
}

/** A `ReferentBindingResult` for the identifier limb, plus who the accepted custodian
 *  records say holds the identifier at the instant asked about.
 *
 *  `controller_at_instant` is `null` whenever the boundary could not establish a single
 *  holder, which includes the conflict case where two accepted records disagree. A
 *  non-null value on a `denied` result is the load-bearing one: it names the party that
 *  holds the identifier now, which is precisely the fact that is NOT the pinned party. */
export interface IdentifierContinuityResult extends ReferentBindingResult {
  readonly controller_at_instant: string | null
}

/** What a caller observed about one tool attestation, with the crypto already done.
 *
 *  Built by `observeToolAttestation`, which runs the SDK's own `verifyToolIntegrity`. Kept
 *  as a separate value so `evaluateCapabilityBinding` stays pure: no clock, no network, no
 *  crypto, per the same rule the chain verifier follows. PROPOSED. */
export interface ToolAttestationObservation {
  /** The tool name the presented entry is about, as the entry itself states it. */
  readonly attested_tool_name: string
  /** The implementation digest the entry attests, `sha256:<64 lowercase hex>`. */
  readonly attested_implementation_digest: string
  /** Whether a trusted attestor key was resolvable FOR THE TOOL. Resolution is by tool,
   *  never from the `attestorId` the presented entry asserts about itself: a valid
   *  signature establishes who signed, not that they had standing to attest this tool. */
  readonly attestor_key_resolved: boolean
  /** `verifyToolIntegrity().attestorSignatureValid` against that resolved key. `false`
   *  whenever no key resolved. */
  readonly attestor_signature_valid: boolean
}

/** Every reason code `evaluateCapabilityBinding` can emit. */
export const CAPABILITY_BINDING_REASON_CODES = [
  /** authorized: every pinned axis matched what was observed. */
  'CAPABILITY_CONTINUITY_ESTABLISHED',
  /** denied: the grant does not name this tool at all. An established negative, not
   *  ignorance: the grant is in front of the verifier and it does not say this. */
  'TOOL_NOT_IN_GRANT_SCOPE',
  /** denied: the grant names the tool but does not carry a scope the action requires. */
  'SCOPE_NOT_GRANTED',
  /** not_established (source): no trusted attestor key resolved for this tool. */
  'TOOL_ATTESTOR_KEY_UNRESOLVED',
  /** not_established (source): the entry's signature does not verify against the key the
   *  caller resolved for this tool, so no accepted attestation exists. */
  'TOOL_ATTESTATION_SIGNATURE_INVALID',
  /** not_established (coverage): no attestation was presented at all. */
  'TOOL_ATTESTATION_ABSENT',
  /** not_established (coverage): the entry is about a different tool, so the claim does
   *  not cover what the verdict needed. */
  'REGISTRY_ENTRY_TOOL_NAME_MISMATCH',
  /** not_established (freshness): the signed entry no longer describes the implementation
   *  observed now. The entry is a claim, and the claim is stale. */
  'REGISTRY_ENTRY_IMPLEMENTATION_MISMATCH',
  /** not_established (coverage): the grant names the tool and pins neither axis. CAND-07
   *  v2's unpinned limb: recorded, not admitted, and not resolved either way. */
  'NO_CAPABILITY_PIN_IN_GRANT',
  /** not_established (coverage): the grant pins the declared metadata and says nothing
   *  about the implementation. A metadata pin does not cover an implementation. */
  'IMPLEMENTATION_NOT_PINNED_IN_GRANT',
  /** not_established (coverage): the grant pins the implementation and says nothing about
   *  the declared metadata. An implementation pin does not cover a schema. */
  'METADATA_NOT_PINNED_IN_GRANT',
  /** not_established (coverage): the caller observed nothing on an axis the evaluation
   *  needed. `detail` names the axis. The SDK cannot reach a running tool and must not
   *  pretend that an unobserved axis matched. */
  'OBSERVATION_ABSENT',
  /** denied: the implementation pin is established not to match. */
  'PINNED_IMPLEMENTATION_DIGEST_MISMATCH',
  /** denied: the declared-metadata pin is established not to match. */
  'PINNED_METADATA_DIGEST_MISMATCH',
] as const

export type CapabilityBindingReasonCode = (typeof CAPABILITY_BINDING_REASON_CODES)[number]

/** Every reason code `evaluateIdentifierContinuity` can emit. */
export const IDENTIFIER_CONTINUITY_REASON_CODES = [
  /** authorized: a single accepted holder at the instant, equal to a pinned controller,
   *  with every interval since issuance either bound to that holder or covered by an
   *  accepted retention record. */
  'IDENTIFIER_CONTINUITY_ESTABLISHED',
  /** not_established (coverage): the grant does not declare the identifier the action in
   *  fact relies on. A verifier that never modelled the identifier has no record to
   *  invalidate when control of it moves. */
  'IDENTIFIER_DEPENDENCY_NOT_DECLARED',
  /** not_established (coverage): the grant names the identifier and pins no controller. */
  'IDENTIFIER_CONTROLLER_NOT_PINNED',
  /** not_established (coverage): no accepted binding record covers the instant asked
   *  about. */
  'IDENTIFIER_BINDING_LAPSED',
  /** not_established (source): two or more accepted custodian records name different
   *  holders at the instant, an unresolved conflict between accepted sources. */
  'IDENTIFIER_BINDING_CONFLICT',
  /** denied: a single accepted holder is established, and it is not a pinned controller.
   *  The string is the same. The party behind it is not. */
  'IDENTIFIER_CONTROLLER_CHANGED',
  /** not_established (coverage): an interval between issuance and the instant is neither
   *  bound to the holder nor covered by an accepted retention record. An interval the
   *  identifier was held by nobody is an interval anyone could have taken it. */
  'IDENTIFIER_CONTINUITY_GAP_UNCOVERED',
  /** not_established (source): a retention record covering the gap exists but its issuer
   *  is not the custodian this caller resolves for that identifier kind. Worth naming
   *  apart from there being no retention record at all. */
  'RETENTION_CUSTODIAN_WITHOUT_STANDING',
] as const

export type IdentifierContinuityReasonCode = (typeof IDENTIFIER_CONTINUITY_REASON_CODES)[number]

/** Thrown when a caller asks this module for something the vocabulary does not allow, or
 *  passes a malformed record. A shape rule broken at a call boundary is a programming
 *  error, not a verdict. */
export class CapabilityBindingError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'CapabilityBindingError'
    this.code = code
  }
}

/** Internal constructor enforcing the one shape rule this module has: `missing` is present
 *  with at least one member exactly when `outcome` is `not_established`. */
export function referentBindingResult(input: {
  outcome: BoundaryOutcome
  continuity: ReferentContinuity
  reason_code: string
  missing?: readonly EstablishmentGap[]
  detail?: string
}): ReferentBindingResult {
  const wantsMissing = input.outcome === 'not_established'
  if (wantsMissing && (input.missing === undefined || input.missing.length === 0)) {
    throw new CapabilityBindingError(
      'MISSING_REQUIRED',
      'a not_established outcome must name at least one missing establishment limb',
    )
  }
  if (!wantsMissing && input.missing !== undefined) {
    throw new CapabilityBindingError(
      'MISSING_NOT_ALLOWED',
      `missing is only meaningful on not_established, not on ${input.outcome}`,
    )
  }
  const out: {
    outcome: BoundaryOutcome
    continuity: ReferentContinuity
    reason_code: string
    missing?: readonly EstablishmentGap[]
    detail?: string
  } = {
    outcome: input.outcome,
    continuity: input.continuity,
    reason_code: input.reason_code,
  }
  if (input.missing !== undefined) out.missing = Object.freeze([...input.missing])
  if (input.detail !== undefined) out.detail = input.detail
  return Object.freeze(out)
}

/** PROPOSED. Project a boundary outcome into the three-value verdict vocabulary the
 *  `aps-capability-binding-drift-v0` and `aps-lifecycle-identifier-reuse-and-rename-v0`
 *  candidate fixture families declare, so a caller reproducing one of those families does
 *  not have to write the collapse out by hand and get it silently wrong.
 *
 *  THIS FUNCTION COLLAPSES `denied` INTO `not_established` AND THAT IS A KNOWN DIVERGENCE,
 *  NOT THIS MODULE'S READING. Those families were authored against the concept document at
 *  0.1.2-draft, before CAND-07 was rewritten, and their vocabulary has no denial member,
 *  so an established pinned-referent mismatch had nowhere else to land. CAND-07 v2 now
 *  says such a mismatch is a denial with a mismatch reason. Reach for this only to
 *  reproduce a v0 family's labelling, never to decide anything.
 *
 *  `positiveLabel` is `'admitted'` for the capability-binding-drift family and `'valid'`
 *  for the identifier-reuse family, which spell the positive differently. */
export function projectBoundaryOutcomeToCandidateV0(
  outcome: BoundaryOutcome,
  positiveLabel: 'admitted' | 'valid',
): 'admitted' | 'valid' | 'not_established' {
  if (outcome === 'authorized') return positiveLabel
  return 'not_established'
}
