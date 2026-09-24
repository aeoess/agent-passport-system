// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Deciding whether an activation condition is established at an instant.
// See ./types.ts for the specification position and for the three parameters this module
// refuses to default.

import { parseRfc3339 } from '../../core/rfc3339.js'
import { verify as verifyEd25519 } from '../../crypto/keys.js'
import type {
  AuthorityValidationResult,
  VerificationKeyResolver,
} from '../authority-delegation/types.js'
import type { LifecycleMappingOptions } from '../lifecycle-state/map.js'
import { mapAuthorityValidationToLifecycle } from '../lifecycle-state/map.js'
import { lifecycleState } from '../lifecycle-state/state.js'
import type {
  CompositeAuthorityResult,
  LifecycleStateResult,
} from '../lifecycle-state/types.js'
import { activationAttestationSignatureInput } from './canonical.js'
import {
  ACTIVATION_ATTESTATION_TYPE,
  ACTIVATION_CONDITION_TYPE,
  ACTIVATION_GAPS_BY_REASON,
  ACTIVATION_INSTANT_BASES,
  ActivationError,
  type ActivationAttestationV0,
  type ActivationConditionV0,
  type ActivationFinding,
  type ActivationFindingKind,
  type ActivationReasonCode,
  type ActivationRejection,
  type ActivationResult,
  type AttestorRoleResolver,
  type RecordedEventActivationConditionV0,
} from './types.js'

/** How far through the checks a rejected attestation got. When no record was accepted, the
 *  reported code is the reason of the record that got FURTHEST, so the verdict names the
 *  closest thing to usable evidence that was presented. Ties break on `attestation_id`
 *  ascending, which makes the answer independent of presentation order. */
const REJECTION_RANK: Readonly<Record<ActivationReasonCode, number>> = Object.freeze({
  ATTESTATION_RECORD_TYPE_NOT_ACCEPTED: 1,
  ATTESTATION_SIGNATURE_UNVERIFIED: 2,
  ATTESTATION_ATTESTOR_BINDING_MISMATCH: 3,
  ATTESTATION_ATTESTOR_ROLE_UNKNOWN: 4,
  ATTESTATION_ROLE_CLAIM_CONFLICT: 5,
  ATTESTATION_ATTESTOR_ROLE_MISMATCH: 6,
  ATTESTATION_CONDITION_MISMATCH: 7,
  ATTESTATION_UNKNOWN_ASSERTION: 8,
  ATTESTATION_INSTANT_MALFORMED: 9,
  ATTESTATION_DOES_NOT_REACH_ACTION: 10,
  // Verdict-level codes never rank: they are not rejections of a record.
  ACTIVATION_ESTABLISHED: 0,
  CONDITION_DATE_NOT_REACHED: 0,
  CONDITION_ESTABLISHED_NOT_YET_OCCURRED: 0,
  CONDITION_FIRST_OCCURRED_AFTER_ACTION: 0,
  CONDITION_EVIDENCE_CONFLICT: 0,
  ACTIVATION_THRESHOLD_NOT_MET: 0,
  NO_ATTESTATION_PRESENTED: 0,
  CONDITION_DELEGATION_MISMATCH: 0,
})

export interface ActivationVerificationInput {
  /** The condition gating the grant. Shape-checked; a malformed condition throws. */
  readonly condition: ActivationConditionV0
  /** The `delegation_id` of the grant being evaluated. Checked against the condition's own
   *  `delegation_id`, so a condition for another grant produces a verdict rather than being
   *  silently applied to this one. */
  readonly delegationId: string
  /** The instant the action is being authorized at. RFC 3339, offset required. */
  readonly actionInstant: string
  /** Presented attestations, in presentation order. Absent or empty is the "nothing
   *  presented" case, which is `not_established` and never `not_yet_effective`. */
  readonly attestations?: readonly ActivationAttestationV0[]
  /** Resolves whether an attestor held a role. Required even for a date condition, so a
   *  caller cannot get a date answer and then discover the event path needs plumbing it does
   *  not have. */
  readonly resolveAttestorRole: AttestorRoleResolver
  /** Resolves the key that signed an attestation, selected at the attestation's own
   *  `attested_at` rather than at verification time. Same resolver shape and the same
   *  historical-key discipline draft-03 section 2.4 states for delegations: the key current at
   *  verification time is not necessarily the one that signed this record. The `issuer`
   *  argument receives the attestation's `attestor`. */
  readonly resolveVerificationKey: VerificationKeyResolver
  /** Exact bytes a presented attestation's signature covers.
   *
   *  Absent is the normal case: the module uses its own domain-tagged preimage
   *  (`activationAttestationSignatureInput`) and, because that preimage belongs to a record
   *  type it owns, REQUIRES `record_type` to be `ACTIVATION_ATTESTATION_TYPE`.
   *
   *  Supplied is the escape hatch for a model that accepts condition evidence in a shape this
   *  module does not own. Which bytes a signature covers is a property of a record type, and
   *  an SDK cannot dictate the signing convention of a record type it did not define. A caller
   *  using it must also declare `acceptedAttestationRecordTypes`, or the module has no stated
   *  basis for accepting the record at all. */
  readonly attestationPreimage?: (attestation: ActivationAttestationV0) => string
  /** Which attestation record types the model accepts as evidence for this condition.
   *  Required when `attestationPreimage` is supplied. Membership is exact string equality. */
  readonly acceptedAttestationRecordTypes?: readonly string[]
}

function assertInstant(value: string, label: string): number {
  const parsed = parseRfc3339(value)
  if (!parsed.ok) {
    throw new ActivationError(
      'INSTANT_MALFORMED',
      `${label} is not an RFC 3339 instant with an offset (${parsed.reason})`,
    )
  }
  return parsed.ms
}

/** Shape rules, each with the reason it exists. A condition that breaks one is a programming
 *  error at the caller, not a verdict about evidence, so this throws.
 *
 *  Exported so a caller can validate a condition it received before reaching a boundary. */
export function validateActivationCondition(
  condition: ActivationConditionV0,
): ActivationConditionV0 {
  if (condition === null || typeof condition !== 'object') {
    throw new ActivationError('CONDITION_MALFORMED', 'condition is not an object')
  }
  if (condition.record_type !== ACTIVATION_CONDITION_TYPE) {
    throw new ActivationError(
      'CONDITION_RECORD_TYPE_UNKNOWN',
      `condition record_type must be ${ACTIVATION_CONDITION_TYPE}`,
    )
  }
  for (const field of ['condition_id', 'delegation_id'] as const) {
    if (typeof condition[field] !== 'string' || condition[field].length === 0) {
      throw new ActivationError(
        'CONDITION_MALFORMED',
        `condition ${field} must be a non-empty string`,
      )
    }
  }

  if (condition.condition_type === 'date') {
    assertInstant(condition.activation_date, 'condition activation_date')
    return condition
  }

  if (condition.condition_type === 'recorded_event') {
    for (const field of ['event_type', 'event_id'] as const) {
      if (typeof condition[field] !== 'string' || condition[field].length === 0) {
        throw new ActivationError(
          'CONDITION_MALFORMED',
          `condition ${field} must be a non-empty string`,
        )
      }
    }
    const roles = condition.required_attestor_roles
    if (!Array.isArray(roles) || roles.length === 0) {
      // A condition naming no accepted source has not stated what it accepts. Accepting
      // anything would make the role check decorative, and refusing everything would be a
      // fail-closed ruling the text does not state. Refuse the CONDITION instead.
      throw new ActivationError(
        'CONDITION_ROLES_REQUIRED',
        'required_attestor_roles must name at least one role',
      )
    }
    for (const role of roles) {
      if (typeof role !== 'string' || role.length === 0) {
        throw new ActivationError(
          'CONDITION_ROLES_REQUIRED',
          'required_attestor_roles must contain only non-empty strings',
        )
      }
    }
    if (!Number.isInteger(condition.threshold) || condition.threshold < 1) {
      throw new ActivationError(
        'CONDITION_THRESHOLD_INVALID',
        'threshold must be an integer of at least 1, and this module declares no default',
      )
    }
    if (!(ACTIVATION_INSTANT_BASES as readonly string[]).includes(condition.instant_basis)) {
      throw new ActivationError(
        'CONDITION_INSTANT_BASIS_REQUIRED',
        `instant_basis must be one of ${ACTIVATION_INSTANT_BASES.join(', ')}, and this module declares no default`,
      )
    }
    return condition
  }

  throw new ActivationError(
    'CONDITION_TYPE_UNKNOWN',
    'condition_type must be date or recorded_event',
  )
}

type Classification =
  | { readonly ok: true; readonly finding: ActivationFindingKind }
  | { readonly ok: false; readonly reason: ActivationReasonCode }

function classify(
  attestation: ActivationAttestationV0,
  condition: RecordedEventActivationConditionV0,
  actionMs: number,
  input: ActivationVerificationInput,
): Classification {
  const usesOwnPreimage = input.attestationPreimage === undefined
  const accepted = input.acceptedAttestationRecordTypes

  // 1. Record type. A record whose type the model has not declared it accepts for this
  //    condition is not evidence, however well it verifies.
  if (usesOwnPreimage) {
    if (attestation.record_type !== ACTIVATION_ATTESTATION_TYPE) {
      return { ok: false, reason: 'ATTESTATION_RECORD_TYPE_NOT_ACCEPTED' }
    }
  } else if (!accepted!.includes(attestation.record_type)) {
    return { ok: false, reason: 'ATTESTATION_RECORD_TYPE_NOT_ACCEPTED' }
  }

  // 2. Signature, over the record's own bytes, under the key authorized at `attested_at`.
  if (typeof attestation.attested_at !== 'string') {
    return { ok: false, reason: 'ATTESTATION_INSTANT_MALFORMED' }
  }
  if (!parseRfc3339(attestation.attested_at).ok) {
    return { ok: false, reason: 'ATTESTATION_INSTANT_MALFORMED' }
  }
  if (
    typeof attestation.verification_method !== 'string' ||
    typeof attestation.signature !== 'string' ||
    typeof attestation.attestor !== 'string'
  ) {
    return { ok: false, reason: 'ATTESTATION_SIGNATURE_UNVERIFIED' }
  }
  const resolved = input.resolveVerificationKey(
    attestation.attestor,
    attestation.verification_method,
    attestation.attested_at,
  )
  // A resolver failure and a missing key are the same finding here: no accepted source
  // produced a key, so the record is not usable evidence. The granular key-resolution
  // outcomes belong to chain verification, which reports them on its own result.
  if (typeof resolved !== 'string' || resolved.length === 0) {
    return { ok: false, reason: 'ATTESTATION_SIGNATURE_UNVERIFIED' }
  }
  const preimage = usesOwnPreimage
    ? activationAttestationSignatureInput(attestation)
    : input.attestationPreimage!(attestation)
  let signatureOk = false
  try {
    signatureOk = verifyEd25519(preimage, attestation.signature, resolved)
  } catch {
    signatureOk = false
  }
  if (!signatureOk) return { ok: false, reason: 'ATTESTATION_SIGNATURE_UNVERIFIED' }

  // 3. The verification method has to belong to the attestor the body names, or a valid
  //    signature says nothing about who attested.
  if (!attestation.verification_method.startsWith(`${attestation.attestor}#`)) {
    return { ok: false, reason: 'ATTESTATION_ATTESTOR_BINDING_MISMATCH' }
  }

  // 4. The attestor's own role claim, checked AGAINST the resolver. Never believed.
  if (typeof attestation.attestor_role === 'string' && attestation.attestor_role.length > 0) {
    const claimed = input.resolveAttestorRole(
      attestation.attestor,
      attestation.attestor_role,
      attestation.attested_at,
    )
    if (claimed === 'unknown') return { ok: false, reason: 'ATTESTATION_ATTESTOR_ROLE_UNKNOWN' }
    if (claimed !== 'holds') return { ok: false, reason: 'ATTESTATION_ROLE_CLAIM_CONFLICT' }
  }

  // 5. Does the attestor hold a role the condition requires? A source the model does not
  //    accept for THIS condition is not evidence in either direction: it cannot establish the
  //    condition and it cannot establish that the condition was unmet.
  let holdsRequired = false
  let anyUnknown = false
  for (const role of condition.required_attestor_roles) {
    const standing = input.resolveAttestorRole(attestation.attestor, role, attestation.attested_at)
    if (standing === 'holds') {
      holdsRequired = true
      break
    }
    if (standing === 'unknown') anyUnknown = true
  }
  if (!holdsRequired) {
    return {
      ok: false,
      reason: anyUnknown
        ? 'ATTESTATION_ATTESTOR_ROLE_UNKNOWN'
        : 'ATTESTATION_ATTESTOR_ROLE_MISMATCH',
    }
  }

  // 6. Condition binding.
  if (
    attestation.condition_id !== condition.condition_id ||
    attestation.event_type !== condition.event_type ||
    attestation.event_id !== condition.event_id
  ) {
    return { ok: false, reason: 'ATTESTATION_CONDITION_MISMATCH' }
  }

  // 7. What it establishes, measured on the instant the CONDITION declares governs.
  if (attestation.assertion === 'condition_occurred') {
    const raw =
      condition.instant_basis === 'attestation_written'
        ? attestation.attested_at
        : attestation.occurred_at
    if (typeof raw !== 'string') return { ok: false, reason: 'ATTESTATION_UNKNOWN_ASSERTION' }
    const parsed = parseRfc3339(raw)
    if (!parsed.ok) return { ok: false, reason: 'ATTESTATION_INSTANT_MALFORMED' }
    return {
      ok: true,
      finding: parsed.ms <= actionMs ? 'occurred_by_action' : 'occurred_after_action',
    }
  }

  if (attestation.assertion === 'condition_not_occurred_through') {
    const raw = attestation.not_occurred_through
    if (typeof raw !== 'string') return { ok: false, reason: 'ATTESTATION_UNKNOWN_ASSERTION' }
    const parsed = parseRfc3339(raw)
    if (!parsed.ok) return { ok: false, reason: 'ATTESTATION_INSTANT_MALFORMED' }
    // A negative that stops short of the action instant says nothing about the interval
    // between where it stops and the action. That is the coverage limb, not a source problem.
    if (parsed.ms < actionMs) return { ok: false, reason: 'ATTESTATION_DOES_NOT_REACH_ACTION' }
    return { ok: true, finding: 'not_occurred_through_action' }
  }

  return { ok: false, reason: 'ATTESTATION_UNKNOWN_ASSERTION' }
}

function notEstablishedFor(code: ActivationReasonCode): LifecycleStateResult {
  return lifecycleState({
    verdict: 'not_established',
    reason_code: code,
    missing: ACTIVATION_GAPS_BY_REASON[code] ?? ['source'],
  })
}

/**
 * Decide whether an activation condition is established for one action at one instant.
 *
 * Three verdicts are reachable and `invalid` is not one of them:
 *
 * | situation                                                    | verdict             |
 * |--------------------------------------------------------------|---------------------|
 * | condition established at or before the action instant         | `valid`             |
 * | established as not met at that instant, or first met after it | `not_yet_effective` |
 * | the verifier cannot tell                                      | `not_established`   |
 *
 * NOT ESTABLISHED IS NOT THE NEGATION OF THE CLAIM. It says the verifier could not reach a
 * conclusion and names which establishment limb was missing. `not_yet_effective` says the
 * verifier DID reach a conclusion and it was negative; its remedy is to wait, where
 * `not_established`'s remedy is a better source. Collapsing the two throws away a decidable
 * answer the verifier already had.
 *
 * NO RETROACTIVE ACTIVATION, KEYED ON THE CONDITION'S OWN INSTANT. A record putting the
 * condition's first occurrence after the action instant leaves that action
 * `not_yet_effective`, and the SAME record establishes the condition for any later action.
 * What the rule keys on is the condition's instant, not the instant someone wrote the record:
 * learning on Thursday that a condition was met on Monday is the normal case for any model
 * built around an after-the-fact determination, and under
 * `instant_basis: 'condition_occurrence'` such a record establishes the condition. A model
 * that reads it the other way says so with `instant_basis: 'attestation_written'`.
 *
 * ORDER OF RESOLUTION, and why contradiction sits above acceptance:
 *
 *   1. two accepted records that disagree      `not_established`, `CONDITION_EVIDENCE_CONFLICT`
 *   2. `threshold` records say occurred by it  `valid`
 *   3. `threshold` records say not occurred    `not_yet_effective`
 *   4. `threshold` records say occurred after  `not_yet_effective`
 *   5. some accepted, fewer than `threshold`   `not_established`, `ACTIVATION_THRESHOLD_NOT_MET`
 *   6. none accepted                           `not_established`, furthest rejection reason
 *
 * Contradiction is evaluated on PRESENCE, not on counts. Two acceptable records that disagree
 * leave the verifier unable to tell which holds, and neither is discarded in favour of the
 * other: preferring the later record, or the negative one, or a majority, would each be a
 * precedence rule the concept text does not state.
 *
 * This function reads no clock and makes no network call. `actionInstant` is a parameter.
 *
 * Proposed. Concept source: aeoess/agent-authority-lifecycle, invariant candidates CAND-04
 * and CAND-13 (activation half) and BROAD-L7. Not required by draft-pidlisnyi-aps-03.
 */
export function verifyActivation(input: ActivationVerificationInput): ActivationResult {
  if (input === null || typeof input !== 'object') {
    throw new ActivationError('INPUT_MALFORMED', 'input is not an object')
  }
  if (typeof input.resolveAttestorRole !== 'function') {
    throw new ActivationError(
      'ROLE_RESOLVER_REQUIRED',
      'resolveAttestorRole is required: role standing is resolved outside the record, always',
    )
  }
  if (typeof input.resolveVerificationKey !== 'function') {
    throw new ActivationError('KEY_RESOLVER_REQUIRED', 'resolveVerificationKey is required')
  }
  if (input.attestationPreimage !== undefined) {
    const accepted = input.acceptedAttestationRecordTypes
    if (!Array.isArray(accepted) || accepted.length === 0) {
      throw new ActivationError(
        'ACCEPTED_RECORD_TYPES_REQUIRED',
        'acceptedAttestationRecordTypes must name at least one type when attestationPreimage is supplied',
      )
    }
  }
  if (typeof input.delegationId !== 'string' || input.delegationId.length === 0) {
    throw new ActivationError('DELEGATION_ID_REQUIRED', 'delegationId must be a non-empty string')
  }

  const condition = validateActivationCondition(input.condition)
  const actionMs = assertInstant(input.actionInstant, 'actionInstant')
  const presented = input.attestations ?? []

  if (condition.delegation_id !== input.delegationId) {
    return Object.freeze({
      state: notEstablishedFor('CONDITION_DELEGATION_MISMATCH'),
      condition_id: condition.condition_id,
      condition_type: condition.condition_type,
      findings: Object.freeze([]),
      rejections: Object.freeze([]),
    })
  }

  // A date condition needs no evidence at all. The verifier reads the date off the condition
  // and compares it with the action instant, so an unreached date is a KNOWN negative and
  // never an unknown one. Presented attestations are not consulted.
  if (condition.condition_type === 'date') {
    const reached = assertInstant(condition.activation_date, 'condition activation_date') <= actionMs
    return Object.freeze({
      state: reached
        ? lifecycleState({ verdict: 'valid', reason_code: 'ACTIVATION_ESTABLISHED' })
        : lifecycleState({
            verdict: 'not_yet_effective',
            reason_code: 'CONDITION_DATE_NOT_REACHED',
          }),
      condition_id: condition.condition_id,
      condition_type: condition.condition_type,
      findings: Object.freeze([]),
      rejections: Object.freeze([]),
    })
  }

  const findings: ActivationFinding[] = []
  const rejections: ActivationRejection[] = []
  const counts: Record<ActivationFindingKind, number> = {
    occurred_by_action: 0,
    occurred_after_action: 0,
    not_occurred_through_action: 0,
  }

  for (const attestation of presented) {
    if (attestation === null || typeof attestation !== 'object') {
      throw new ActivationError('ATTESTATION_MALFORMED', 'an attestation is not an object')
    }
    const id = typeof attestation.attestation_id === 'string' ? attestation.attestation_id : ''
    const attestor = typeof attestation.attestor === 'string' ? attestation.attestor : ''
    const outcome = classify(attestation, condition, actionMs, input)
    if (outcome.ok) {
      counts[outcome.finding] += 1
      findings.push(Object.freeze({ attestation_id: id, attestor, finding: outcome.finding }))
    } else {
      rejections.push(Object.freeze({ attestation_id: id, attestor, reason_code: outcome.reason }))
    }
  }

  const frozen = {
    condition_id: condition.condition_id,
    condition_type: condition.condition_type,
    findings: Object.freeze([...findings]),
    rejections: Object.freeze([...rejections]),
  }

  if (counts.occurred_by_action > 0 && counts.not_occurred_through_action > 0) {
    return Object.freeze({ ...frozen, state: notEstablishedFor('CONDITION_EVIDENCE_CONFLICT') })
  }
  if (counts.occurred_by_action >= condition.threshold) {
    return Object.freeze({
      ...frozen,
      state: lifecycleState({ verdict: 'valid', reason_code: 'ACTIVATION_ESTABLISHED' }),
    })
  }
  if (counts.not_occurred_through_action >= condition.threshold) {
    return Object.freeze({
      ...frozen,
      state: lifecycleState({
        verdict: 'not_yet_effective',
        reason_code: 'CONDITION_ESTABLISHED_NOT_YET_OCCURRED',
      }),
    })
  }
  if (counts.occurred_after_action >= condition.threshold) {
    return Object.freeze({
      ...frozen,
      state: lifecycleState({
        verdict: 'not_yet_effective',
        reason_code: 'CONDITION_FIRST_OCCURRED_AFTER_ACTION',
      }),
    })
  }
  if (findings.length > 0) {
    return Object.freeze({ ...frozen, state: notEstablishedFor('ACTIVATION_THRESHOLD_NOT_MET') })
  }

  if (rejections.length === 0) {
    return Object.freeze({ ...frozen, state: notEstablishedFor('NO_ATTESTATION_PRESENTED') })
  }
  const furthest = [...rejections].sort((a, b) => {
    const rank = REJECTION_RANK[b.reason_code] - REJECTION_RANK[a.reason_code]
    return rank !== 0 ? rank : a.attestation_id.localeCompare(b.attestation_id)
  })[0]
  return Object.freeze({ ...frozen, state: notEstablishedFor(furthest.reason_code) })
}

export interface ActivationCompositionOptions {
  /** Passed through to `mapAuthorityValidationToLifecycle` when the chain result is reported
   *  in the lifecycle vocabulary.
   *
   *  The contested reading lives here and stays the CALLER's. Both reference SDKs answer
   *  `invalid` with `NOT_YET_VALID` for a grant whose time facet `not_before` has not been
   *  reached, and that is what the chain result says. An activation-condition date at the same
   *  instant answers `not_yet_effective` here. One instant, two mechanisms carrying the wait,
   *  two answers, and the concept text does not say whether a waiting grant should be
   *  `invalid`, `not_yet_effective` or something else. This module does not settle it by
   *  default: the default keeps the chain verifier's own answer, and
   *  `notYetValidAsNotYetEffective: true` takes the other reading. */
  readonly mapping?: LifecycleMappingOptions
}

/**
 * Report an activation result ALONGSIDE a chain result, never merged into it.
 *
 * Two stages, in order, and the order is the point:
 *
 *   1. Chain verification decides whether the grant is valid at the action instant. Its
 *      four-value result is returned untouched in `chain`.
 *   2. Activation is asked ONLY when the chain is valid. A grant that does not verify is not a
 *      grant that is waiting on a condition, and reporting `not_yet_effective` for a revoked
 *      or unparented grant would say the remedy is to wait when it is not.
 *
 * This is also where CAND-13's activation half lands. A pre-committed replacement grant is an
 * ordinary grant with an ordinary condition, so it needs no separate machinery here, and the
 * ordering is what keeps L1 intact: if the pre-committing instrument is revoked, the
 * replacement's chain is invalid and no activation evidence can make it exercisable. Nothing
 * in this module can turn an invalid chain into a `valid` lifecycle verdict.
 *
 * `activation` may be `null`, which is how a caller says no activation module ran. The
 * composite then carries only the chain's own reading.
 *
 * Proposed. Concept source: aeoess/agent-authority-lifecycle, invariant L1 and invariant
 * candidates CAND-04 and CAND-13.
 */
export function composeActivation(
  chain: AuthorityValidationResult,
  activation: ActivationResult | null,
  options: ActivationCompositionOptions = {},
): CompositeAuthorityResult<AuthorityValidationResult> {
  const mapped = mapAuthorityValidationToLifecycle(chain, options.mapping ?? {})
  if (chain.state !== 'valid' || activation === null) {
    return Object.freeze({ chain, lifecycle: mapped })
  }
  return Object.freeze({ chain, lifecycle: activation.state })
}
