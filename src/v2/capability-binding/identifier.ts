// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. The identity limb of CAND-07: whether an authority path that depends on
// an identifier nobody in the delegation graph controls still depends on the same party.
//
// SPECIFICATION POSITION. Not required by draft-pidlisnyi-aps-03, which states no rule about
// an off-chain identifier a grant depends on. Concept source:
// aeoess/agent-authority-lifecycle, invariant candidate CAND-07 v2 ("A verifier must not
// treat an unchanged name as evidence of an unchanged controller, an unchanged
// implementation or an unchanged schema") and the AUTHORITY-LIFECYCLE.md concepts "Target
// binding", "Authority path and dependency", "Issuer standing" and "Coverage and
// completeness". All PROPOSED.
//
// THE THING THIS CATCHES. A mail domain, a package namespace or a phone number that an
// account-recovery path depends on. The string in the grant never changes. The party holding
// it does, by lapse and re-registration, by a vacated name being claimed, or by routine
// reassignment. A boundary whose whole check is that the string still matches admits every
// one of those.
//
// WHAT RUNS WHERE. Chain verification stays with the caller and is unchanged. An identifier
// changing hands is not a revocation, so the two checks are separate: run
// `verifyAuthorityDelegationChain` first, and if it does not return `valid` there is no
// identifier question to ask. This module reads no clock and no network. It does verify
// Ed25519 signatures over custodian records, which is why it is not pure in the way
// `evaluateCapabilityBinding` is; standing is still resolved entirely outside the records,
// through two caller-supplied resolvers.

import { verify as verifyEd25519 } from '../../crypto/keys.js'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import {
  CapabilityBindingError,
  referentBindingResult,
  type IdentifierContinuityResult,
} from './types.js'

/** A custodian's signed statement that one party held one identifier over one interval.
 *
 *  The interval is half-open, `[bound_from, bound_until)`, and a `null` `bound_until` is
 *  open-ended. Extra members are allowed and ARE part of the signed body: a record carrying
 *  a `record_type` or a `nonce` signs over them too. */
export interface IdentifierBindingRecord {
  readonly identifier_kind: string
  readonly identifier: string
  readonly controller: string
  readonly bound_from: string
  readonly bound_until: string | null
  readonly custodian: string
  readonly signature: string
  readonly [key: string]: unknown
}

/** A custodian's signed statement that an identifier was RETAINED over an interval, meaning
 *  it was not available to anyone else even though no binding covered it.
 *
 *  This is what closes a gap. An interval the identifier was held by nobody is an interval
 *  anyone could have taken it, and the holder being the pinned holder today says nothing
 *  about what happened in between. The interval is half-open, `[retained_from,
 *  retained_until)`. */
export interface IdentifierRetentionRecord {
  readonly identifier_kind: string
  readonly identifier: string
  readonly retained_from: string
  readonly retained_until: string
  readonly custodian: string
  readonly signature: string
  readonly [key: string]: unknown
}

/** Members dropped from a binding record before canonicalizing its signed body. The record
 *  id is a digest OF the body and the signature is OVER the body, so neither can be inside
 *  it. */
export const IDENTIFIER_BINDING_UNSIGNED_FIELDS = ['binding_id', 'signature'] as const

/** Members dropped from a retention record before canonicalizing its signed body. */
export const IDENTIFIER_RETENTION_UNSIGNED_FIELDS = ['retention_id', 'signature'] as const

/** The exact bytes a custodian signature is taken over: RFC 8785 JCS over the record with
 *  `unsignedFields` removed.
 *
 *  JCS, not the SDK's legacy `canonicalize`. The two are NOT interchangeable here, because a
 *  binding record's `bound_until` is meaningfully `null` for an open-ended interval and the
 *  legacy form strips null members, which would make an open-ended binding and a binding
 *  with no end field sign to the same bytes. */
export function identifierRecordSignedBytes(
  record: Readonly<Record<string, unknown>>,
  unsignedFields: readonly string[],
): string {
  if (record === null || typeof record !== 'object') {
    throw new CapabilityBindingError('RECORD_INVALID', 'record must be an object')
  }
  const body: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) {
    if (unsignedFields.includes(key)) continue
    body[key] = value
  }
  return canonicalizeJCS(body)
}

/** The dependency scope grant, `extid:<kind>:<identifier>`. Says the grant's recovery or
 *  verification path depends on this identifier at all. */
export function identifierDependencyScopeGrant(kind: string, identifier: string): string {
  assertSegment('kind', kind)
  assertSegment('identifier', identifier)
  return `extid:${kind}:${identifier}`
}

/** The controller-pin scope grant, `extid:<kind>:<identifier>:controller:<did>`. Says which
 *  party the grant was written against. */
export function identifierControllerPinScopeGrant(
  kind: string,
  identifier: string,
  controller: string,
): string {
  assertSegment('controller', controller)
  return `${identifierDependencyScopeGrant(kind, identifier)}:controller:${controller}`
}

/** Read the controller pins a grant's scope carries for one identifier. Empty means the
 *  grant names the identifier and says nothing about who holds it. */
export function parseIdentifierControllerPins(
  grants: readonly string[],
  kind: string,
  identifier: string,
): readonly string[] {
  if (!Array.isArray(grants)) {
    throw new CapabilityBindingError('GRANTS_INVALID', 'grants must be an array of strings')
  }
  const prefix = `${identifierDependencyScopeGrant(kind, identifier)}:controller:`
  const seen = new Set<string>()
  for (const grant of grants) {
    if (typeof grant !== 'string' || !grant.startsWith(prefix)) continue
    const value = grant.slice(prefix.length)
    if (value.length > 0) seen.add(value)
  }
  return Object.freeze([...seen])
}

function assertSegment(label: string, value: string): void {
  if (typeof value !== 'string' || value.length === 0) {
    throw new CapabilityBindingError('SEGMENT_INVALID', `${label} must be a non-empty string`)
  }
}

interface Interval {
  from: string
  until: string | null
}

/** Half-open [from, until). A null `until` is open-ended. */
function covers(from: string, until: string | null, instant: string): boolean {
  if (instant < from) return false
  if (until === null) return true
  return instant < until
}

/** Subtract a covered interval from a list of gaps, half-open throughout. */
function subtract(gaps: readonly Interval[], from: string, until: string): Interval[] {
  const out: Interval[] = []
  for (const gap of gaps) {
    const gapUntil = gap.until
    if (gapUntil !== null && from >= gapUntil) {
      out.push(gap)
      continue
    }
    if (until <= gap.from) {
      out.push(gap)
      continue
    }
    if (from > gap.from) out.push({ from: gap.from, until: from })
    if (gapUntil === null || until < gapUntil) out.push({ from: until, until: gapUntil })
  }
  return out
}

export interface IdentifierContinuityInput {
  /** What kind of identifier this is, for example `mail-domain`. Standing is resolved per
   *  kind, because the party with standing to say who holds a mail domain is not the party
   *  with standing to say who holds a phone number. */
  readonly identifierKind: string
  /** The identifier the action IN FACT relies on, whether or not the grant declares it. */
  readonly identifier: string
  /** Every scope grant the presented delegation carries. */
  readonly grantedScopes: readonly string[]
  /** `issued_at` of the presented delegation. Continuity is measured from here, not from an
   *  arbitrary earlier point: what matters is whether the identifier was continuously the
   *  pinned party's since the grant was written. */
  readonly grantIssuedAt: string
  /** The instant asked about, as an RFC 3339 string. Supplied, never read from a clock. */
  readonly at: string
  readonly bindings: readonly IdentifierBindingRecord[]
  readonly retentions: readonly IdentifierRetentionRecord[]
  /** Which custodian this caller resolves for an identifier kind. Returning `null` means the
   *  caller resolves none, and then no record of that kind is acceptable. Resolution is by
   *  KIND and never from the `custodian` member the record asserts about itself: a valid
   *  signature establishes who signed, not that they had standing. */
  readonly resolveCustodianStanding: (identifierKind: string) => string | null | undefined
  /** The Ed25519 public key for a custodian identifier. */
  readonly resolveCustodianKey: (custodian: string) => string | null | undefined
}

/** Decide whether the identifier this authority path depends on is still held by the party
 *  the grant pinned, and whether it has been continuously so since issuance.
 *
 *  Four ordered steps:
 *
 *  1. Is the dependency declared in the grant at all. A verifier that never modelled the
 *     identifier has no record to invalidate when control of it moves, so an undeclared
 *     dependency is `not_established` on the coverage limb rather than a silent admit.
 *  2. Does the grant pin who controls it. An unpinned dependency is CAND-07 v2's unpinned
 *     limb again: the grant names a string and says nothing about who holds it.
 *  3. Who holds it at `at`, according to records from a custodian this caller resolves for
 *     that kind. No accepted record covering the instant is a lapse. Two accepted records
 *     naming different holders is an unresolved conflict between accepted sources, and the
 *     holder is reported as `null` rather than guessed.
 *  4. Continuity since issuance. Every interval from `grantIssuedAt` to `at` must be either
 *     bound to the established holder or covered by an accepted retention record. A
 *     retention record that exists but comes from a party without standing is named
 *     separately from there being no retention record at all, because the two call for
 *     different fixes.
 *
 *  Never returns an artifact verdict and never makes any delegation invalid. PROPOSED. */
export function evaluateIdentifierContinuity(
  input: IdentifierContinuityInput,
): IdentifierContinuityResult {
  if (input === null || typeof input !== 'object') {
    throw new CapabilityBindingError(
      'INPUT_INVALID',
      'evaluateIdentifierContinuity requires an input object',
    )
  }
  const { identifierKind, identifier, at, grantIssuedAt } = input
  assertSegment('identifierKind', identifierKind)
  assertSegment('identifier', identifier)
  assertSegment('at', at)
  assertSegment('grantIssuedAt', grantIssuedAt)
  if (!Array.isArray(input.grantedScopes)) {
    throw new CapabilityBindingError('GRANTS_INVALID', 'grantedScopes must be an array of strings')
  }
  if (!Array.isArray(input.bindings) || !Array.isArray(input.retentions)) {
    throw new CapabilityBindingError('RECORDS_INVALID', 'bindings and retentions must be arrays')
  }
  if (
    typeof input.resolveCustodianStanding !== 'function' ||
    typeof input.resolveCustodianKey !== 'function'
  ) {
    throw new CapabilityBindingError(
      'RESOLVER_INVALID',
      'resolveCustodianStanding and resolveCustodianKey must be functions',
    )
  }

  const withController = (
    result: ReturnType<typeof referentBindingResult>,
    controller: string | null,
  ): IdentifierContinuityResult => Object.freeze({ ...result, controller_at_instant: controller })

  const dependency = identifierDependencyScopeGrant(identifierKind, identifier)

  // Step 1.
  if (!input.grantedScopes.includes(dependency)) {
    return withController(
      referentBindingResult({
        outcome: 'not_established',
        continuity: 'not_established',
        reason_code: 'IDENTIFIER_DEPENDENCY_NOT_DECLARED',
        missing: ['coverage'],
        detail: dependency,
      }),
      null,
    )
  }

  // Step 2.
  const pins = parseIdentifierControllerPins(input.grantedScopes, identifierKind, identifier)
  if (pins.length === 0) {
    return withController(
      referentBindingResult({
        outcome: 'not_established',
        continuity: 'not_established',
        reason_code: 'IDENTIFIER_CONTROLLER_NOT_PINNED',
        missing: ['coverage'],
        detail: dependency,
      }),
      null,
    )
  }

  const acceptable = <T extends { identifier_kind: string; custodian: string; signature: string }>(
    records: readonly T[],
    unsignedFields: readonly string[],
  ): T[] =>
    records.filter(record => {
      const key = input.resolveCustodianKey(record.custodian)
      if (key === null || key === undefined || key.length === 0) return false
      if (!verifyEd25519(identifierRecordSignedBytes(record, unsignedFields), record.signature, key)) {
        return false
      }
      const standing = input.resolveCustodianStanding(record.identifier_kind)
      return standing !== null && standing !== undefined && standing === record.custodian
    })

  const relevant = acceptable(input.bindings, IDENTIFIER_BINDING_UNSIGNED_FIELDS).filter(
    b => b.identifier_kind === identifierKind && b.identifier === identifier,
  )

  // Step 3.
  const atInstant = relevant.filter(b => covers(b.bound_from, b.bound_until, at))
  const holders = [...new Set(atInstant.map(b => b.controller))].sort()
  if (holders.length === 0) {
    return withController(
      referentBindingResult({
        outcome: 'not_established',
        continuity: 'not_established',
        reason_code: 'IDENTIFIER_BINDING_LAPSED',
        missing: ['coverage'],
        detail: `no_binding_covers=${at}`,
      }),
      null,
    )
  }
  if (holders.length > 1) {
    return withController(
      referentBindingResult({
        outcome: 'not_established',
        continuity: 'not_established',
        reason_code: 'IDENTIFIER_BINDING_CONFLICT',
        missing: ['source'],
        detail: `holders=${holders.join('|')}`,
      }),
      null,
    )
  }
  const holder = holders[0] as string
  if (!pins.includes(holder)) {
    // ESTABLISHED NEGATIVE. The string is the same. The party behind it is not, and the
    // verifier established that from accepted records. CAND-07 v2: a denial with a mismatch
    // reason, not ignorance. `controller_at_instant` names who holds it now.
    return withController(
      referentBindingResult({
        outcome: 'denied',
        continuity: 'mismatch',
        reason_code: 'IDENTIFIER_CONTROLLER_CHANGED',
        detail: `pinned=${pins.join('|')} holder=${holder}`,
      }),
      holder,
    )
  }

  // Step 4.
  let gaps: Interval[] = [{ from: grantIssuedAt, until: at }]
  for (const binding of relevant) {
    if (binding.controller !== holder) continue
    gaps = subtract(gaps, binding.bound_from, binding.bound_until ?? at)
  }
  if (gaps.length === 0) {
    return withController(
      referentBindingResult({
        outcome: 'authorized',
        continuity: 'established',
        reason_code: 'IDENTIFIER_CONTINUITY_ESTABLISHED',
        detail: 'continuously_bound',
      }),
      holder,
    )
  }

  const acceptableRetentions = acceptable(
    input.retentions,
    IDENTIFIER_RETENTION_UNSIGNED_FIELDS,
  ).filter(r => r.identifier_kind === identifierKind && r.identifier === identifier)
  let uncovered: readonly Interval[] = gaps
  for (const retention of acceptableRetentions) {
    uncovered = subtract(uncovered, retention.retained_from, retention.retained_until)
  }
  if (uncovered.length === 0) {
    return withController(
      referentBindingResult({
        outcome: 'authorized',
        continuity: 'established',
        reason_code: 'IDENTIFIER_CONTINUITY_ESTABLISHED',
        detail: `retained_gap=${gaps.map(g => `${g.from}..${g.until ?? 'open'}`).join(',')}`,
      }),
      holder,
    )
  }

  // A retention record that exists but does not count is worth naming apart from there being
  // no retention record at all: the first is a standing problem and the second is a missing
  // record, and they call for different fixes.
  const presentButUnacceptable = input.retentions.filter(
    r =>
      r.identifier_kind === identifierKind &&
      r.identifier === identifier &&
      !acceptableRetentions.includes(r),
  )
  let wouldBeCovered: readonly Interval[] = uncovered
  for (const retention of presentButUnacceptable) {
    wouldBeCovered = subtract(wouldBeCovered, retention.retained_from, retention.retained_until)
  }
  if (wouldBeCovered.length === 0) {
    return withController(
      referentBindingResult({
        outcome: 'not_established',
        continuity: 'not_established',
        reason_code: 'RETENTION_CUSTODIAN_WITHOUT_STANDING',
        missing: ['source'],
        detail: [...new Set(presentButUnacceptable.map(r => r.custodian))].sort().join('|'),
      }),
      holder,
    )
  }
  return withController(
    referentBindingResult({
      outcome: 'not_established',
      continuity: 'not_established',
      reason_code: 'IDENTIFIER_CONTINUITY_GAP_UNCOVERED',
      missing: ['coverage'],
      detail: uncovered.map(g => `${g.from}..${g.until ?? 'open'}`).join(','),
    }),
    holder,
  )
}
