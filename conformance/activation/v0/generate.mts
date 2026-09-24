// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generator for the PROPOSED activation-condition v0 conformance vectors.
//
// Produces conformance/activation/v0/vectors.json: activation conditions, signed
// activation attestations, an attestor-role registry, and HAND-SPECIFIED expectations.
// Every expectation below is written as a literal in this file. Nothing in the emitted
// vectors is computed by `verifyActivation`, `validateActivationCondition` or
// `composeActivation`, so running the vectors in either SDK is a real check rather than a
// tautology.
//
// Run: cd <repo> && npx tsx conformance/activation/v0/generate.mts
//
// Keys are DETERMINISTIC, derived from published seed labels, so a regeneration reproduces
// the committed artifact byte for byte and the Python SDK's vendored copy can be shown
// identical to it:
//
//     private key = SHA-256("aps-conformance:activation-v0:" + label)
//
// No secret material is introduced: every private key regenerates from a label that is
// printed in the emitted file under `seed_labels`.
//
// Status: PROPOSED and OPT-IN. Not required by draft-pidlisnyi-aps-03. Concept source: the
// aeoess/agent-authority-lifecycle concept document, invariant candidates CAND-04, CAND-13
// (activation half) and BROAD-L7, all proposed.
import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { publicKeyFromPrivate, sign } from '../../../src/crypto/keys.js'
import {
  ACTIVATION_ASSERTIONS,
  ACTIVATION_ATTESTATION_TYPE,
  ACTIVATION_CONDITION_KINDS,
  ACTIVATION_CONDITION_TYPE,
  ACTIVATION_FINDINGS,
  ACTIVATION_INSTANT_BASES,
  ACTIVATION_REASON_CODES,
  ATTESTOR_ROLE_STANDINGS,
  activationAttestationSignatureInput,
  computeActivationAttestationId,
} from '../../../src/v2/activation/index.js'

const SEED_PREFIX = 'aps-conformance:activation-v0:'

function privateKeyFor(label: string): string {
  return createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')
}

// ── identities ──────────────────────────────────────────────────────────────────────────
const IDS = {
  monitorA: 'did:aps:example:acv-monitor-a',
  monitorC: 'did:aps:example:acv-monitor-c',
  auditorB: 'did:aps:example:acv-auditor-b',
  stranger: 'did:aps:example:acv-stranger',
} as const

const SEED_LABELS: Record<string, string> = {
  [`${IDS.monitorA}#key-1`]: 'monitor-a-key-1',
  [`${IDS.monitorC}#key-1`]: 'monitor-c-key-1',
  [`${IDS.auditorB}#key-1`]: 'auditor-b-key-1',
  [`${IDS.stranger}#key-1`]: 'stranger-key-1',
}

const privateKeys: Record<string, string> = {}
const verificationKeys: Record<string, string> = {}
for (const [method, label] of Object.entries(SEED_LABELS)) {
  privateKeys[method] = privateKeyFor(label)
  verificationKeys[method] = publicKeyFromPrivate(privateKeys[method])
}

/** Roles held, resolved OUTSIDE any attestation. An attestor absent from this map is
 *  `unknown` for every role, which is ignorance and deliberately not `does_not_hold`. */
const ROLE_REGISTRY: Record<string, string[]> = {
  [IDS.monitorA]: ['outage-monitor'],
  [IDS.monitorC]: ['outage-monitor'],
  [IDS.auditorB]: ['billing-auditor'],
}

// ── clock ───────────────────────────────────────────────────────────────────────────────
const CLOCK = {
  T_STALE_THROUGH: '2026-09-20T08:30:00.000Z',
  T_EVENT: '2026-09-20T09:00:00.000Z',
  T_ATTESTED: '2026-09-20T09:05:00.000Z',
  T_ACTION: '2026-09-20T10:00:00.000Z',
  T_LATE_EVENT: '2026-09-20T10:30:00.000Z',
  T_LATE_ATTESTED: '2026-09-20T11:00:00.000Z',
  T_ACTIVATION_DATE: '2026-09-20T11:30:00.000Z',
  T_LATER_ACTION: '2026-09-20T12:00:00.000Z',
} as const

const DELEGATION_ID = 'acv-grant-1'
const EVENT_TYPE = 'service_outage_declared'
const EVENT_ID = 'acv-outage-2026-09-20'

// ── conditions ──────────────────────────────────────────────────────────────────────────
const eventCondition = (over: Record<string, unknown> = {}) => ({
  record_type: ACTIVATION_CONDITION_TYPE,
  condition_id: 'acv-cond-outage-1',
  delegation_id: DELEGATION_ID,
  condition_type: 'recorded_event',
  event_type: EVENT_TYPE,
  event_id: EVENT_ID,
  required_attestor_roles: ['outage-monitor'],
  threshold: 1,
  instant_basis: 'condition_occurrence',
  ...over,
})

const CONDITIONS: Record<string, Record<string, unknown>> = {
  COND_EVENT: eventCondition(),
  // The recorded-event variants below are the SAME condition read under a different model
  // decision, so they keep its identifier and the minted attestations bind to them all.
  // Each case presents exactly one of them.
  COND_EVENT_WRITTEN: eventCondition({ instant_basis: 'attestation_written' }),
  COND_EVENT_T2: eventCondition({ threshold: 2 }),
  COND_EVENT_TWO_ROLES: eventCondition({
    required_attestor_roles: ['outage-monitor', 'billing-auditor'],
  }),
  COND_EVENT_OTHER_GRANT: eventCondition({ delegation_id: 'acv-grant-other' }),
  COND_DATE: {
    record_type: ACTIVATION_CONDITION_TYPE,
    condition_id: 'acv-cond-date-1',
    delegation_id: DELEGATION_ID,
    condition_type: 'date',
    activation_date: CLOCK.T_ACTIVATION_DATE,
  },
}

// ── attestations ────────────────────────────────────────────────────────────────────────
// `attestation_id` is recomputed from the body and `signature` covers the same bytes, so
// neither is part of the body either one is derived from.
function mint(
  label: string,
  method: string,
  body: Record<string, unknown>,
  tamperSignature = false,
): Record<string, unknown> {
  const withId = { ...body, attestation_id: computeActivationAttestationId(body as never) }
  const signature = sign(
    activationAttestationSignatureInput(body as never),
    privateKeys[method],
  )
  const flipped = signature.startsWith('0')
    ? `1${signature.slice(1)}`
    : `0${signature.slice(1)}`
  const record = { ...withId, signature: tamperSignature ? flipped : signature }
  if (Object.keys(record).length < 8) throw new Error(`mint ${label}: body too small`)
  return record
}

const occurredBase = {
  record_type: ACTIVATION_ATTESTATION_TYPE,
  assertion: 'condition_occurred',
  condition_id: 'acv-cond-outage-1',
  event_type: EVENT_TYPE,
  event_id: EVENT_ID,
}

const ATTESTATIONS: Record<string, Record<string, unknown>> = {
  // Accepted, occurrence at or before the action instant.
  ATT_OCCURRED_ON_TIME: mint('ATT_OCCURRED_ON_TIME', `${IDS.monitorA}#key-1`, {
    ...occurredBase,
    attestor: IDS.monitorA,
    attestor_role: 'outage-monitor',
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.monitorA}#key-1`,
  }),
  // Occurrence before the action, WRITTEN after it. The instant_basis pair.
  ATT_OCCURRED_ATTESTED_LATE: mint('ATT_OCCURRED_ATTESTED_LATE', `${IDS.monitorA}#key-1`, {
    ...occurredBase,
    attestor: IDS.monitorA,
    attestor_role: 'outage-monitor',
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_LATE_ATTESTED,
    verification_method: `${IDS.monitorA}#key-1`,
  }),
  // Occurrence after the action instant. No retroactive activation.
  ATT_OCCURRED_AFTER_ACTION: mint('ATT_OCCURRED_AFTER_ACTION', `${IDS.monitorA}#key-1`, {
    ...occurredBase,
    attestor: IDS.monitorA,
    attestor_role: 'outage-monitor',
    occurred_at: CLOCK.T_LATE_EVENT,
    attested_at: CLOCK.T_LATE_ATTESTED,
    verification_method: `${IDS.monitorA}#key-1`,
  }),
  // No role claim at all. Not a rejection reason: the required-role check still runs.
  ATT_OCCURRED_NO_ROLE_CLAIM: mint('ATT_OCCURRED_NO_ROLE_CLAIM', `${IDS.monitorA}#key-1`, {
    ...occurredBase,
    attestor: IDS.monitorA,
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.monitorA}#key-1`,
  }),
  // A second holder of the required role, for the threshold cases.
  ATT_MONITOR_C_OCCURRED: mint('ATT_MONITOR_C_OCCURRED', `${IDS.monitorC}#key-1`, {
    ...occurredBase,
    attestor: IDS.monitorC,
    attestor_role: 'outage-monitor',
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.monitorC}#key-1`,
  }),
  // Honest about a role it really holds, which is not a role this condition accepts.
  ATT_AUDITOR_HONEST_ROLE: mint('ATT_AUDITOR_HONEST_ROLE', `${IDS.auditorB}#key-1`, {
    ...occurredBase,
    attestor: IDS.auditorB,
    attestor_role: 'billing-auditor',
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.auditorB}#key-1`,
  }),
  // Claims a role the registry says it does not hold. The self-declared-role control.
  ATT_AUDITOR_CLAIMS_MONITOR: mint('ATT_AUDITOR_CLAIMS_MONITOR', `${IDS.auditorB}#key-1`, {
    ...occurredBase,
    attestor: IDS.auditorB,
    attestor_role: 'outage-monitor',
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.auditorB}#key-1`,
  }),
  // Not in the registry at all, and makes no role claim. Ignorance, not a denial.
  ATT_STRANGER_OCCURRED: mint('ATT_STRANGER_OCCURRED', `${IDS.stranger}#key-1`, {
    ...occurredBase,
    attestor: IDS.stranger,
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.stranger}#key-1`,
  }),
  ATT_MONITOR_WRONG_EVENT: mint('ATT_MONITOR_WRONG_EVENT', `${IDS.monitorA}#key-1`, {
    ...occurredBase,
    event_id: 'acv-outage-some-other',
    attestor: IDS.monitorA,
    attestor_role: 'outage-monitor',
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.monitorA}#key-1`,
  }),
  ATT_MONITOR_FORGED: mint(
    'ATT_MONITOR_FORGED',
    `${IDS.monitorA}#key-1`,
    {
      ...occurredBase,
      attestor: IDS.monitorA,
      attestor_role: 'outage-monitor',
      occurred_at: CLOCK.T_EVENT,
      attested_at: CLOCK.T_ATTESTED,
      verification_method: `${IDS.monitorA}#key-1`,
    },
    true,
  ),
  // Signed by the auditor's key while the body names the monitor. The signature verifies
  // and still says nothing about who attested.
  ATT_BINDING_MISMATCH: mint('ATT_BINDING_MISMATCH', `${IDS.auditorB}#key-1`, {
    ...occurredBase,
    attestor: IDS.monitorA,
    attestor_role: 'outage-monitor',
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.auditorB}#key-1`,
  }),
  // A verification method no resolver answers for.
  ATT_UNRESOLVABLE_KEY: mint('ATT_UNRESOLVABLE_KEY', `${IDS.monitorA}#key-1`, {
    ...occurredBase,
    attestor: IDS.monitorA,
    attestor_role: 'outage-monitor',
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.monitorA}#key-9`,
  }),
  // An established NEGATIVE reaching the action instant. Evidence, not an absence of it.
  ATT_NOT_OCCURRED_THROUGH_ACTION: mint(
    'ATT_NOT_OCCURRED_THROUGH_ACTION',
    `${IDS.monitorA}#key-1`,
    {
      record_type: ACTIVATION_ATTESTATION_TYPE,
      assertion: 'condition_not_occurred_through',
      condition_id: 'acv-cond-outage-1',
      event_type: EVENT_TYPE,
      event_id: EVENT_ID,
      attestor: IDS.monitorA,
      attestor_role: 'outage-monitor',
      not_occurred_through: CLOCK.T_ACTION,
      attested_at: CLOCK.T_ATTESTED,
      verification_method: `${IDS.monitorA}#key-1`,
    },
  ),
  // A negative that stops short of the action. The coverage limb.
  ATT_NOT_OCCURRED_STALE: mint('ATT_NOT_OCCURRED_STALE', `${IDS.monitorA}#key-1`, {
    record_type: ACTIVATION_ATTESTATION_TYPE,
    assertion: 'condition_not_occurred_through',
    condition_id: 'acv-cond-outage-1',
    event_type: EVENT_TYPE,
    event_id: EVENT_ID,
    attestor: IDS.monitorA,
    attestor_role: 'outage-monitor',
    not_occurred_through: CLOCK.T_STALE_THROUGH,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.monitorA}#key-1`,
  }),
  ATT_AUDITOR_NOT_OCCURRED: mint('ATT_AUDITOR_NOT_OCCURRED', `${IDS.auditorB}#key-1`, {
    record_type: ACTIVATION_ATTESTATION_TYPE,
    assertion: 'condition_not_occurred_through',
    condition_id: 'acv-cond-outage-1',
    event_type: EVENT_TYPE,
    event_id: EVENT_ID,
    attestor: IDS.auditorB,
    attestor_role: 'billing-auditor',
    not_occurred_through: CLOCK.T_ACTION,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.auditorB}#key-1`,
  }),
  ATT_UNKNOWN_ASSERTION: mint('ATT_UNKNOWN_ASSERTION', `${IDS.monitorA}#key-1`, {
    record_type: ACTIVATION_ATTESTATION_TYPE,
    assertion: 'condition_probably_occurred',
    condition_id: 'acv-cond-outage-1',
    event_type: EVENT_TYPE,
    event_id: EVENT_ID,
    attestor: IDS.monitorA,
    attestor_role: 'outage-monitor',
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.monitorA}#key-1`,
  }),
  // `condition_occurred` with no `occurred_at`: the assertion's own member is absent.
  ATT_OCCURRED_NO_INSTANT: mint('ATT_OCCURRED_NO_INSTANT', `${IDS.monitorA}#key-1`, {
    ...occurredBase,
    attestor: IDS.monitorA,
    attestor_role: 'outage-monitor',
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.monitorA}#key-1`,
  }),
  ATT_OCCURRED_MALFORMED_INSTANT: mint(
    'ATT_OCCURRED_MALFORMED_INSTANT',
    `${IDS.monitorA}#key-1`,
    {
      ...occurredBase,
      attestor: IDS.monitorA,
      attestor_role: 'outage-monitor',
      occurred_at: '2026-09-20 09:00:00',
      attested_at: CLOCK.T_ATTESTED,
      verification_method: `${IDS.monitorA}#key-1`,
    },
  ),
  ATT_WRONG_RECORD_TYPE: mint('ATT_WRONG_RECORD_TYPE', `${IDS.monitorA}#key-1`, {
    ...occurredBase,
    record_type: 'fixture:some-other-attestation:v0',
    attestor: IDS.monitorA,
    attestor_role: 'outage-monitor',
    occurred_at: CLOCK.T_EVENT,
    attested_at: CLOCK.T_ATTESTED,
    verification_method: `${IDS.monitorA}#key-1`,
  }),
}

// ── HAND-SPECIFIED expectations ─────────────────────────────────────────────────────────
// `validateActivationCondition` throws on a shape rule, because a condition that breaks one
// is a programming error at the caller and not a verdict about evidence.
const conditionCases = [
  {
    id: 'AC-CV-01-date-condition-accepted',
    tests: 'A well formed date condition validates.',
    condition: CONDITIONS.COND_DATE,
    expected: { ok: true },
  },
  {
    id: 'AC-CV-02-event-condition-accepted',
    tests: 'A well formed recorded-event condition validates.',
    condition: CONDITIONS.COND_EVENT,
    expected: { ok: true },
  },
  {
    id: 'AC-CV-03-foreign-record-type-rejected',
    tests: 'A record type this module does not own is not an activation condition.',
    condition: { ...CONDITIONS.COND_EVENT, record_type: 'proposed:aps:something-else:v0' },
    expected: { ok: false, error_code: 'CONDITION_RECORD_TYPE_UNKNOWN' },
  },
  {
    id: 'AC-CV-04-empty-condition-id-rejected',
    tests: 'An identifier is required and is never derived by this module.',
    condition: { ...CONDITIONS.COND_EVENT, condition_id: '' },
    expected: { ok: false, error_code: 'CONDITION_MALFORMED' },
  },
  {
    id: 'AC-CV-05-unknown-condition-type-rejected',
    tests: 'Only the two kinds the concept text names are modelled.',
    condition: { ...CONDITIONS.COND_EVENT, condition_type: 'absence_within_window' },
    expected: { ok: false, error_code: 'CONDITION_TYPE_UNKNOWN' },
  },
  {
    id: 'AC-CV-06-no-required-roles-rejected',
    tests:
      'A condition naming no accepted source has not stated what it accepts. Refusing the condition is not the same as accepting anything.',
    condition: { ...CONDITIONS.COND_EVENT, required_attestor_roles: [] },
    expected: { ok: false, error_code: 'CONDITION_ROLES_REQUIRED' },
  },
  {
    id: 'AC-CV-07-threshold-zero-rejected',
    tests: 'How many determinations establish a finding is a model decision, and it is at least one.',
    condition: { ...CONDITIONS.COND_EVENT, threshold: 0 },
    expected: { ok: false, error_code: 'CONDITION_THRESHOLD_INVALID' },
  },
  {
    id: 'AC-CV-08-threshold-absent-rejected',
    tests: 'There is NO DEFAULT threshold. An absent one is refused rather than read as one.',
    condition: (() => {
      const c = { ...CONDITIONS.COND_EVENT } as Record<string, unknown>
      delete c.threshold
      return c
    })(),
    expected: { ok: false, error_code: 'CONDITION_THRESHOLD_INVALID' },
  },
  {
    id: 'AC-CV-09-instant-basis-absent-rejected',
    tests:
      'There is NO DEFAULT instant basis. Which instant an occurrence is measured from changes the verdict, so the condition has to say.',
    condition: (() => {
      const c = { ...CONDITIONS.COND_EVENT } as Record<string, unknown>
      delete c.instant_basis
      return c
    })(),
    expected: { ok: false, error_code: 'CONDITION_INSTANT_BASIS_REQUIRED' },
  },
  {
    id: 'AC-CV-10-instant-basis-unknown-rejected',
    tests: 'An instant basis outside the two named values is refused.',
    condition: { ...CONDITIONS.COND_EVENT, instant_basis: 'whenever' },
    expected: { ok: false, error_code: 'CONDITION_INSTANT_BASIS_REQUIRED' },
  },
  {
    id: 'AC-CV-11-malformed-activation-date-rejected',
    tests: 'A date condition carries an RFC 3339 instant with an offset.',
    condition: { ...CONDITIONS.COND_DATE, activation_date: '2026-09-20' },
    expected: { ok: false, error_code: 'INSTANT_MALFORMED' },
  },
  {
    id: 'AC-CV-12-empty-event-type-rejected',
    tests: 'An event type is opaque to this module and still has to be present.',
    condition: { ...CONDITIONS.COND_EVENT, event_type: '' },
    expected: { ok: false, error_code: 'CONDITION_MALFORMED' },
  },
]

const verifyCases = [
  {
    id: 'AC-01-occurrence-before-action-valid',
    tests:
      'An acceptable record from a required source that the condition occurred at or before the action instant establishes activation.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_ON_TIME'],
    expected: {
      verdict: 'valid',
      reason_code: 'ACTIVATION_ESTABLISHED',
      findings: [{ attestation: 'ATT_OCCURRED_ON_TIME', finding: 'occurred_by_action' }],
      rejections: [],
    },
  },
  {
    id: 'AC-02-nothing-presented-not-established',
    tests:
      'Nothing presented is ignorance, so not_established with the source limb missing. It is NEVER not_yet_effective: no record said the condition had not occurred.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: [],
    expected: {
      verdict: 'not_established',
      reason_code: 'NO_ATTESTATION_PRESENTED',
      missing: ['source'],
      findings: [],
      rejections: [],
    },
  },
  {
    id: 'AC-03-honest-wrong-role-not-established',
    tests:
      'A source the model does not accept FOR THIS CONDITION is not evidence in either direction. It cannot establish the condition and it cannot establish that the condition was unmet.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_AUDITOR_HONEST_ROLE'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_ATTESTOR_ROLE_MISMATCH',
      missing: ['source'],
      findings: [],
      rejections: [
        {
          attestation: 'ATT_AUDITOR_HONEST_ROLE',
          reason_code: 'ATTESTATION_ATTESTOR_ROLE_MISMATCH',
        },
      ],
    },
  },
  {
    id: 'AC-04-self-declared-role-not-established',
    tests:
      'THE NEGATIVE CONTROL. A role claim the resolver contradicts is its own rejection reason and is never believed. An implementation reading the role off the record returns valid here.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_AUDITOR_CLAIMS_MONITOR'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_ROLE_CLAIM_CONFLICT',
      missing: ['source'],
      findings: [],
      rejections: [
        { attestation: 'ATT_AUDITOR_CLAIMS_MONITOR', reason_code: 'ATTESTATION_ROLE_CLAIM_CONFLICT' },
      ],
    },
  },
  {
    id: 'AC-05-role-standing-unknown-not-established',
    tests:
      'THREE VALUES, NOT A BOOLEAN. An attestor the registry has never heard of is unknown, which is ignorance and reported under its own code rather than collapsed into a mismatch.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_STRANGER_OCCURRED'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_ATTESTOR_ROLE_UNKNOWN',
      missing: ['source'],
      findings: [],
      rejections: [
        { attestation: 'ATT_STRANGER_OCCURRED', reason_code: 'ATTESTATION_ATTESTOR_ROLE_UNKNOWN' },
      ],
    },
  },
  {
    id: 'AC-06-no-role-claim-is-not-a-rejection',
    tests:
      'An attestation that makes no role claim about itself is not rejected for that. The required-role check still runs and the resolver still answers.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_NO_ROLE_CLAIM'],
    expected: {
      verdict: 'valid',
      reason_code: 'ACTIVATION_ESTABLISHED',
      findings: [{ attestation: 'ATT_OCCURRED_NO_ROLE_CLAIM', finding: 'occurred_by_action' }],
      rejections: [],
    },
  },
  {
    id: 'AC-07-wrong-event-not-established',
    tests: 'A record about another event does not bind to this condition.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_MONITOR_WRONG_EVENT'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_CONDITION_MISMATCH',
      missing: ['source'],
      findings: [],
      rejections: [
        { attestation: 'ATT_MONITOR_WRONG_EVENT', reason_code: 'ATTESTATION_CONDITION_MISMATCH' },
      ],
    },
  },
  {
    id: 'AC-08-forged-signature-not-established',
    tests: 'A signature that does not verify over the record bytes makes the record unusable.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_MONITOR_FORGED'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_SIGNATURE_UNVERIFIED',
      missing: ['source'],
      findings: [],
      rejections: [
        { attestation: 'ATT_MONITOR_FORGED', reason_code: 'ATTESTATION_SIGNATURE_UNVERIFIED' },
      ],
    },
  },
  {
    id: 'AC-09-attestor-binding-mismatch-not-established',
    tests:
      'The signature verifies and the verification method belongs to somebody else, so it says nothing about who attested. Its own code, not a signature failure.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_BINDING_MISMATCH'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_ATTESTOR_BINDING_MISMATCH',
      missing: ['source'],
      findings: [],
      rejections: [
        {
          attestation: 'ATT_BINDING_MISMATCH',
          reason_code: 'ATTESTATION_ATTESTOR_BINDING_MISMATCH',
        },
      ],
    },
  },
  {
    id: 'AC-10-unresolvable-key-not-established',
    tests: 'No key resolved at the record own attested_at, so the record is not usable evidence.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_UNRESOLVABLE_KEY'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_SIGNATURE_UNVERIFIED',
      missing: ['source'],
      findings: [],
      rejections: [
        { attestation: 'ATT_UNRESOLVABLE_KEY', reason_code: 'ATTESTATION_SIGNATURE_UNVERIFIED' },
      ],
    },
  },
  {
    id: 'AC-11-occurrence-after-action-not-yet-effective',
    tests:
      'NO RETROACTIVE ACTIVATION. A record putting the first occurrence after the action instant leaves that action not_yet_effective, which is an established negative and not ignorance.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_AFTER_ACTION'],
    expected: {
      verdict: 'not_yet_effective',
      reason_code: 'CONDITION_FIRST_OCCURRED_AFTER_ACTION',
      findings: [{ attestation: 'ATT_OCCURRED_AFTER_ACTION', finding: 'occurred_after_action' }],
      rejections: [],
    },
  },
  {
    id: 'AC-12-same-record-later-action-valid',
    tests:
      'The SAME record establishes the condition for any later action. That is what makes AC-11 a wait rather than a failure.',
    condition: 'COND_EVENT',
    action_at: 'T_LATER_ACTION',
    presented: ['ATT_OCCURRED_AFTER_ACTION'],
    expected: {
      verdict: 'valid',
      reason_code: 'ACTIVATION_ESTABLISHED',
      findings: [{ attestation: 'ATT_OCCURRED_AFTER_ACTION', finding: 'occurred_by_action' }],
      rejections: [],
    },
  },
  {
    id: 'AC-13-written-after-action-about-earlier-occurrence-valid',
    tests:
      'Under instant_basis condition_occurrence, learning on Thursday that a condition was met on Monday establishes it. The activation is keyed on the condition instant, never on the instant someone wrote the record down.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_ATTESTED_LATE'],
    expected: {
      verdict: 'valid',
      reason_code: 'ACTIVATION_ESTABLISHED',
      findings: [{ attestation: 'ATT_OCCURRED_ATTESTED_LATE', finding: 'occurred_by_action' }],
      rejections: [],
    },
  },
  {
    id: 'AC-14-attestation-written-basis-flips-the-same-record',
    tests:
      'THE PAIR THAT PROVES THE NO-DEFAULT RULE. The identical record, at the identical action instant, under instant_basis attestation_written, is not_yet_effective. Two defensible readings, opposite verdicts, so the condition states which governs and this module defaults to neither.',
    condition: 'COND_EVENT_WRITTEN',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_ATTESTED_LATE'],
    expected: {
      verdict: 'not_yet_effective',
      reason_code: 'CONDITION_FIRST_OCCURRED_AFTER_ACTION',
      findings: [{ attestation: 'ATT_OCCURRED_ATTESTED_LATE', finding: 'occurred_after_action' }],
      rejections: [],
    },
  },
  {
    id: 'AC-15-accepted-negative-not-yet-effective',
    tests:
      'An accepted record that the condition had NOT occurred through an instant reaching the action is evidence, not an absence of evidence. The verifier reached a conclusion and the remedy is to wait.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_NOT_OCCURRED_THROUGH_ACTION'],
    expected: {
      verdict: 'not_yet_effective',
      reason_code: 'CONDITION_ESTABLISHED_NOT_YET_OCCURRED',
      findings: [
        { attestation: 'ATT_NOT_OCCURRED_THROUGH_ACTION', finding: 'not_occurred_through_action' },
      ],
      rejections: [],
    },
  },
  {
    id: 'AC-16-negative-from-unaccepted-source-not-established',
    tests:
      'The same negative from a source the model does not accept for this condition establishes nothing. This is the pair to AC-15 and the whole content of the not_established split.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_AUDITOR_NOT_OCCURRED'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_ATTESTOR_ROLE_MISMATCH',
      missing: ['source'],
      findings: [],
      rejections: [
        {
          attestation: 'ATT_AUDITOR_NOT_OCCURRED',
          reason_code: 'ATTESTATION_ATTESTOR_ROLE_MISMATCH',
        },
      ],
    },
  },
  {
    id: 'AC-17-negative-stopping-short-is-a-coverage-gap',
    tests:
      'A negative that stops before the action says nothing about the interval between where it stops and the action. COVERAGE, not source: the record is authentic and from an accepted source, and it just does not reach.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_NOT_OCCURRED_STALE'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_DOES_NOT_REACH_ACTION',
      missing: ['coverage'],
      findings: [],
      rejections: [
        { attestation: 'ATT_NOT_OCCURRED_STALE', reason_code: 'ATTESTATION_DOES_NOT_REACH_ACTION' },
      ],
    },
  },
  {
    id: 'AC-18-conflicting-accepted-evidence-not-established',
    tests:
      'Two acceptable records disagreeing about the action instant leaves the verifier unable to tell which holds. Neither defeats the other: preferring the later record, the negative one or a majority would each be a precedence rule the concept text does not state.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_ON_TIME', 'ATT_NOT_OCCURRED_THROUGH_ACTION'],
    expected: {
      verdict: 'not_established',
      reason_code: 'CONDITION_EVIDENCE_CONFLICT',
      missing: ['source'],
      findings: [
        { attestation: 'ATT_OCCURRED_ON_TIME', finding: 'occurred_by_action' },
        { attestation: 'ATT_NOT_OCCURRED_THROUGH_ACTION', finding: 'not_occurred_through_action' },
      ],
      rejections: [],
    },
  },
  {
    id: 'AC-19-conflict-is-order-independent',
    tests: 'The same two records in the other order give the same answer.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_NOT_OCCURRED_THROUGH_ACTION', 'ATT_OCCURRED_ON_TIME'],
    expected: {
      verdict: 'not_established',
      reason_code: 'CONDITION_EVIDENCE_CONFLICT',
      missing: ['source'],
      findings: [
        { attestation: 'ATT_NOT_OCCURRED_THROUGH_ACTION', finding: 'not_occurred_through_action' },
        { attestation: 'ATT_OCCURRED_ON_TIME', finding: 'occurred_by_action' },
      ],
      rejections: [],
    },
  },
  {
    id: 'AC-20-acceptable-record-alongside-unacceptable-ones-valid',
    tests:
      'Rejected records are not evidence in either direction, so they neither block nor dilute an acceptable one. The rejections are still reported.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_AUDITOR_HONEST_ROLE', 'ATT_AUDITOR_CLAIMS_MONITOR', 'ATT_OCCURRED_ON_TIME'],
    expected: {
      verdict: 'valid',
      reason_code: 'ACTIVATION_ESTABLISHED',
      findings: [{ attestation: 'ATT_OCCURRED_ON_TIME', finding: 'occurred_by_action' }],
      rejections: [
        {
          attestation: 'ATT_AUDITOR_HONEST_ROLE',
          reason_code: 'ATTESTATION_ATTESTOR_ROLE_MISMATCH',
        },
        { attestation: 'ATT_AUDITOR_CLAIMS_MONITOR', reason_code: 'ATTESTATION_ROLE_CLAIM_CONFLICT' },
      ],
    },
  },
  {
    id: 'AC-21-threshold-not-met-not-established',
    tests:
      'One acceptable record under a threshold of two. Accepted evidence exists and there is not enough of it, which is its own code and not the same as nothing presented.',
    condition: 'COND_EVENT_T2',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_ON_TIME'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ACTIVATION_THRESHOLD_NOT_MET',
      missing: ['source'],
      findings: [{ attestation: 'ATT_OCCURRED_ON_TIME', finding: 'occurred_by_action' }],
      rejections: [],
    },
  },
  {
    id: 'AC-22-threshold-met-valid',
    tests: 'Two acceptable records from two holders of the required role meet a threshold of two.',
    condition: 'COND_EVENT_T2',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_ON_TIME', 'ATT_MONITOR_C_OCCURRED'],
    expected: {
      verdict: 'valid',
      reason_code: 'ACTIVATION_ESTABLISHED',
      findings: [
        { attestation: 'ATT_OCCURRED_ON_TIME', finding: 'occurred_by_action' },
        { attestation: 'ATT_MONITOR_C_OCCURRED', finding: 'occurred_by_action' },
      ],
      rejections: [],
    },
  },
  {
    id: 'AC-23-required-roles-are-a-union-not-a-conjunction',
    tests:
      'A condition naming two roles accepts a record from a holder of EITHER. A model needing every named role to attest needs a rule this module does not express.',
    condition: 'COND_EVENT_TWO_ROLES',
    action_at: 'T_ACTION',
    presented: ['ATT_AUDITOR_HONEST_ROLE'],
    expected: {
      verdict: 'valid',
      reason_code: 'ACTIVATION_ESTABLISHED',
      findings: [{ attestation: 'ATT_AUDITOR_HONEST_ROLE', finding: 'occurred_by_action' }],
      rejections: [],
    },
  },
  {
    id: 'AC-24-unknown-assertion-not-established',
    tests: 'An assertion outside the two this module defines establishes nothing.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_UNKNOWN_ASSERTION'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_UNKNOWN_ASSERTION',
      missing: ['source'],
      findings: [],
      rejections: [
        { attestation: 'ATT_UNKNOWN_ASSERTION', reason_code: 'ATTESTATION_UNKNOWN_ASSERTION' },
      ],
    },
  },
  {
    id: 'AC-25-occurred-without-its-instant-not-established',
    tests: 'A condition_occurred record with no occurred_at is missing the member its assertion needs.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_NO_INSTANT'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_UNKNOWN_ASSERTION',
      missing: ['source'],
      findings: [],
      rejections: [
        { attestation: 'ATT_OCCURRED_NO_INSTANT', reason_code: 'ATTESTATION_UNKNOWN_ASSERTION' },
      ],
    },
  },
  {
    id: 'AC-26-malformed-occurrence-instant-not-established',
    tests: 'An instant this module will not compare is a rejection and never a silent comparison.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_MALFORMED_INSTANT'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_INSTANT_MALFORMED',
      missing: ['source'],
      findings: [],
      rejections: [
        {
          attestation: 'ATT_OCCURRED_MALFORMED_INSTANT',
          reason_code: 'ATTESTATION_INSTANT_MALFORMED',
        },
      ],
    },
  },
  {
    id: 'AC-27-foreign-record-type-not-accepted',
    tests:
      'With no attestationPreimage supplied the module accepts only the record type it owns, because the preimage it would verify against belongs to that record type.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_WRONG_RECORD_TYPE'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_RECORD_TYPE_NOT_ACCEPTED',
      missing: ['source'],
      findings: [],
      rejections: [
        {
          attestation: 'ATT_WRONG_RECORD_TYPE',
          reason_code: 'ATTESTATION_RECORD_TYPE_NOT_ACCEPTED',
        },
      ],
    },
  },
  {
    id: 'AC-28-furthest-rejection-is-reported',
    tests:
      'When nothing was accepted the verdict names the reason of the record that got FURTHEST through the checks, so it names the closest thing to usable evidence presented. Reported here as a condition mismatch (rank 7) rather than an unaccepted record type (rank 1).',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_WRONG_RECORD_TYPE', 'ATT_MONITOR_WRONG_EVENT'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_CONDITION_MISMATCH',
      missing: ['source'],
      findings: [],
      rejections: [
        {
          attestation: 'ATT_WRONG_RECORD_TYPE',
          reason_code: 'ATTESTATION_RECORD_TYPE_NOT_ACCEPTED',
        },
        { attestation: 'ATT_MONITOR_WRONG_EVENT', reason_code: 'ATTESTATION_CONDITION_MISMATCH' },
      ],
    },
  },
  {
    id: 'AC-29-furthest-rejection-is-order-independent',
    tests: 'The same two records in the other order report the same verdict code.',
    condition: 'COND_EVENT',
    action_at: 'T_ACTION',
    presented: ['ATT_MONITOR_WRONG_EVENT', 'ATT_WRONG_RECORD_TYPE'],
    expected: {
      verdict: 'not_established',
      reason_code: 'ATTESTATION_CONDITION_MISMATCH',
      missing: ['source'],
      findings: [],
      rejections: [
        { attestation: 'ATT_MONITOR_WRONG_EVENT', reason_code: 'ATTESTATION_CONDITION_MISMATCH' },
        {
          attestation: 'ATT_WRONG_RECORD_TYPE',
          reason_code: 'ATTESTATION_RECORD_TYPE_NOT_ACCEPTED',
        },
      ],
    },
  },
  {
    id: 'AC-30-date-not-reached-not-yet-effective',
    tests:
      'A date condition needs NO EVIDENCE. The verifier reads the date, so an unreached date is always a known negative and never an unknown one.',
    condition: 'COND_DATE',
    action_at: 'T_ACTION',
    presented: [],
    expected: {
      verdict: 'not_yet_effective',
      reason_code: 'CONDITION_DATE_NOT_REACHED',
      findings: [],
      rejections: [],
    },
  },
  {
    id: 'AC-31-date-reached-valid',
    tests: 'The same condition at an instant past the date establishes activation.',
    condition: 'COND_DATE',
    action_at: 'T_LATER_ACTION',
    presented: [],
    expected: {
      verdict: 'valid',
      reason_code: 'ACTIVATION_ESTABLISHED',
      findings: [],
      rejections: [],
    },
  },
  {
    id: 'AC-32-date-condition-ignores-attestations',
    tests:
      'Attestations presented against a date condition are not consulted, so an acceptable occurrence record cannot bring a date forward.',
    condition: 'COND_DATE',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_ON_TIME'],
    expected: {
      verdict: 'not_yet_effective',
      reason_code: 'CONDITION_DATE_NOT_REACHED',
      findings: [],
      rejections: [],
    },
  },
  {
    id: 'AC-33-date-boundary-is-inclusive',
    tests: 'An action exactly at the activation date is at the date, so the date has been reached.',
    condition: 'COND_DATE',
    action_at: 'T_ACTIVATION_DATE',
    presented: [],
    expected: {
      verdict: 'valid',
      reason_code: 'ACTIVATION_ESTABLISHED',
      findings: [],
      rejections: [],
    },
  },
  {
    id: 'AC-34-condition-for-another-grant-is-a-coverage-gap',
    tests:
      'A condition gating a different delegation does not state that it covers this one, so it is a coverage gap and is never silently applied here.',
    condition: 'COND_EVENT_OTHER_GRANT',
    action_at: 'T_ACTION',
    presented: ['ATT_OCCURRED_ON_TIME'],
    expected: {
      verdict: 'not_established',
      reason_code: 'CONDITION_DELEGATION_MISMATCH',
      missing: ['coverage'],
      findings: [],
      rejections: [],
    },
  },
]

// Chain results are hand-written plain data in the draft-03 four-value vocabulary, exactly
// as the lifecycle-state vectors do it. `activation_from_case` names a verify case above, so
// the composition cases reuse an activation result rather than restating one.
const composeCases = [
  {
    id: 'AC-CO-01-valid-chain-reports-the-activation-answer',
    tests:
      'Chain valid and activation established: the composite carries the activation verdict and the chain result is returned untouched.',
    chain_result: { state: 'valid', valid: true, failures: [] },
    activation_from_case: 'AC-01-occurrence-before-action-valid',
    expected: {
      chain_state: 'valid',
      lifecycle_verdict: 'valid',
      lifecycle_reason_code: 'ACTIVATION_ESTABLISHED',
    },
  },
  {
    id: 'AC-CO-02-valid-chain-waiting-condition-is-not-yet-effective',
    tests:
      'A validly issued grant waiting on a condition. This is the answer draft-03 chain verification has no slot for, and it is reported alongside a chain result that still says valid.',
    chain_result: { state: 'valid', valid: true, failures: [] },
    activation_from_case: 'AC-15-accepted-negative-not-yet-effective',
    expected: {
      chain_state: 'valid',
      lifecycle_verdict: 'not_yet_effective',
      lifecycle_reason_code: 'CONDITION_ESTABLISHED_NOT_YET_OCCURRED',
    },
  },
  {
    id: 'AC-CO-03-revoked-chain-is-invalid-and-activation-is-not-asked',
    tests:
      'INVARIANT L1 STAYS INTACT. A revoked grant is invalid, activation is never consulted, and no activation evidence can make it exercisable. Reporting not_yet_effective here would say the remedy is to wait when it is not.',
    chain_result: {
      state: 'invalid',
      valid: false,
      failures: [{ code: 'REVOKED', message: 'delegation revoked', index: 0 }],
    },
    activation_from_case: 'AC-01-occurrence-before-action-valid',
    expected: {
      chain_state: 'invalid',
      lifecycle_verdict: 'invalid',
      lifecycle_reason_code: 'REVOKED',
    },
  },
  {
    id: 'AC-CO-04-indeterminate-chain-keeps-its-own-answer',
    tests:
      'An unknown revocation answer is indeterminate at the chain layer and maps to not_established with the source limb. Activation is not asked.',
    chain_result: {
      state: 'indeterminate',
      valid: false,
      failures: [{ code: 'REVOCATION_UNKNOWN', message: 'revocation unavailable', index: 0 }],
    },
    activation_from_case: 'AC-01-occurrence-before-action-valid',
    expected: {
      chain_state: 'indeterminate',
      lifecycle_verdict: 'not_established',
      lifecycle_reason_code: 'REVOCATION_UNKNOWN',
      lifecycle_missing: ['source'],
    },
  },
  {
    id: 'AC-CO-05-no-activation-module-ran',
    tests: 'A null activation result is how a caller says no activation module ran. The composite then carries only the chain reading.',
    chain_result: { state: 'valid', valid: true, failures: [] },
    activation_from_case: null,
    expected: {
      chain_state: 'valid',
      lifecycle_verdict: 'valid',
      lifecycle_reason_code: 'CHAIN_VALID',
    },
  },
  {
    id: 'AC-CO-06-time-facet-wait-keeps-the-chain-answer-by-default',
    tests:
      'THE CONTESTED READING, LEFT TO THE CALLER. A grant whose time facet not_before has not been reached is invalid with NOT_YET_VALID at the chain layer. One instant, two mechanisms carrying the wait, and this module settles nothing by default.',
    chain_result: {
      state: 'invalid',
      valid: false,
      failures: [{ code: 'NOT_YET_VALID', message: 'not_before is after now', index: 0 }],
    },
    activation_from_case: null,
    mapping: { not_yet_valid_as_not_yet_effective: false },
    expected: {
      chain_state: 'invalid',
      lifecycle_verdict: 'invalid',
      lifecycle_reason_code: 'NOT_YET_VALID',
    },
  },
  {
    id: 'AC-CO-07-time-facet-wait-under-the-other-reading',
    tests:
      'The same chain result under the opt-in reading. The chain result itself is byte for byte unchanged either way.',
    chain_result: {
      state: 'invalid',
      valid: false,
      failures: [{ code: 'NOT_YET_VALID', message: 'not_before is after now', index: 0 }],
    },
    activation_from_case: null,
    mapping: { not_yet_valid_as_not_yet_effective: true },
    expected: {
      chain_state: 'invalid',
      lifecycle_verdict: 'not_yet_effective',
      // The lifecycle reading mints its OWN code rather than reusing the chain failure code.
      // The two are different findings about different subjects, and NOT_YET_VALID stays
      // the chain result's own word for its own answer.
      lifecycle_reason_code: 'NOT_BEFORE_UNREACHED',
    },
  },
]

const vectors = {
  profile: 'aps-activation-v0',
  status: 'proposed',
  status_note:
    'PROPOSED and OPT-IN. Not required by draft-pidlisnyi-aps-03, which states no activation-condition rule, no attestor role and no attestation-acceptance rule: a case-insensitive search of the published text for activation, attestor and contingen returns nothing. Its section 3.2 closes the authority vector at seven facets, so an activation condition can never be a facet and is a separate artifact referencing a delegation_id. Concept source: the aeoess/agent-authority-lifecycle concept document and its invariant candidates CAND-04, CAND-13 (activation half) and BROAD-L7, all proposed. Nothing downstream should bind to these names as specified text.',
  description:
    'Cross-language parity vectors for activation conditions naming an attestor role, the split between not_yet_effective and not_established, and the no-retroactive-activation rule keyed on the condition own occurrence instant. The TypeScript and Python SDKs must produce identical results for every case.',
  vocabulary: {
    condition_kinds: [...ACTIVATION_CONDITION_KINDS],
    instant_bases: [...ACTIVATION_INSTANT_BASES],
    assertions: [...ACTIVATION_ASSERTIONS],
    attestor_role_standings: [...ATTESTOR_ROLE_STANDINGS],
    findings: [...ACTIVATION_FINDINGS],
    reason_codes: [...ACTIVATION_REASON_CODES],
  },
  record_types: {
    condition: ACTIVATION_CONDITION_TYPE,
    attestation: ACTIVATION_ATTESTATION_TYPE,
  },
  seed_convention: `private key = SHA-256("${SEED_PREFIX}" + label)`,
  seed_labels: SEED_LABELS,
  verification_keys: verificationKeys,
  attestor_role_registry: ROLE_REGISTRY,
  role_registry_note:
    'Roles held, resolved OUTSIDE any attestation. An attestor absent from this map is unknown for every role, which is ignorance and deliberately not does_not_hold.',
  clock: CLOCK,
  delegation_id: DELEGATION_ID,
  conditions: CONDITIONS,
  attestations: ATTESTATIONS,
  condition_validation_cases: conditionCases,
  verify_cases: verifyCases,
  compose_cases: composeCases,
}

const here = dirname(fileURLToPath(import.meta.url))
writeFileSync(join(here, 'vectors.json'), `${JSON.stringify(vectors, null, 2)}\n`, 'utf8')
console.log(
  `wrote vectors.json: ${conditionCases.length} condition cases, ${verifyCases.length} verify cases, ${composeCases.length} compose cases`,
)
