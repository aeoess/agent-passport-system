// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Claim Verifier (Module 2) — pure registry type-checker tests.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  ClaimType,
  RecordType,
  verifyEvidenceClaim,
} from '../../src/index.js'
import type { ClaimVerificationInput } from '../../src/index.js'

const SUBJECT = 'aps:test:subject-001'

function makeInput(
  type: ClaimType,
  evidence: ClaimVerificationInput['evidence'],
): ClaimVerificationInput {
  return { claim: { type, subject: SUBJECT }, evidence }
}

describe('verifyEvidenceClaim — Module 2 registry checks', () => {
  it('BINDING_COMMITMENT with only ActionReceipt → forbidden_substitution with the registry reason text', () => {
    // The draft-as-commitment failure mode: an agent points at an
    // ActionReceipt and asserts "this is binding". The registry
    // forbids that substitution; the verifier surfaces the
    // verbatim rationale from the registry.
    const result = verifyEvidenceClaim(
      makeInput(ClaimType.BINDING_COMMITMENT, [
        { recordType: RecordType.ActionReceipt, record: { /* opaque */ } },
      ]),
    )
    assert.equal(result.status, 'forbidden_substitution')
    if (result.status !== 'forbidden_substitution') return
    assert.equal(result.claimType, ClaimType.BINDING_COMMITMENT)
    assert.equal(result.offendingRecord, RecordType.ActionReceipt)
    assert.equal(
      result.reason,
      'Action receipts prove execution or communication, not binding commitment.',
    )
  })

  it('BINDING_COMMITMENT with PromotionEvent + ProvisionalStatement → valid', () => {
    const result = verifyEvidenceClaim(
      makeInput(ClaimType.BINDING_COMMITMENT, [
        { recordType: RecordType.PromotionEvent, record: {} },
        { recordType: RecordType.ProvisionalStatement, record: {} },
      ]),
    )
    assert.equal(result.status, 'valid')
    if (result.status !== 'valid') return
    assert.deepEqual(result.satisfiedBy, [
      RecordType.PromotionEvent,
      RecordType.ProvisionalStatement,
    ])
  })

  it('AUTHORITY_TO_EXECUTE with only AuthorityBoundaryReceipt → valid', () => {
    const result = verifyEvidenceClaim(
      makeInput(ClaimType.AUTHORITY_TO_EXECUTE, [
        { recordType: RecordType.AuthorityBoundaryReceipt, record: {} },
      ]),
    )
    assert.equal(result.status, 'valid')
    if (result.status !== 'valid') return
    assert.deepEqual(result.satisfiedBy, [RecordType.AuthorityBoundaryReceipt])
  })

  it('AUTHORITY_TO_EXECUTE with no evidence → missing_evidence with [AuthorityBoundaryReceipt] missing', () => {
    const result = verifyEvidenceClaim(makeInput(ClaimType.AUTHORITY_TO_EXECUTE, []))
    assert.equal(result.status, 'missing_evidence')
    if (result.status !== 'missing_evidence') return
    assert.deepEqual(result.missing, [RecordType.AuthorityBoundaryReceipt])
    assert.deepEqual(result.provided, [])
  })

  it('BATCH_ATTESTED with APSBundle → valid', () => {
    const result = verifyEvidenceClaim(
      makeInput(ClaimType.BATCH_ATTESTED, [
        { recordType: RecordType.APSBundle, record: {} },
      ]),
    )
    assert.equal(result.status, 'valid')
    if (result.status !== 'valid') return
    assert.deepEqual(result.satisfiedBy, [RecordType.APSBundle])
  })

  it('BINDING_COMMITMENT with APSBundle in evidence → bundle_requires_inclusion_proof', () => {
    const bundleRec = { claim_type: 'aps:bundle:v1', merkle_root: 'deadbeef' }
    const result = verifyEvidenceClaim(
      makeInput(ClaimType.BINDING_COMMITMENT, [
        { recordType: RecordType.APSBundle, record: bundleRec },
      ]),
    )
    assert.equal(result.status, 'bundle_requires_inclusion_proof')
    if (result.status !== 'bundle_requires_inclusion_proof') return
    assert.equal(result.claimType, ClaimType.BINDING_COMMITMENT)
    assert.equal(result.bundleRecord, bundleRec)
  })

  it('EVIDENCE_CUSTODY_HELD with ActionReceipt → forbidden_substitution', () => {
    const result = verifyEvidenceClaim(
      makeInput(ClaimType.EVIDENCE_CUSTODY_HELD, [
        { recordType: RecordType.ActionReceipt, record: {} },
      ]),
    )
    assert.equal(result.status, 'forbidden_substitution')
    if (result.status !== 'forbidden_substitution') return
    assert.equal(result.offendingRecord, RecordType.ActionReceipt)
    assert.match(result.reason, /held the evidence/i)
  })

  it('EVIDENCE_CUSTODY_HELD with CustodyReceipt → valid', () => {
    const result = verifyEvidenceClaim(
      makeInput(ClaimType.EVIDENCE_CUSTODY_HELD, [
        { recordType: RecordType.CustodyReceipt, record: {} },
      ]),
    )
    assert.equal(result.status, 'valid')
    if (result.status !== 'valid') return
    assert.deepEqual(result.satisfiedBy, [RecordType.CustodyReceipt])
  })

  it('ACTION_EXECUTED (stubbed) with anything → profile_not_populated', () => {
    const result = verifyEvidenceClaim(
      makeInput(ClaimType.ACTION_EXECUTED, [
        { recordType: RecordType.ActionReceipt, record: {} },
      ]),
    )
    assert.equal(result.status, 'profile_not_populated')
    if (result.status !== 'profile_not_populated') return
    assert.equal(result.claimType, ClaimType.ACTION_EXECUTED)
  })

  it('unsupported claim type → unsupported_claim_type', () => {
    const result = verifyEvidenceClaim({
      claim: { type: 'NOT_A_REAL_CLAIM' as unknown as ClaimType, subject: SUBJECT },
      evidence: [],
    })
    assert.equal(result.status, 'unsupported_claim_type')
  })

  // ── Module 4 — openContestationResolver hook ──

  it('with no resolver returns valid as before (regression)', () => {
    const result = verifyEvidenceClaim(
      makeInput(ClaimType.AUTHORITY_TO_EXECUTE, [
        {
          recordType: RecordType.AuthorityBoundaryReceipt,
          receiptId: 'auth_001',
          record: {},
        },
      ]),
    )
    assert.equal(result.status, 'valid')
  })

  it('with resolver returning filed status returns contested', () => {
    const result = verifyEvidenceClaim({
      claim: { type: ClaimType.AUTHORITY_TO_EXECUTE, subject: SUBJECT },
      evidence: [
        {
          recordType: RecordType.AuthorityBoundaryReceipt,
          receiptId: 'auth_001',
          record: {},
        },
      ],
      openContestationResolver: () => ({
        contestationId: 'contest_xyz',
        status: 'filed',
      }),
    })
    assert.equal(result.status, 'contested')
    if (result.status !== 'contested') return
    assert.equal(result.contestedRecordId, 'auth_001')
    assert.equal(result.contestationId, 'contest_xyz')
    assert.equal(result.contestationStatus, 'filed')
  })

  it('with resolver returning rejected status returns valid (rejected does not block)', () => {
    const result = verifyEvidenceClaim({
      claim: { type: ClaimType.AUTHORITY_TO_EXECUTE, subject: SUBJECT },
      evidence: [
        {
          recordType: RecordType.AuthorityBoundaryReceipt,
          receiptId: 'auth_001',
          record: {},
        },
      ],
      openContestationResolver: () => ({
        contestationId: 'contest_xyz',
        status: 'rejected',
      }),
    })
    assert.equal(result.status, 'valid')
  })

  it('with resolver returning upheld status returns contested', () => {
    const result = verifyEvidenceClaim({
      claim: { type: ClaimType.AUTHORITY_TO_EXECUTE, subject: SUBJECT },
      evidence: [
        {
          recordType: RecordType.AuthorityBoundaryReceipt,
          receiptId: 'auth_001',
          record: {},
        },
      ],
      openContestationResolver: () => ({
        contestationId: 'contest_xyz',
        status: 'upheld',
      }),
    })
    assert.equal(result.status, 'contested')
    if (result.status !== 'contested') return
    assert.equal(result.contestationStatus, 'upheld')
  })
})

describe('compliance-complete failure (Paper 8 instantiation)', () => {
  it('full procedural chain claiming EFFECT_SAFETY_ATTESTED returns profile_not_populated', () => {
    // Construct evidence representing all five Auditable Agents dimensions:
    // - action recoverability (ActionReceipt)
    // - lifecycle coverage (DerivationReceipt)
    // - policy checkability (DecisionReceipt)
    // - responsibility attribution (AuthorityBoundaryReceipt)
    // - evidence integrity (each receipt is independently valid)
    //
    // EFFECT_SAFETY_ATTESTED is intentionally a stubbed claim type:
    // the protocol does not certify effect safety. The verifier
    // returns 'profile_not_populated', which IS the correct
    // compliance-complete-failure response — the protocol
    // acknowledges it cannot answer the claim rather than
    // vacuously approving it.
    const evidence = [
      { recordType: RecordType.AuthorityBoundaryReceipt, record: {} },
      { recordType: RecordType.DecisionReceipt, record: {} },
      { recordType: RecordType.ActionReceipt, record: {} },
      { recordType: RecordType.DerivationReceipt, record: {} },
    ]

    const result = verifyEvidenceClaim({
      claim: { type: ClaimType.EFFECT_SAFETY_ATTESTED, subject: 'paper8_scenario' },
      evidence,
    })

    assert.equal(result.status, 'profile_not_populated')
    if (result.status !== 'profile_not_populated') return
    assert.equal(result.claimType, ClaimType.EFFECT_SAFETY_ATTESTED)
  })
})
