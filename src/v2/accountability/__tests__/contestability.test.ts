// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ContestabilityReceipt — construct + verify conformance.
//
// Note: node:test rather than vitest because the repo has no vitest
// install; node:test is the v2 convention.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  attachControllerResponse,
  createContestabilityReceipt,
} from '../construct/contestability.js'
import { verifyContestabilityReceipt } from '../verify/contestability.js'
import { publicKeyFromPrivate } from '../../../crypto/keys.js'
import type {
  ContestStatus,
  ContestabilityReceipt,
  RequestedRemedy,
  StandingBasis,
} from '../types/contestability.js'
import type { ScopeOfClaim } from '../types/base.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

const CONTESTANT_PRIV = '33'.repeat(64)
const CONTROLLER_PRIV = '44'.repeat(64)
const CONTESTANT_TS = '2026-04-30T00:00:00.000Z'
const RESPONDED_TS = '2026-04-30T01:00:00.000Z'
const ACTION_ID = '0000000000000000000000000000000000000000000000000000000000000002'

const SCOPE: ScopeOfClaim = {
  asserts: 'Named contestant filed a challenge against the named action with the named grounds.',
  does_not_assert: [
    'that the contestation is meritorious',
    'that the standing is legally valid',
    'that any controller response is correct or final',
  ],
  capture_mode: 'self_attested',
  completeness: 'complete',
  self_attested: true,
}

function baseInput(overrides: Partial<ContestabilityReceipt> = {}) {
  return {
    timestamp: CONTESTANT_TS,
    scope_of_claim: SCOPE,
    contestant: {
      did: 'did:aps:test-subject-001',
      standing_basis: 'data_subject' as StandingBasis,
    },
    action_id: ACTION_ID,
    grounds: 'Automated decision affected my access without disclosed criteria.',
    requested_remedy: 'explanation' as RequestedRemedy,
    ...overrides,
  }
}

describe('ContestabilityReceipt — construct + verify', () => {
  it('happy path without response: construct + verify round-trips green', () => {
    const r = createContestabilityReceipt(baseInput(), CONTESTANT_PRIV)
    const v = verifyContestabilityReceipt(r)
    assert.equal(v.valid, true, `expected valid; got reason=${v.reason}`)
    assert.equal(r.claim_type, 'aps:contestability:v1')
    assert.equal(r.controller_response, undefined)
  })

  it('receipt_id is stable across reruns with identical inputs', () => {
    const a = createContestabilityReceipt(baseInput(), CONTESTANT_PRIV)
    const b = createContestabilityReceipt(baseInput(), CONTESTANT_PRIV)
    assert.equal(a.receipt_id, b.receipt_id)
    assert.equal(a.signature, b.signature)
  })

  it('happy path with controller_response attached: both signatures verify', () => {
    const filed = createContestabilityReceipt(baseInput(), CONTESTANT_PRIV)
    const controllerDid = publicKeyFromPrivate(CONTROLLER_PRIV)
    const responded = attachControllerResponse(
      filed,
      {
        status: 'under_review',
        responded_at: RESPONDED_TS,
        responder_did: controllerDid,
        response_detail: 'Acknowledged. Routed to data-subject access team.',
      },
      CONTROLLER_PRIV,
    )
    assert.notEqual(responded.controller_response, undefined)
    assert.equal(responded.controller_response?.response_signature.length, 128)
    // Outer (contestant) signature is unchanged from the filing.
    assert.equal(responded.signature, filed.signature)
    assert.equal(responded.receipt_id, filed.receipt_id)
    const v = verifyContestabilityReceipt(responded)
    assert.equal(v.valid, true, `expected valid; got reason=${v.reason}`)
  })

  it('pseudonymous contestant: pseudonym_hash only, no did', () => {
    const pseudo = createHash('sha256').update('subject-handle-42').digest('hex')
    const r = createContestabilityReceipt(
      baseInput({
        contestant: {
          pseudonym_hash: pseudo,
          standing_basis: 'data_subject',
        },
      }),
      CONTESTANT_PRIV,
    )
    assert.equal(r.contestant.did, undefined)
    assert.equal(r.contestant.pseudonym_hash, pseudo)
    const v = verifyContestabilityReceipt(r)
    assert.equal(v.valid, true, `expected valid; got reason=${v.reason}`)
  })

  it('construct rejects contestant with neither did nor pseudonym_hash', () => {
    assert.throws(
      () =>
        createContestabilityReceipt(
          baseInput({
            contestant: { standing_basis: 'data_subject' } as ContestabilityReceipt['contestant'],
          }),
          CONTESTANT_PRIV,
        ),
      /must have at least one of did or pseudonym_hash/,
    )
  })

  it('verify reports MISSING_CONTESTANT_IDENTITY when both identity fields are empty', () => {
    const r = createContestabilityReceipt(baseInput(), CONTESTANT_PRIV)
    const tampered: ContestabilityReceipt = {
      ...r,
      contestant: { standing_basis: 'data_subject' },
    }
    const v = verifyContestabilityReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'MISSING_CONTESTANT_IDENTITY')
  })

  it('tamper on grounds field yields RECEIPT_ID_MISMATCH', () => {
    const r = createContestabilityReceipt(baseInput(), CONTESTANT_PRIV)
    const tampered: ContestabilityReceipt = {
      ...r,
      grounds: 'rewritten grounds after the fact',
    }
    const v = verifyContestabilityReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'RECEIPT_ID_MISMATCH')
  })

  it('tamper on response_detail invalidates the controller signature only', () => {
    const filed = createContestabilityReceipt(baseInput(), CONTESTANT_PRIV)
    const controllerDid = publicKeyFromPrivate(CONTROLLER_PRIV)
    const responded = attachControllerResponse(
      filed,
      {
        status: 'under_review',
        responded_at: RESPONDED_TS,
        responder_did: controllerDid,
        response_detail: 'original response detail',
      },
      CONTROLLER_PRIV,
    )
    const tampered: ContestabilityReceipt = {
      ...responded,
      controller_response: {
        ...responded.controller_response!,
        response_detail: 'rewritten response detail',
      },
    }
    const v = verifyContestabilityReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'CONTROLLER_SIGNATURE_INVALID')
  })

  it('all 7 standing_basis values verify', () => {
    const all: StandingBasis[] = [
      'data_subject',
      'third_party',
      'regulator',
      'court',
      'internal_audit',
      'insurer',
      'principal',
    ]
    for (const standing_basis of all) {
      const r = createContestabilityReceipt(
        baseInput({
          contestant: { did: 'did:aps:test-subject-001', standing_basis },
        }),
        CONTESTANT_PRIV,
      )
      const v = verifyContestabilityReceipt(r)
      assert.equal(v.valid, true, `standing=${standing_basis} did not verify: ${v.reason}`)
    }
  })

  it('all 6 requested_remedy values verify', () => {
    const all: RequestedRemedy[] = [
      'rollback',
      'review',
      'explanation',
      'compensation',
      'erasure',
      'modification',
    ]
    for (const requested_remedy of all) {
      const r = createContestabilityReceipt(baseInput({ requested_remedy }), CONTESTANT_PRIV)
      const v = verifyContestabilityReceipt(r)
      assert.equal(v.valid, true, `remedy=${requested_remedy} did not verify: ${v.reason}`)
    }
  })

  it('all 7 contest_status values verify when carried in controller_response', () => {
    const all: ContestStatus[] = [
      'filed',
      'under_review',
      'upheld',
      'rejected',
      'remedied',
      'expired',
      'abandoned',
    ]
    const controllerDid = publicKeyFromPrivate(CONTROLLER_PRIV)
    for (const status of all) {
      const filed = createContestabilityReceipt(baseInput(), CONTESTANT_PRIV)
      const responded = attachControllerResponse(
        filed,
        { status, responded_at: RESPONDED_TS, responder_did: controllerDid },
        CONTROLLER_PRIV,
      )
      const v = verifyContestabilityReceipt(responded)
      assert.equal(v.valid, true, `status=${status} did not verify: ${v.reason}`)
    }
  })

  it('rejects wrong claim_type', () => {
    const r = createContestabilityReceipt(baseInput(), CONTESTANT_PRIV)
    const tampered = {
      ...r,
      claim_type: 'aps:custody:v1' as 'aps:contestability:v1',
    }
    const v = verifyContestabilityReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_CLAIM_TYPE')
  })

  it('matches the on-disk fixture byte-for-byte (no controller_response)', () => {
    const fixturePath = join(__dirname, '..', 'fixtures', 'contestability.fixture.json')
    const fixture = JSON.parse(readFileSync(fixturePath, 'utf-8')) as ContestabilityReceipt
    const built = createContestabilityReceipt(baseInput(), CONTESTANT_PRIV)
    assert.deepEqual(built, fixture)
    const v = verifyContestabilityReceipt(fixture)
    assert.equal(v.valid, true, `fixture failed verify: ${v.reason}`)
  })
})
