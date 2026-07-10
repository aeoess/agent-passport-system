// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Claim → Evidence types — skeleton conformance.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  ClaimType,
  RecordType,
  EvidenceProfiles,
  requiredEvidenceFor,
} from '../../src/index.js'

describe('claim-evidence-types', () => {
  it('every ClaimType has an EvidenceProfile entry', () => {
    for (const claim of Object.values(ClaimType)) {
      const profile = EvidenceProfiles[claim]
      assert.ok(profile, `missing EvidenceProfile for ${claim}`)
      assert.ok(Array.isArray(profile.required), `required must be an array for ${claim}`)
      assert.ok(
        profile.forbiddenSubstitutions && typeof profile.forbiddenSubstitutions === 'object',
        `forbiddenSubstitutions must be an object for ${claim}`,
      )
    }
  })

  it('requiredEvidenceFor(BINDING_COMMITMENT) includes forbiddenSubstitutions for ActionReceipt', () => {
    const profile = requiredEvidenceFor(ClaimType.BINDING_COMMITMENT)
    const reason = profile.forbiddenSubstitutions[RecordType.ActionReceipt]
    assert.equal(typeof reason, 'string')
    assert.ok(
      reason && reason.length > 0,
      'forbiddenSubstitutions[ActionReceipt] must carry a non-empty rationale',
    )
    assert.match(reason!, /binding commitment/i)
  })

  it('requiredEvidenceFor(AUTHORITY_TO_EXECUTE) returns expected required record types', () => {
    const profile = requiredEvidenceFor(ClaimType.AUTHORITY_TO_EXECUTE)
    assert.deepEqual(profile.required, [RecordType.AuthorityBoundaryReceipt])
  })

  it('BATCH_ATTESTED requires APSBundle', () => {
    const profile = requiredEvidenceFor(ClaimType.BATCH_ATTESTED)
    assert.deepEqual(profile.required, [RecordType.APSBundle])
    assert.deepEqual(profile.forbiddenSubstitutions, {})
  })

  it('EVIDENCE_CUSTODY_HELD requires CustodyReceipt and forbids ActionReceipt', () => {
    const profile = requiredEvidenceFor(ClaimType.EVIDENCE_CUSTODY_HELD)
    assert.deepEqual(profile.required, [RecordType.CustodyReceipt])
    const reason = profile.forbiddenSubstitutions[RecordType.ActionReceipt]
    assert.equal(typeof reason, 'string')
    assert.ok(reason && reason.length > 0)
    assert.match(reason!, /held the evidence/i)
  })

  // ── Phase 4.1 / Q1 — rail receipts registered as evidence types ──

  it('Q1: five rail receipt types are registered in RecordType enum', () => {
    const expected = [
      'PaymentReceipt',
      'AcpReceipt',
      'MppApsReceipt',
      'SignedAP2Mandate',
      'StripeIssuingReceipt',
    ]
    for (const name of expected) {
      assert.ok(
        Object.values(RecordType as unknown as Record<string, string>).includes(name),
        `RecordType is missing ${name}`,
      )
    }
  })

  it('Q1: RAIL_RECEIPT_CLAIM_TYPES maps each rail receipt to its claim_type literal', async () => {
    const { RAIL_RECEIPT_CLAIM_TYPES } = await import('../../src/v2/claim-evidence-types.js')
    assert.equal(RAIL_RECEIPT_CLAIM_TYPES[RecordType.PaymentReceipt], 'rail.payment.v1')
    assert.equal(RAIL_RECEIPT_CLAIM_TYPES[RecordType.AcpReceipt], 'rail.acp.v1')
    assert.equal(RAIL_RECEIPT_CLAIM_TYPES[RecordType.MppApsReceipt], 'rail.mpp.v1')
    assert.equal(RAIL_RECEIPT_CLAIM_TYPES[RecordType.SignedAP2Mandate], 'rail.ap2.mandate.v1')
    assert.equal(
      RAIL_RECEIPT_CLAIM_TYPES[RecordType.StripeIssuingReceipt],
      'rail.stripe_issuing.v1',
    )
  })
})
