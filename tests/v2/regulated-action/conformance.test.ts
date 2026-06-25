// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// APS Regulated Action Profile v0: in-suite conformance + adversarial gate.
// Runs the deterministic disposition verifier (A2) against the frozen conformance vectors
// and pins the locked invariants. judgment_correctness is always not_claimed.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { RegulatedActionV0 } from '../../../src/index.js'

const { verifyRegulatedAction } = RegulatedActionV0
type Vec = {
  id: string
  surface: string
  input_receipt: Parameters<typeof verifyRegulatedAction>[0]
  verification_context: Parameters<typeof verifyRegulatedAction>[1]
  expected: {
    disposition: string
    incomplete_reason?: string
    authority_basis?: string
    violations: string[]
    trust_domain_separation: { computed_domains: number }
  }
}
const doc = JSON.parse(readFileSync(join(process.cwd(), 'conformance/regulated-action/v0/vectors.json'), 'utf8')) as {
  count: number
  verifier_vector_count: number
  vectors: Vec[]
}
const verifierVectors = doc.vectors.filter((v) => v.surface === 'verifier')

describe('RAPV0 conformance vectors (disposition function)', () => {
  it('has 33 frozen vectors (31 verifier + 2 completeness)', () => {
    assert.equal(doc.count, 33)
    assert.equal(doc.verifier_vector_count, 31)
    assert.equal(verifierVectors.length, 31)
  })

  for (const v of verifierVectors) {
    it(`${v.id}: ${v.expected.disposition}${v.expected.incomplete_reason ? ':' + v.expected.incomplete_reason : ''}`, () => {
      const r = verifyRegulatedAction(v.input_receipt, v.verification_context)
      assert.equal(r.disposition, v.expected.disposition, `${v.id} disposition`)
      if (v.expected.incomplete_reason) assert.equal(r.incomplete_reason, v.expected.incomplete_reason, `${v.id} reason`)
      if (v.expected.authority_basis) assert.equal(r.authority_basis, v.expected.authority_basis, `${v.id} basis`)
      assert.deepEqual(r.violations, v.expected.violations, `${v.id} violations`)
      // locked: never claims judgment correctness; replay is a gateway concern
      assert.equal(r.judgment_correctness, 'not_claimed')
      assert.equal(r.authority_replay, 'not_evaluated')
    })
  }
})

describe('RAPV0 locked invariants', () => {
  const reconciled = verifierVectors.filter((v) => v.expected.disposition === 'reconciled' || v.expected.disposition === 'regulator_grade_for_class')

  it('reconciled / regulator_grade ALWAYS carry computed_domains >= 2', () => {
    assert.ok(reconciled.length > 0)
    for (const v of reconciled) {
      const r = verifyRegulatedAction(v.input_receipt, v.verification_context)
      assert.ok(r.trust_domain_separation.computed_domains >= 2, `${v.id} domains`)
      assert.equal(r.trust_domain_separation.resource_counts, true, `${v.id} resource domain`)
    }
  })

  it('a boundary_attested_weak resource can NEVER reconcile, even at two presented domains (V33)', () => {
    const v33 = verifierVectors.find((v) => v.id === 'V33')!
    const r = verifyRegulatedAction(v33.input_receipt, v33.verification_context)
    assert.equal(r.disposition, 'intent_precommitted')
    assert.notEqual(r.disposition, 'reconciled')
    assert.ok(r.trust_domain_separation.computed_domains < 2)
  })

  it('self_attested is terminal: intent_ok + policy_allow do not override it (V32)', () => {
    const v32 = verifierVectors.find((v) => v.id === 'V32')!
    const r = verifyRegulatedAction(v32.input_receipt, v32.verification_context)
    assert.equal(r.disposition, 'self_attested')
  })

  it('authority_invalid fires regardless of a valid resource (V26, amended guard 6)', () => {
    const v26 = verifierVectors.find((v) => v.id === 'V26')!
    const r = verifyRegulatedAction(v26.input_receipt, v26.verification_context)
    assert.equal(r.disposition, 'authority_invalid')
  })

  it('records every terminal condition in violations[] and first-match wins (V31)', () => {
    const v31 = verifierVectors.find((v) => v.id === 'V31')!
    const r = verifyRegulatedAction(v31.input_receipt, v31.verification_context)
    assert.equal(r.disposition, 'void_policy_violation')
    assert.deepEqual(r.violations, ['void_policy_violation', 'void_temporal_violation', 'void_reconciliation_mismatch'])
  })

  it('an operator-anchored authority copy yields weak basis, never an external domain (V18)', () => {
    const v18 = verifierVectors.find((v) => v.id === 'V18')!
    const r = verifyRegulatedAction(v18.input_receipt, v18.verification_context)
    assert.equal(r.authority_basis, 'operator_anchored_copy_weak')
    assert.equal(r.trust_domain_separation.idp_counts, false)
  })
})
