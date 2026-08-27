// Regression for the Day 192 defect: ReceiptContext.active_delegation_root
// was declared authoritative and never read, so a receipt from any root
// verified as long as that root was not on the revoked list. Both harnesses
// set the active root equal to the receipt root by construction, which is
// why no existing test caught it. Rejection reason is DELEGATION_ROOT_MISMATCH,
// deliberately not DELEGATION_REVOKED: an unrecognised root is not a revoked one.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { buildGoldenValid, type ReceiptContext } from '../../conformance/generate.js'
import { verifyReceiptContext } from '../../../src/v2/offline-verifier/context.js'

const OTHER_ROOT = 'b'.repeat(64)

function ctxWithActiveRoot(agentDid: string, activeRoot: string): ReceiptContext {
  return {
    now: '2026-05-01T12:00:00.000Z',
    active_delegation_root: activeRoot,
    delegation_expires_at: '2027-01-01T00:00:00.000Z',
    revoked_delegation_roots: [],
    budget_base_units: 1_000_000n,
    action_cost_base_units: 1_000n,
    expected_principal_did: agentDid,
    active_policy_version: 3,
    evaluated_policy_version: 3,
    seen_receipt_ids: [],
    presented_as_claim_type: 'aps:action:v1',
    execution_attested: true,
  }
}

describe('offline verifier: receipt root vs authoritative root', () => {
  const golden = buildGoldenValid()

  it('control: matching active root verifies', () => {
    const r = verifyReceiptContext(golden.receipt, ctxWithActiveRoot(golden.receipt.agent_did, golden.receipt.delegation_chain_root))
    assert.equal(r.valid, true)
  })

  it('the roots differ and it is not revoked', () => {
    assert.notEqual(golden.receipt.delegation_chain_root, OTHER_ROOT)
  })

  it('receipt from a NON-authoritative root must be rejected', () => {
    const r = verifyReceiptContext(golden.receipt, ctxWithActiveRoot(golden.receipt.agent_did, OTHER_ROOT))
    assert.equal(r.valid, false, 'receipt verified against a root the context does not treat as authoritative')
    assert.equal(r.reason, 'DELEGATION_ROOT_MISMATCH')
  })

  it('an unrecognised root is not reported as a revoked root', () => {
    const ctx = ctxWithActiveRoot(golden.receipt.agent_did, OTHER_ROOT)
    const r = verifyReceiptContext(golden.receipt, ctx)
    assert.notEqual(r.reason, 'DELEGATION_REVOKED')
  })
})
