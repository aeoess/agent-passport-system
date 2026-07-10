// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Offline verifier tests
// ══════════════════════════════════════════════════════════════════
// Pins three properties:
//   1. The verifier runs FULLY OFFLINE - any network access during a
//      verify call is a test failure (global fetch is trapped).
//   2. A clean receipt verifies and yields the W2-A1 descriptor.
//   3. Every negative fixture is rejected, at the right layer, for the
//      stated reason - the verifier composes the crypto and context
//      layers in the pinned order.
// ══════════════════════════════════════════════════════════════════

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildGoldenValid,
  buildNegatives,
  type ReceiptContext,
} from '../../conformance/generate.js'
import { verifyOffline } from '../../../src/v2/offline-verifier/verify.js'
import type { WitnessConflict } from '../../../src/types/gateway.js'

// ── network trap: fetch must never be called during a verify ─────────
let fetchCalled = false
const realFetch = globalThis.fetch
before(() => {
  fetchCalled = false
  // Replace fetch with a trap. Any call flips the flag and throws so a
  // verify path that reaches for the network fails loudly.
  ;(globalThis as { fetch: unknown }).fetch = (...args: unknown[]) => {
    fetchCalled = true
    throw new Error(`offline verifier reached the network: fetch(${String(args[0])})`)
  }
})
after(() => {
  ;(globalThis as { fetch: unknown }).fetch = realFetch
})

function okContext(agentDid: string, delegationRoot: string): ReceiptContext {
  return {
    now: '2026-05-01T12:00:00.000Z',
    active_delegation_root: delegationRoot,
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

describe('offline verifier: golden valid receipt', () => {
  const golden = buildGoldenValid()
  const ctx = okContext(golden.receipt.agent_did, golden.receipt.delegation_chain_root)

  it('accepts a clean receipt with both layers, no network', () => {
    const r = verifyOffline(golden.receipt, { context: ctx })
    assert.equal(r.verdict, 'accept')
    assert.equal(r.cryptoValid, true)
    assert.equal(r.contextChecked, true)
    assert.equal(r.contextValid, true)
    assert.equal(r.reason, undefined)
    assert.equal(fetchCalled, false, 'verify must not touch the network')
  })

  it('emits the W2-A1 evidence descriptor as a verifier OUTPUT', () => {
    const r = verifyOffline(golden.receipt, { context: ctx })
    const d = r.descriptor
    assert.equal(d.version, 'aps:evidence-descriptor:v1')
    assert.equal(d.receiptId, golden.receipt.receipt_id)
    // The verifier seeds one signature fact: the receipt's own signer.
    assert.equal(d.signerSet.length, 1)
    assert.equal(d.signerSet[0], golden.receipt.signer_did)
    assert.equal(d.signerClaims[0].signatureValid, true)
    assert.equal(d.validSignatureCount, 1)
    assert.equal(d.absentSignerCount, 0)
    // One signer, no witnesses: nothing to corroborate. Belnap lattice
    // point, never a scalar. This is a verifier OUTPUT, not a receipt field.
    assert.equal(d.corroborationStatus, 'not_applicable')
    // Dogfooded scope. Hard claims language: it does not assert truth.
    assert.ok(d.scope_of_claim.does_not_assert.length >= 1)
  })

  it('runs the crypto layer only when no context is supplied, and says so', () => {
    const r = verifyOffline(golden.receipt)
    assert.equal(r.verdict, 'accept')
    assert.equal(r.cryptoValid, true)
    assert.equal(r.contextChecked, false)
    assert.equal(r.contextValid, false)
    assert.equal(fetchCalled, false)
  })

  it('reports independence when the caller adds an independent co-signer', () => {
    const r = verifyOffline(golden.receipt, {
      context: ctx,
      descriptor: {
        signatures: [
          {
            signerId: 'cosigner-pubkey-hex',
            role: 'notary',
            claim: 'outcome',
            valid: true,
            chainsTo: ['notary-root'],
          },
        ],
        // The receipt signer chains to a different root than the notary.
        anchorEdges: [],
      },
    })
    // Two signers, both valid, no shared root: corroboration stands.
    assert.equal(r.descriptor.signerSet.length, 2)
    assert.equal(r.descriptor.fullyIndependent, true)
    assert.equal(r.descriptor.independentSignerCount, 2)
    assert.equal(r.descriptor.corroborationStatus, 'pass')
  })

  it('does NOT credit independence to witnesses sharing the same root', () => {
    const r = verifyOffline(golden.receipt, {
      context: ctx,
      descriptor: {
        signatures: [
          {
            signerId: 'cosigner-pubkey-hex',
            role: 'co_signer',
            claim: 'outcome',
            valid: true,
            // Same root as the action signer: self-attestation, not
            // independent corroboration.
            chainsTo: [golden.receipt.signer_did],
          },
        ],
        // Make the receipt signer's anchor equal the shared root.
        anchorEdges: [[golden.receipt.signer_did, golden.receipt.signer_did]],
      },
    })
    assert.equal(r.descriptor.signerSet.length, 2)
    // Both signers reduce to the receipt signer's identity as root, so they
    // share a root and are not independent.
    assert.equal(r.descriptor.fullyIndependent, false)
    assert.equal(r.descriptor.corroborationStatus, 'unknown')
  })

  it('surfaces a witness conflict as a fail status (first-class state)', () => {
    const conflict: WitnessConflict = {
      conflictId: 'wc-1',
      receiptId: golden.receipt.receipt_id,
      gatewayAssertion: 'success',
      witnessAssertion: 'inconsistent',
      autoDisputeCandidate: true,
      createdAt: '2026-05-01T12:00:01.000Z',
    }
    const r = verifyOffline(golden.receipt, {
      context: ctx,
      descriptor: { witnessConflicts: [conflict] },
    })
    assert.equal(r.descriptor.hasWitnessConflict, true)
    assert.deepEqual(r.descriptor.witnessConflictIds, ['wc-1'])
    assert.equal(r.descriptor.corroborationStatus, 'fail')
  })
})

describe('offline verifier: negative fixtures (composed crypto + context)', () => {
  const negatives = buildNegatives()

  for (const neg of negatives) {
    it(`rejects ${neg.id} for ${neg.expected_reject_reason} at the ${neg.layer} layer`, () => {
      const r = verifyOffline(neg.receipt, { context: neg.context })
      assert.equal(r.verdict, 'reject', `${neg.id} must be rejected`)
      assert.equal(
        r.reason,
        neg.expected_reject_reason,
        `${neg.id} reason mismatch`,
      )
      assert.equal(
        r.rejectedAtLayer,
        neg.layer,
        `${neg.id} layer mismatch`,
      )
      assert.equal(fetchCalled, false, 'rejection must not touch the network')
      // Even on rejection, a descriptor is always present.
      assert.equal(r.descriptor.version, 'aps:evidence-descriptor:v1')
    })
  }

  it('marks a failed signature as a fail descriptor status', () => {
    const sigBad = negatives.find((n) => n.id === 'NEG-SIGNATURE-INVALID')
    assert.ok(sigBad)
    const r = verifyOffline(sigBad!.receipt, { context: sigBad!.context })
    assert.equal(r.descriptor.allSignaturesValid, false)
    assert.equal(r.descriptor.corroborationStatus, 'fail')
  })

  it('short-circuits at crypto: a tampered receipt never reaches context', () => {
    const mismatch = negatives.find((n) => n.id === 'NEG-MISMATCHED-HASH')
    assert.ok(mismatch)
    const r = verifyOffline(mismatch!.receipt, { context: mismatch!.context })
    assert.equal(r.rejectedAtLayer, 'crypto')
    assert.equal(r.contextChecked, false)
  })
})
