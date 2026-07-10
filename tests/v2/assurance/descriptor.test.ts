// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════════
// Evidence Descriptor - tests (W2-A1)
// ══════════════════════════════════════════════════════════════════════
// Proof box for this module:
//
//   Proves: the descriptor reports exactly what evidence is
//     cryptographically present on a receipt (which signer signed which
//     claim, whether each signature verified, each witness observation
//     basis, witness-conflict presence) and how independent the signers are
//     (derived from the key/DID graph via sharesRoot); and that the single
//     advisory scalar is reproducible PURELY from the descriptor.
//
//   Does NOT prove: that any external effect described by the receipt
//     actually occurred (that is W2-A2), nor that the outcome is true. The
//     advisory scalar is a relying-party-policy view, never an assertion of
//     truth, and is never read from the receipt.
// ══════════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createBilateralReceipt,
  verifyBilateralReceipt,
} from '../../../src/index.js'
import type { InteractionOutcome } from '../../../src/index.js'
import type { WitnessConflict } from '../../../src/types/gateway.js'
import {
  buildEvidenceDescriptor,
  computeAdvisoryScalar,
  generalizeBilateralVerification,
  sharesRoot,
  allPairwiseIndependence,
  independentSignerCount,
  DEFAULT_OBSERVATION_WEIGHTS,
  type CheckedSignature,
  type SignerGraph,
} from '../../../src/v2/assurance/descriptor.js'

const agentA = generateKeyPair() // requesting agent
const agentB = generateKeyPair() // serving agent
const gateway = generateKeyPair() // witnessing gateway
const stranger = generateKeyPair()

function makeOutcome(overrides?: Partial<InteractionOutcome>): InteractionOutcome {
  return {
    toolName: 'web_search',
    requestHash: 'abc123',
    responseHash: 'def456',
    status: 'success',
    summary: 'Searched for weather data',
    ...overrides,
  }
}

// ══════════════════════════════════════════════════════════════════════
// sharesRoot - the sharp independence metric (key/DID graph)
// ══════════════════════════════════════════════════════════════════════

describe('sharesRoot - signer independence from the key/DID graph', () => {
  it('two signers chaining to the same gateway root are NOT independent', () => {
    const rel = sharesRoot(
      { id: 'did:notary-1', chainsTo: ['gateway-root-X'] },
      { id: 'did:notary-2', chainsTo: ['gateway-root-X'] }
    )
    assert.equal(rel.independent, false)
    assert.deepEqual(rel.sharedRoots, ['gateway-root-X'])
  })

  it('two signers chaining to different roots ARE independent', () => {
    const rel = sharesRoot(
      { id: 'did:notary-1', chainsTo: ['root-A'] },
      { id: 'did:notary-2', chainsTo: ['root-B'] }
    )
    assert.equal(rel.independent, true)
    assert.deepEqual(rel.sharedRoots, [])
  })

  it('is reflexive: a signer always shares a root with itself', () => {
    const node = { id: 'did:x', chainsTo: ['root-A'] }
    const rel = sharesRoot(node, node)
    assert.equal(rel.independent, false)
  })

  it('is symmetric: order does not change the answer', () => {
    const a = { id: 'a', chainsTo: ['root-A'] }
    const b = { id: 'b', chainsTo: ['root-A'] }
    assert.equal(sharesRoot(a, b).independent, sharesRoot(b, a).independent)
  })

  it('anchor equivalence collapses differently-labelled same root', () => {
    // Two anchors that are really the same root, declared via anchorEdges.
    const rel = sharesRoot(
      { id: 'a', chainsTo: ['gateway-root'] },
      { id: 'b', chainsTo: ['jwks-origin'] },
      { anchorEdges: [['gateway-root', 'jwks-origin']] }
    )
    assert.equal(rel.independent, false)
  })

  it('anchorless signers default to anchoring their own identity (distinct = independent)', () => {
    const rel = sharesRoot({ id: 'a' }, { id: 'b' })
    assert.equal(rel.independent, true)
  })

  it('independence is per-pair, NOT transitive across signers', () => {
    // A~B share root-1, B~C share root-2; A and C share nothing.
    const graph: SignerGraph = {
      nodes: [
        { id: 'A', chainsTo: ['root-1'] },
        { id: 'B', chainsTo: ['root-1', 'root-2'] },
        { id: 'C', chainsTo: ['root-2'] },
      ],
    }
    const rels = allPairwiseIndependence(graph)
    const ac = rels.find((r) => r.signerA === 'A' && r.signerB === 'C')
    assert.ok(ac)
    assert.equal(ac!.independent, true)
  })

  it('independentSignerCount counts signers independent of every peer', () => {
    // notary-1 and notary-2 share gateway-root; external anchors are alone.
    const graph: SignerGraph = {
      nodes: [
        { id: 'notary-1', chainsTo: ['gateway-root'] },
        { id: 'notary-2', chainsTo: ['gateway-root'] },
        { id: 'external', chainsTo: ['independent-anchor'] },
      ],
    }
    // 'external' is independent of both; neither notary is independent of all.
    assert.equal(independentSignerCount(graph), 1)
  })
})

// ══════════════════════════════════════════════════════════════════════
// generalizeBilateralVerification - extend verifyBilateralReceipt
// ══════════════════════════════════════════════════════════════════════

describe('generalizeBilateralVerification - generalize, do not duplicate', () => {
  it('reshapes a verified bilateral receipt into signer/claim facts', () => {
    const receipt = createBilateralReceipt({
      requestingAgentId: 'agent-a',
      servingAgentId: 'agent-b',
      outcome: makeOutcome(),
      requestedAt: '2026-04-01T10:00:00Z',
      completedAt: '2026-04-01T10:00:01Z',
      requestingAgentPrivateKey: agentA.privateKey,
      servingAgentPrivateKey: agentB.privateKey,
      gatewayPrivateKey: gateway.privateKey,
    })
    const verification = verifyBilateralReceipt(
      receipt,
      agentA.publicKey,
      agentB.publicKey,
      gateway.publicKey
    )
    assert.equal(verification.valid, true)

    const sigs = generalizeBilateralVerification({
      verification,
      requestingAgentId: agentA.publicKey,
      servingAgentId: agentB.publicKey,
      gatewayId: gateway.publicKey,
      anchors: {
        [agentA.publicKey]: ['root-agent-a'],
        [agentB.publicKey]: ['root-agent-b'],
        [gateway.publicKey]: ['gateway-root'],
      },
    })
    assert.equal(sigs.length, 3)
    assert.ok(sigs.every((s) => s.valid === true))
    assert.equal(sigs.find((s) => s.role === 'gateway_witness')?.claim, 'gateway-countersignature')
  })

  it('preserves the absent-gateway tri-state as null, not false', () => {
    const receipt = createBilateralReceipt({
      requestingAgentId: 'agent-a',
      servingAgentId: 'agent-b',
      outcome: makeOutcome(),
      requestedAt: '2026-04-01T10:00:00Z',
      completedAt: '2026-04-01T10:00:01Z',
      requestingAgentPrivateKey: agentA.privateKey,
      servingAgentPrivateKey: agentB.privateKey,
    })
    const verification = verifyBilateralReceipt(receipt, agentA.publicKey, agentB.publicKey)
    assert.equal(verification.gatewaySignatureValid, null)

    const sigs = generalizeBilateralVerification({
      verification,
      requestingAgentId: agentA.publicKey,
      servingAgentId: agentB.publicKey,
      gatewayId: gateway.publicKey,
    })
    const gw = sigs.find((s) => s.role === 'gateway_witness')
    assert.equal(gw?.valid, null)
  })
})

// ══════════════════════════════════════════════════════════════════════
// buildEvidenceDescriptor - the verifier OUTPUT (lattice, not ladder)
// ══════════════════════════════════════════════════════════════════════

describe('buildEvidenceDescriptor - mechanical facts only', () => {
  it('end-to-end: a genuine bilateral receipt yields a pass descriptor with independent co-signers', () => {
    const receipt = createBilateralReceipt({
      requestingAgentId: 'agent-a',
      servingAgentId: 'agent-b',
      outcome: makeOutcome(),
      requestedAt: '2026-04-01T10:00:00Z',
      completedAt: '2026-04-01T10:00:01Z',
      requestingAgentPrivateKey: agentA.privateKey,
      servingAgentPrivateKey: agentB.privateKey,
    })
    const verification = verifyBilateralReceipt(receipt, agentA.publicKey, agentB.publicKey)
    const sigs = generalizeBilateralVerification({
      verification,
      requestingAgentId: agentA.publicKey,
      servingAgentId: agentB.publicKey,
      anchors: {
        [agentA.publicKey]: ['root-agent-a'],
        [agentB.publicKey]: ['root-agent-b'],
      },
    })
    const descriptor = buildEvidenceDescriptor({ receiptId: receipt.receiptId, signatures: sigs })

    assert.equal(descriptor.version, 'aps:evidence-descriptor:v1')
    assert.equal(descriptor.receiptId, receipt.receiptId)
    assert.equal(descriptor.allSignaturesValid, true)
    assert.equal(descriptor.validSignatureCount, 2)
    assert.equal(descriptor.absentSignerCount, 0)
    assert.equal(descriptor.fullyIndependent, true)
    assert.equal(descriptor.independentSignerCount, 2)
    assert.equal(descriptor.corroborationStatus, 'pass')
    assert.deepEqual(
      descriptor.signerSet,
      [agentA.publicKey, agentB.publicKey].sort()
    )
  })

  it('HIGH independence: genuinely independent co-signers (different roots)', () => {
    const sigs: CheckedSignature[] = [
      { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
      { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
    ]
    const descriptor = buildEvidenceDescriptor({ receiptId: 'r-high', signatures: sigs })
    assert.equal(descriptor.fullyIndependent, true)
    assert.equal(descriptor.independentSignerCount, 2)
    assert.equal(descriptor.corroborationStatus, 'pass')
    assert.equal(descriptor.scope_of_claim.self_attested, false)
  })

  it('LOW independence: witnesses sharing the gateway root are still self-attestation', () => {
    const sigs: CheckedSignature[] = [
      { signerId: 'notary-1', claim: 'outcome', valid: true, chainsTo: ['gateway-root'] },
      { signerId: 'notary-2', claim: 'outcome', valid: true, chainsTo: ['gateway-root'] },
    ]
    const descriptor = buildEvidenceDescriptor({ receiptId: 'r-low', signatures: sigs })
    // Two signers, both valid, but they share the gateway root: no independent
    // corroboration. Belnap 'unknown', never 'pass'.
    assert.equal(descriptor.allSignaturesValid, true)
    assert.equal(descriptor.fullyIndependent, false)
    assert.equal(descriptor.independentSignerCount, 0)
    assert.equal(descriptor.corroborationStatus, 'unknown')
    assert.equal(descriptor.scope_of_claim.self_attested, true)
  })

  it('NEGATIVE: a failed signature drives corroborationStatus to fail', () => {
    const sigs: CheckedSignature[] = [
      { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
      { signerId: 'B', claim: 'outcome', valid: false, chainsTo: ['root-B'] },
    ]
    const descriptor = buildEvidenceDescriptor({ receiptId: 'r-fail', signatures: sigs })
    assert.equal(descriptor.allSignaturesValid, false)
    assert.equal(descriptor.corroborationStatus, 'fail')
  })

  it('NEGATIVE: a WitnessConflict surfaces in the descriptor and forces fail', () => {
    const conflict: WitnessConflict = {
      conflictId: 'conflict-1',
      receiptId: 'r-conflict',
      gatewayAssertion: 'success',
      witnessAssertion: 'inconsistent',
      divergenceDetails: 'witness saw a different response hash',
      autoDisputeCandidate: true,
      createdAt: '2026-04-01T10:05:00Z',
    }
    const sigs: CheckedSignature[] = [
      { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
      { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
    ]
    const descriptor = buildEvidenceDescriptor({
      receiptId: 'r-conflict',
      signatures: sigs,
      witnessConflicts: [conflict],
    })
    assert.equal(descriptor.hasWitnessConflict, true)
    assert.deepEqual(descriptor.witnessConflictIds, ['conflict-1'])
    assert.equal(descriptor.corroborationStatus, 'fail')
  })

  it('lone self-signature is not_applicable (nothing to corroborate)', () => {
    const sigs: CheckedSignature[] = [
      { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
    ]
    const descriptor = buildEvidenceDescriptor({ receiptId: 'r-lone', signatures: sigs })
    assert.equal(descriptor.corroborationStatus, 'not_applicable')
    assert.equal(descriptor.scope_of_claim.self_attested, true)
  })

  it('records witness observation basis verbatim (existing five-valued enum)', () => {
    const sigs: CheckedSignature[] = [
      { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
      { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
    ]
    const descriptor = buildEvidenceDescriptor({
      receiptId: 'r-obs',
      signatures: sigs,
      witnessObservations: [
        { witnessId: 'w-2', observationBasis: 'receipt_only' },
        { witnessId: 'w-1', observationBasis: 'direct_observation', divergence: 0 },
      ],
    })
    // Sorted by witnessId.
    assert.deepEqual(
      descriptor.witnessObservations.map((w) => w.witnessId),
      ['w-1', 'w-2']
    )
    assert.equal(descriptor.witnessObservations[0].observationBasis, 'direct_observation')
  })

  it('absent signer (tri-state null) does not count as a failure', () => {
    const sigs: CheckedSignature[] = [
      { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
      { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
      { signerId: 'GW', claim: 'gateway-countersignature', valid: null, chainsTo: ['gateway-root'] },
    ]
    const descriptor = buildEvidenceDescriptor({ receiptId: 'r-absent', signatures: sigs })
    assert.equal(descriptor.absentSignerCount, 1)
    assert.equal(descriptor.validSignatureCount, 2)
    // Present signatures all valid, an absent signer is not a failure.
    assert.notEqual(descriptor.corroborationStatus, 'fail')
  })

  it('is pure: identical input yields a deeply-equal descriptor', () => {
    const sigs: CheckedSignature[] = [
      { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
      { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
    ]
    const d1 = buildEvidenceDescriptor({ receiptId: 'r-pure', signatures: sigs })
    const d2 = buildEvidenceDescriptor({ receiptId: 'r-pure', signatures: sigs })
    assert.deepEqual(d1, d2)
  })

  it('reads NO issuer-written assurance field (none exists on the input type)', () => {
    // The builder input has no assurance/evidence_assurance slot. Even if a
    // caller smuggles extra keys onto a signature object, they are ignored:
    // only signerId/role/claim/valid/chainsTo are read.
    const rogue = {
      signerId: 'A',
      claim: 'outcome',
      valid: true,
      chainsTo: ['root-A'],
      // not part of CheckedSignature - must have no effect
      evidence_assurance: 'L4',
      assurance: 5,
    } as unknown as CheckedSignature
    const clean: CheckedSignature = { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] }
    const descriptor = buildEvidenceDescriptor({ receiptId: 'r-rogue', signatures: [rogue, clean] })
    // Status is driven purely by mechanical facts, not the smuggled field.
    assert.equal(descriptor.corroborationStatus, 'pass')
    assert.ok(!('evidence_assurance' in descriptor))
    assert.ok(!('assurance' in descriptor))
  })
})

// ══════════════════════════════════════════════════════════════════════
// computeAdvisoryScalar - the ONE relying-party-policy scalar
// ══════════════════════════════════════════════════════════════════════

describe('computeAdvisoryScalar - relying-party-policy, reproducible from the descriptor', () => {
  it('is labelled a relying-party-policy output, never a truth assertion', () => {
    const descriptor = buildEvidenceDescriptor({
      receiptId: 'r-1',
      signatures: [
        { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
        { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
      ],
    })
    const scalar = computeAdvisoryScalar(descriptor)
    assert.equal(scalar.kind, 'relying-party-policy')
    assert.equal(scalar.basis, 'pass')
    assert.ok(scalar.value > 0 && scalar.value <= 1)
  })

  it('is reproducible PURELY from the descriptor (no receipt involved)', () => {
    const descriptor = buildEvidenceDescriptor({
      receiptId: 'r-2',
      signatures: [
        { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
        { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
      ],
      witnessObservations: [{ witnessId: 'w-1', observationBasis: 'direct_observation' }],
    })
    // Recompute twice from the SAME descriptor object: identical scalar.
    const s1 = computeAdvisoryScalar(descriptor)
    const s2 = computeAdvisoryScalar(descriptor)
    assert.deepEqual(s1, s2)

    // And serialize/deserialize the descriptor (proving the scalar needs
    // nothing but the descriptor's own fields) - still identical.
    const roundTripped = JSON.parse(JSON.stringify(descriptor))
    const s3 = computeAdvisoryScalar(roundTripped)
    assert.deepEqual(s1, s3)
  })

  it('self-attestation (shared root) scores strictly lower than independent corroboration', () => {
    const independent = buildEvidenceDescriptor({
      receiptId: 'r-ind',
      signatures: [
        { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
        { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
      ],
    })
    const selfAttested = buildEvidenceDescriptor({
      receiptId: 'r-self',
      signatures: [
        { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['gateway-root'] },
        { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['gateway-root'] },
      ],
    })
    const sInd = computeAdvisoryScalar(independent)
    const sSelf = computeAdvisoryScalar(selfAttested)
    assert.ok(sSelf.value < sInd.value)
  })

  it('fail status yields a zero scalar', () => {
    const descriptor = buildEvidenceDescriptor({
      receiptId: 'r-fail',
      signatures: [
        { signerId: 'A', claim: 'outcome', valid: false, chainsTo: ['root-A'] },
        { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
      ],
    })
    const scalar = computeAdvisoryScalar(descriptor)
    assert.equal(scalar.value, 0)
    assert.equal(scalar.basis, 'fail')
  })

  it('not_applicable (lone signer) yields a zero scalar', () => {
    const descriptor = buildEvidenceDescriptor({
      receiptId: 'r-lone',
      signatures: [{ signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] }],
    })
    const scalar = computeAdvisoryScalar(descriptor)
    assert.equal(scalar.value, 0)
    assert.equal(scalar.basis, 'not_applicable')
  })

  it('stronger observation basis lifts the pass-band scalar', () => {
    const base = {
      receiptId: 'r-obs',
      signatures: [
        { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
        { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
      ] as CheckedSignature[],
    }
    const strong = buildEvidenceDescriptor({
      ...base,
      witnessObservations: [{ witnessId: 'w', observationBasis: 'direct_observation' }],
    })
    const weak = buildEvidenceDescriptor({
      ...base,
      witnessObservations: [{ witnessId: 'w', observationBasis: 'receipt_only' }],
    })
    assert.ok(computeAdvisoryScalar(strong).value > computeAdvisoryScalar(weak).value)
  })

  it('default observation weights cover all five WitnessObservationBasis values', () => {
    const keys = Object.keys(DEFAULT_OBSERVATION_WEIGHTS).sort()
    assert.deepEqual(keys, [
      'direct_observation',
      'independent_recomputation',
      'log_derived',
      'receipt_only',
      'replay_verification',
    ])
  })

  it('scalar is never read from the receipt: same descriptor with a different receiptId is identical scalar', () => {
    const d1 = buildEvidenceDescriptor({
      receiptId: 'receipt-aaa',
      signatures: [
        { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
        { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
      ],
    })
    const d2 = buildEvidenceDescriptor({
      receiptId: 'receipt-zzz',
      signatures: [
        { signerId: 'A', claim: 'outcome', valid: true, chainsTo: ['root-A'] },
        { signerId: 'B', claim: 'outcome', valid: true, chainsTo: ['root-B'] },
      ],
    })
    // The receiptId differs, but the EVIDENCE is identical, so the advisory
    // scalar - a function of evidence, not of receipt identity - matches.
    assert.equal(computeAdvisoryScalar(d1).value, computeAdvisoryScalar(d2).value)
  })
})
