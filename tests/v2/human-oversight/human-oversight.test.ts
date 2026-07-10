// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Human oversight as evidence (W2-B5): tests
// ══════════════════════════════════════════════════════════════════
// Covers: a co-signed (human + agent) receipt proves both signatures
// over ONE canonical body; tamper rejection; break_glass over a
// forbidden class is rejected; approval-reference scheme classification;
// independence derived from the key/DID graph (sharesRoot); the verifier
// -derived advisory scalar; byte-stability of a receipt that omits the
// slots; and the dogfooded ScopeOfClaim. The bilateral case reuses the
// existing src/core/bilateral-receipt.ts co-sign and is exercised here
// only to confirm the general-path slot does not rebuild it.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  signAsCoSigner,
  attachCoSigner,
  canonicalCoSignBody,
  verifyCoSignatures,
  validateBreakGlass,
  classifyApprovalScheme,
  deriveOversightDescriptor,
  computeIndependence,
  isSignerIndependent,
  buildOversightScopeOfClaim,
} from '../../../src/v2/human-oversight/index.js'
import type {
  CoSignerEntry,
  BreakGlass,
  HumanOversightSlots,
} from '../../../src/v2/human-oversight/index.js'
import { generateKeyPair, sign, verify } from '../../../src/crypto/keys.js'
import { canonicalize } from '../../../src/core/canonical.js'
import {
  createBilateralReceipt,
  verifyBilateralReceipt,
} from '../../../src/core/bilateral-receipt.js'

// A general (NON-bilateral) receipt body: a signed declaration with an
// approval reference. The co_signer slot is added on top.
function generalReceipt(extra: Partial<HumanOversightSlots> = {}) {
  return {
    claim_type: 'aps:action:v1',
    receipt_id: 'rcpt-general-001',
    timestamp: '2026-05-31T12:00:00.000Z',
    subject: 'transfer-of-record-42',
    ...extra,
  } as Record<string, unknown>
}

describe('W2-B5 co-sign (general path): human + agent over one body', () => {
  it('a co-signed receipt proves both the human and agent signatures over one body', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()

    // Receipt carries an approval_reference the human is signing over.
    const base = generalReceipt({
      approval_reference: { requestId: 'approval_abc123def456' },
    })

    const humanEntry = signAsCoSigner({
      receipt: base,
      role: 'human',
      keyClass: 'human',
      privateKey: human.privateKey,
      publicKey: human.publicKey,
      did: 'did:key:human',
    })
    const withHuman = attachCoSigner(base, humanEntry)

    const agentEntry = signAsCoSigner({
      receipt: withHuman,
      role: 'agent',
      keyClass: 'operations',
      privateKey: agent.privateKey,
      publicKey: agent.publicKey,
      did: 'did:key:agent',
    })
    const receipt = attachCoSigner(withHuman, agentEntry)

    // Both signatures cover the IDENTICAL canonical body.
    const canonical = canonicalCoSignBody(receipt)
    assert.equal(verify(canonical, humanEntry.signature, human.publicKey), true)
    assert.equal(verify(canonical, agentEntry.signature, agent.publicKey), true)

    const facts = verifyCoSignatures(receipt)
    assert.equal(facts.length, 2)
    assert.equal(facts[0].status, 'pass')
    assert.equal(facts[1].status, 'pass')
    assert.equal(facts[0].role, 'human')
    assert.equal(facts[1].role, 'agent')

    const desc = deriveOversightDescriptor(receipt)
    assert.equal(desc.humanSignaturePresent, true)
    assert.equal(desc.approvalReference.present, true)
    assert.equal(desc.approvalReference.scheme, 'charter_uuid')
  })

  it('both co-signers sign the SAME canonical string (sibling-field discipline)', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const base = generalReceipt()

    const h = signAsCoSigner({
      receipt: base, role: 'human', keyClass: 'human',
      privateKey: human.privateKey, publicKey: human.publicKey,
    })
    const withH = attachCoSigner(base, h)
    const a = signAsCoSigner({
      receipt: withH, role: 'agent', keyClass: 'operations',
      privateKey: agent.privateKey, publicKey: agent.publicKey,
    })
    const receipt = attachCoSigner(withH, a)

    // The canonical body the human signed (no co_signer) equals the
    // canonical body the agent signed (co_signer + version stripped).
    assert.equal(canonicalCoSignBody(base), canonicalCoSignBody(receipt))
  })

  it('NEGATIVE: a tampered body fails both co-signatures', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const base = generalReceipt()

    const h = signAsCoSigner({
      receipt: base, role: 'human', keyClass: 'human',
      privateKey: human.privateKey, publicKey: human.publicKey,
    })
    const withH = attachCoSigner(base, h)
    const a = signAsCoSigner({
      receipt: withH, role: 'agent', keyClass: 'operations',
      privateKey: agent.privateKey, publicKey: agent.publicKey,
    })
    const receipt = attachCoSigner(withH, a) as Record<string, unknown>

    // Mutate a body field AFTER signing.
    receipt.subject = 'transfer-of-record-99'
    const facts = verifyCoSignatures(receipt)
    assert.equal(facts[0].status, 'fail')
    assert.equal(facts[1].status, 'fail')

    const desc = deriveOversightDescriptor(receipt)
    assert.equal(desc.humanSignaturePresent, false)
    assert.equal(desc.advisory_independent_human_oversight, false)
  })

  it('NEGATIVE: a wrong public key yields fail, an absent key yields unknown (Belnap)', () => {
    const human = generateKeyPair()
    const attacker = generateKeyPair()
    const base = generalReceipt()
    const h = signAsCoSigner({
      receipt: base, role: 'human', keyClass: 'human',
      privateKey: human.privateKey, publicKey: human.publicKey,
    })
    const receipt = attachCoSigner(base, h)

    // Verify against the attacker key supplied by resolution -> fail.
    const wrong = verifyCoSignatures(receipt, [{ publicKey: attacker.publicKey }])
    assert.equal(wrong[0].status, 'fail')

    // Empty entry publicKey and no resolution -> unknown, never silent pass.
    const blanked = attachCoSigner(base, { ...h, publicKey: '' })
    const facts = verifyCoSignatures(blanked)
    assert.equal(facts[0].status, 'unknown')
  })
})

describe('W2-B5 break_glass: format with forbidden-class rejection', () => {
  const valid: BreakGlass = {
    reason: 'pager outage, manual override to unblock incident',
    approved_by: 'did:key:oncall-human',
    expires_at: '2099-01-01T00:00:00.000Z',
    post_review_required: true,
  }

  it('a well-formed, in-force, allowed-class declaration is accepted', () => {
    const f = validateBreakGlass(valid)
    assert.equal(f.wellFormed, true)
    assert.equal(f.inForce, true)
    assert.equal(f.classAllowed, true)
    assert.equal(f.postReviewRequired, true)
    assert.equal(f.rejections.length, 0)
  })

  it('NEGATIVE: a break_glass on a forbidden class is rejected', () => {
    const bg: BreakGlass = { ...valid, action_class: 'irreversible_funds_transfer' }
    const f = validateBreakGlass(bg, {
      forbiddenClasses: ['irreversible_funds_transfer', 'key_revocation'],
    })
    assert.equal(f.classAllowed, false)
    assert.ok(f.rejections.some(r => r.includes('forbidden class')))

    // And it sinks the advisory scalar on a receipt carrying it.
    const human = generateKeyPair()
    const base = generalReceipt({ break_glass: bg })
    const h = signAsCoSigner({
      receipt: base, role: 'human', keyClass: 'human',
      privateKey: human.privateKey, publicKey: human.publicKey,
    })
    const receipt = attachCoSigner(base, h)
    const desc = deriveOversightDescriptor(receipt, {
      forbiddenBreakGlassClasses: ['irreversible_funds_transfer'],
    })
    assert.equal(desc.breakGlass.classAllowed, false)
    assert.equal(desc.advisory_independent_human_oversight, false)
  })

  it('NEGATIVE: an expired declaration is not in force', () => {
    const f = validateBreakGlass({ ...valid, expires_at: '2000-01-01T00:00:00.000Z' })
    assert.equal(f.inForce, false)
    assert.ok(f.rejections.some(r => r.includes('expired')))
  })

  it('NEGATIVE: a missing required field is not well formed', () => {
    const bad = { reason: '', approved_by: 'x', expires_at: valid.expires_at } as unknown as BreakGlass
    const f = validateBreakGlass(bad)
    assert.equal(f.wellFormed, false)
    assert.ok(f.rejections.length > 0)
  })
})

describe('W2-B5 approval_reference: match an existing id scheme, coin no third', () => {
  it('classifies the commerce hex and charter uuid schemes, and flags unrecognized', () => {
    assert.equal(classifyApprovalScheme('approval-deadbeef01'), 'commerce_hex')
    assert.equal(classifyApprovalScheme('approval_abc123def456'), 'charter_uuid')
    assert.equal(classifyApprovalScheme('appr0val-XYZ'), 'unrecognized')
    assert.equal(classifyApprovalScheme('ticket-123'), 'unrecognized')
  })
})

describe('W2-B5 independence: derived from the key and DID graph (sharesRoot)', () => {
  it('two signers sharing a root are NOT independent; the advisory scalar drops', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const base = generalReceipt()
    const h = signAsCoSigner({
      receipt: base, role: 'human', keyClass: 'human',
      privateKey: human.privateKey, publicKey: human.publicKey, did: 'did:web:gw',
    })
    const withH = attachCoSigner(base, h)
    const a = signAsCoSigner({
      receipt: withH, role: 'agent', keyClass: 'operations',
      privateKey: agent.privateKey, publicKey: agent.publicKey, did: 'did:web:gw',
    })
    const receipt = attachCoSigner(withH, a)

    // sharesRoot relation: both DIDs sit under the same gateway controller.
    const sharesRoot = (x: CoSignerEntry, y: CoSignerEntry) =>
      x.did === y.did && x.did === 'did:web:gw'

    const desc = deriveOversightDescriptor(receipt, { sharesRoot })
    assert.equal(desc.allSignersIndependent, false)
    assert.equal(desc.independence[0].sharesRoot, true)
    // human verified, but it shares a root with the agent -> not independent.
    assert.equal(desc.humanSignaturePresent, true)
    assert.equal(desc.advisory_independent_human_oversight, false)
  })

  it('independent human + agent yields an independent-oversight advisory true', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const base = generalReceipt()
    const h = signAsCoSigner({
      receipt: base, role: 'human', keyClass: 'human',
      privateKey: human.privateKey, publicKey: human.publicKey, did: 'did:key:human',
    })
    const withH = attachCoSigner(base, h)
    const a = signAsCoSigner({
      receipt: withH, role: 'agent', keyClass: 'operations',
      privateKey: agent.privateKey, publicKey: agent.publicKey, did: 'did:key:agent',
    })
    const receipt = attachCoSigner(withH, a)

    // Default conservative graph: distinct keys + distinct DIDs -> independent.
    const desc = deriveOversightDescriptor(receipt)
    assert.equal(desc.allSignersIndependent, true)
    assert.equal(desc.advisory_independent_human_oversight, true)
  })

  it('computeIndependence and isSignerIndependent agree on the default graph', () => {
    const a: CoSignerEntry = { publicKey: 'aa', role: 'human', keyClass: 'human', signedAt: 't', signature: 's' }
    const b: CoSignerEntry = { publicKey: 'bb', role: 'agent', keyClass: 'op', signedAt: 't', signature: 's' }
    const dup: CoSignerEntry = { publicKey: 'aa', role: 'gateway', keyClass: 'gw', signedAt: 't', signature: 's' }

    const indep = computeIndependence([a, b])
    assert.equal(indep.allIndependent, true)

    const shared = computeIndependence([a, dup])
    assert.equal(shared.allIndependent, false)
    assert.equal(isSignerIndependent(a, [a, b]), true)
    assert.equal(isSignerIndependent(a, [a, dup]), false)
  })
})

describe('W2-B5 byte-stability: a receipt that omits the slots is unchanged', () => {
  it('canonicalize of a slot-free receipt equals canonicalCoSignBody of it', () => {
    const base = generalReceipt()
    // No co_signer, no version: the co-sign body is just the receipt.
    assert.equal(canonicalize(base), canonicalCoSignBody(base))
  })

  it('omitting all three slots leaves the descriptor reporting absence, not failure', () => {
    const base = generalReceipt()
    const desc = deriveOversightDescriptor(base)
    assert.equal(desc.coSignatures.length, 0)
    assert.equal(desc.humanSignaturePresent, false)
    assert.equal(desc.approvalReference.present, false)
    assert.equal(desc.breakGlass.present, false)
    assert.equal(desc.advisory_independent_human_oversight, false)
  })
})

describe('W2-B5 bilateral case reuses the existing co-sign (not rebuilt here)', () => {
  it('a bilateral interaction outcome uses verifyBilateralReceipt verbatim', () => {
    const req = generateKeyPair()
    const srv = generateKeyPair()
    const receipt = createBilateralReceipt({
      requestingAgentId: 'agent-req',
      servingAgentId: 'agent-srv',
      outcome: {
        toolName: 'fetch',
        requestHash: 'a'.repeat(64),
        responseHash: 'b'.repeat(64),
        status: 'success',
        summary: 'ok',
      },
      requestedAt: '2026-05-31T11:00:00.000Z',
      completedAt: '2026-05-31T11:00:01.000Z',
      requestingAgentPrivateKey: req.privateKey,
      servingAgentPrivateKey: srv.privateKey,
    })
    const v = verifyBilateralReceipt(receipt, req.publicKey, srv.publicKey)
    assert.equal(v.valid, true)
    assert.equal(v.outcomeConsistent, true)
  })
})

describe('W2-B5 ScopeOfClaim dogfood', () => {
  it('an independent verified human yields a non-self-attested scope', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const base = generalReceipt()
    const h = signAsCoSigner({
      receipt: base, role: 'human', keyClass: 'human',
      privateKey: human.privateKey, publicKey: human.publicKey, did: 'did:key:h',
    })
    const withH = attachCoSigner(base, h)
    const a = signAsCoSigner({
      receipt: withH, role: 'agent', keyClass: 'op',
      privateKey: agent.privateKey, publicKey: agent.publicKey, did: 'did:key:a',
    })
    const receipt = attachCoSigner(withH, a)
    const desc = deriveOversightDescriptor(receipt)
    const scope = buildOversightScopeOfClaim(desc)

    assert.equal(scope.self_attested, false)
    assert.equal(scope.capture_mode, 'gateway_observed')
    assert.ok(scope.does_not_assert.some(s => s.includes('understood')))
    assert.ok(scope.does_not_assert.some(s => s.includes('workflow outside')))
  })

  it('absent independent oversight, the scope is self-attested', () => {
    const scope = buildOversightScopeOfClaim()
    assert.equal(scope.self_attested, true)
    assert.equal(scope.capture_mode, 'self_attested')
  })
})
