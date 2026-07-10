// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * Tests for audience binding: a versioned, additive `aud` slot on delegation
 * and receipt proofs so a passport issued for recipient A is rejected at B.
 *
 * ── PROOF BOX ──────────────────────────────────────────────────────────────
 * Proves: the issuer named this relying party among the proof's recipients; a
 *         proof minted for A is rejected when checked against B.
 * Does NOT prove: that a NAMED recipient will not misuse what it legitimately
 *         received. Audience restricts WHO may present a proof, not what a
 *         legitimate holder does with it afterward.
 * ───────────────────────────────────────────────────────────────────────────
 *
 * Explicit negative paths: a wrong-audience proof is rejected; a missing aud on
 * an audience-required profile is rejected; the interaction with the cross_chain
 * constraint is consistent (no double-deny, no contradiction).
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  AUDIENCE_BINDING_PROFILE,
  bindAudience,
  matchAudience,
  normalizeRecipients,
  checkAudience,
  audienceToConstraintStatus,
  audienceFailure,
  reconcileAudienceWithCrossChain,
  verifyRequestWithAudience,
} from '../../../src/v2/audience-binding/index.js'
import type {
  AudienceBinding,
  AudienceBearer,
} from '../../../src/v2/audience-binding/index.js'

import {
  createV2Delegation,
  supersedeV2Delegation,
  validateV2Delegation,
  clearV2DelegationStore,
} from '../../../src/v2/delegation-v2.js'
import {
  createBilateralReceipt,
  verifyBilateralReceipt,
} from '../../../src/core/bilateral-receipt.js'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import {
  signRequest,
  APS_REQUEST_BINDING_TAG,
} from '../../../src/v2/transport/rfc9421/index.js'
import type {
  RequestContext,
  SignerKey,
  VerifierKey,
  VerifyPolicy,
} from '../../../src/v2/transport/rfc9421/index.js'
import type { ConstraintFailure } from '../../../src/types/gateway.js'
import type { PolicyContext, V2ScopeDefinition } from '../../../src/v2/types.js'

// ── helpers ─────────────────────────────────────────────────────────────────

function policyContext(): PolicyContext {
  const now = new Date()
  const until = new Date(now.getTime() + 3600_000)
  return {
    policy_version: '2.0',
    values_floor_version: '1.0',
    trust_epoch: 1,
    issuer_id: 'issuer-1',
    created_at: now.toISOString(),
    valid_from: now.toISOString(),
    valid_until: until.toISOString(),
  }
}

const scope: V2ScopeDefinition = { action_categories: ['read'] }

const RECIPIENT_A = 'did:example:recipient-A'
const RECIPIENT_B = 'did:example:recipient-B'

// ══════════════════════════════════════════════════════════════════
// 1. Core membership primitive (reuses OAuth normalize + includes)
// ══════════════════════════════════════════════════════════════════

test('bindAudience produces a versioned, non-empty binding', () => {
  const aud = bindAudience(RECIPIENT_A)
  assert.equal(aud.profile, AUDIENCE_BINDING_PROFILE)
  assert.deepEqual(aud.recipients, [RECIPIENT_A])

  const multi = bindAudience([RECIPIENT_A, RECIPIENT_B])
  assert.deepEqual(multi.recipients, [RECIPIENT_A, RECIPIENT_B])
})

test('bindAudience refuses an empty or ill-formed audience', () => {
  assert.throws(() => bindAudience([]), /empty audience/)
  assert.throws(() => bindAudience(['']), /non-empty strings/)
})

test('normalizeRecipients rejects malformed bindings, accepts well-formed', () => {
  assert.equal(normalizeRecipients(undefined), null)
  assert.equal(
    normalizeRecipients({ profile: 'aps:audience-binding:v1', recipients: [] }),
    null,
  )
  // Wrong profile tag is treated as malformed (forward-compat guard).
  assert.equal(
    normalizeRecipients({
      profile: 'aps:audience-binding:v2' as AudienceBinding['profile'],
      recipients: [RECIPIENT_A],
    }),
    null,
  )
  assert.deepEqual(
    normalizeRecipients(bindAudience([RECIPIENT_A, RECIPIENT_B])),
    [RECIPIENT_A, RECIPIENT_B],
  )
})

test('matchAudience: A is a member, B is not', () => {
  const aud = bindAudience([RECIPIENT_A])
  assert.equal(matchAudience(aud, RECIPIENT_A), true)
  assert.equal(matchAudience(aud, RECIPIENT_B), false)
  assert.equal(matchAudience(undefined, RECIPIENT_A), false)
})

// ══════════════════════════════════════════════════════════════════
// 2. Four-valued checkAudience (Belnap-aligned)
// ══════════════════════════════════════════════════════════════════

test('checkAudience pass when relying party is a named recipient', () => {
  const proof: AudienceBearer = { aud: bindAudience([RECIPIENT_A]) }
  const r = checkAudience(proof, { recipientId: RECIPIENT_A })
  assert.equal(r.status, 'pass')
  assert.equal(r.reason, 'audience_match')
})

test('checkAudience FAIL when relying party is not a named recipient', () => {
  const proof: AudienceBearer = { aud: bindAudience([RECIPIENT_A]) }
  const r = checkAudience(proof, { recipientId: RECIPIENT_B })
  assert.equal(r.status, 'fail')
  assert.equal(r.reason, 'audience_mismatch')
})

test('checkAudience FAIL when an audience-required profile omits aud', () => {
  const proof: AudienceBearer = {}
  const r = checkAudience(proof, { recipientId: RECIPIENT_A, requireAudience: true })
  assert.equal(r.status, 'fail')
  assert.equal(r.reason, 'audience_required_absent')
})

test('checkAudience not_applicable when unbound and binding not required', () => {
  const proof: AudienceBearer = {}
  const r = checkAudience(proof, { recipientId: RECIPIENT_A })
  assert.equal(r.status, 'not_applicable')
  assert.equal(r.reason, 'audience_unbound')
})

test('checkAudience FAIL on a malformed binding (fail-closed)', () => {
  const proof: AudienceBearer = {
    aud: { profile: AUDIENCE_BINDING_PROFILE, recipients: [] },
  }
  const r = checkAudience(proof, { recipientId: RECIPIENT_A })
  assert.equal(r.status, 'fail')
  assert.equal(r.reason, 'audience_malformed')
})

test('checkAudience unknown when policy carries no recipientId', () => {
  const proof: AudienceBearer = { aud: bindAudience([RECIPIENT_A]) }
  const r = checkAudience(proof, { recipientId: '' })
  assert.equal(r.status, 'unknown')
  assert.equal(r.reason, 'audience_unknown')
})

test('audienceToConstraintStatus projects the four values directly', () => {
  assert.equal(
    audienceToConstraintStatus(checkAudience({ aud: bindAudience([RECIPIENT_A]) }, { recipientId: RECIPIENT_A })),
    'pass',
  )
  assert.equal(
    audienceToConstraintStatus(checkAudience({ aud: bindAudience([RECIPIENT_A]) }, { recipientId: RECIPIENT_B })),
    'fail',
  )
  assert.equal(
    audienceToConstraintStatus(checkAudience({}, { recipientId: RECIPIENT_A })),
    'not_applicable',
  )
  assert.equal(
    audienceToConstraintStatus(checkAudience({ aud: bindAudience([RECIPIENT_A]) }, { recipientId: '' })),
    'unknown',
  )
})

// ══════════════════════════════════════════════════════════════════
// 3. Delegation binding: A's passport is rejected at B
// ══════════════════════════════════════════════════════════════════

test('delegation bound to A: signature still valid; A accepted, B rejected', () => {
  clearV2DelegationStore()
  const delegator = generateKeyPair()
  const del = createV2Delegation({
    delegator: delegator.publicKey,
    delegatee: 'agent-1',
    scope,
    policy_context: policyContext(),
    delegator_private_key: delegator.privateKey,
    aud: bindAudience([RECIPIENT_A]),
  })

  // The audience binding is in the signed bytes: the signature verifies.
  assert.equal(validateV2Delegation(del).valid, true)
  assert.equal(del.aud?.recipients[0], RECIPIENT_A)

  // Recipient A accepts; recipient B rejects.
  assert.equal(checkAudience(del, { recipientId: RECIPIENT_A }).status, 'pass')
  const atB = checkAudience(del, { recipientId: RECIPIENT_B })
  assert.equal(atB.status, 'fail')
  assert.equal(atB.reason, 'audience_mismatch')
})

test('delegation tampered aud breaks the signature', () => {
  clearV2DelegationStore()
  const delegator = generateKeyPair()
  const del = createV2Delegation({
    delegator: delegator.publicKey,
    delegatee: 'agent-1',
    scope,
    policy_context: policyContext(),
    delegator_private_key: delegator.privateKey,
    aud: bindAudience([RECIPIENT_A]),
  })
  // Re-target the audience to B without re-signing.
  const tampered = { ...del, aud: bindAudience([RECIPIENT_B]) }
  assert.equal(validateV2Delegation(tampered).valid, false)
})

test('audience-free delegation is byte-identical to pre-audience-binding', () => {
  clearV2DelegationStore()
  const delegator = generateKeyPair()
  const del = createV2Delegation({
    delegator: delegator.publicKey,
    delegatee: 'agent-1',
    scope,
    policy_context: policyContext(),
    delegator_private_key: delegator.privateKey,
  })
  // No aud key on an audience-free delegation; signature verifies as before.
  assert.equal(Object.prototype.hasOwnProperty.call(del, 'aud'), false)
  assert.equal(validateV2Delegation(del).valid, true)
  // Audience-unbound under a non-requiring policy is not_applicable, not a fail.
  assert.equal(checkAudience(del, { recipientId: RECIPIENT_A }).status, 'not_applicable')
})

test('supersede carries the original audience forward unless overridden', () => {
  clearV2DelegationStore()
  const delegator = generateKeyPair()
  const del = createV2Delegation({
    delegator: delegator.publicKey,
    delegatee: 'agent-1',
    scope,
    policy_context: policyContext(),
    delegator_private_key: delegator.privateKey,
    aud: bindAudience([RECIPIENT_A]),
  })
  const renewed = supersedeV2Delegation({
    original_delegation_id: del.id,
    new_scope: scope,
    justification: 'rotate',
    policy_context: policyContext(),
    delegator_private_key: delegator.privateKey,
  })
  assert.equal(renewed.aud?.recipients[0], RECIPIENT_A)
  assert.equal(validateV2Delegation(renewed).valid, true)
  // Still rejected at B after renewal.
  assert.equal(checkAudience(renewed, { recipientId: RECIPIENT_B }).status, 'fail')
})

// ══════════════════════════════════════════════════════════════════
// 4. Receipt binding: dogfood verifyBilateralReceipt
// ══════════════════════════════════════════════════════════════════

test('bilateral receipt bound to A: both signatures cover aud; A accepted, B rejected', () => {
  const req = generateKeyPair()
  const srv = generateKeyPair()
  const now = new Date().toISOString()
  const receipt = createBilateralReceipt({
    requestingAgentId: 'req',
    servingAgentId: 'srv',
    outcome: {
      toolName: 'search',
      requestHash: 'rh',
      responseHash: 'sh',
      status: 'success',
      summary: 'ok',
    },
    requestedAt: now,
    completedAt: now,
    requestingAgentPrivateKey: req.privateKey,
    servingAgentPrivateKey: srv.privateKey,
    aud: bindAudience([RECIPIENT_A]),
  })

  // verifyBilateralReceipt re-canonicalizes the body INCLUDING aud, so both
  // co-signatures must (and do) cover it.
  const v = verifyBilateralReceipt(receipt, req.publicKey, srv.publicKey)
  assert.equal(v.valid, true)
  assert.equal(receipt.aud?.recipients[0], RECIPIENT_A)

  assert.equal(checkAudience(receipt, { recipientId: RECIPIENT_A }).status, 'pass')
  assert.equal(checkAudience(receipt, { recipientId: RECIPIENT_B }).status, 'fail')
})

test('tampering a bound receipt aud invalidates both signatures', () => {
  const req = generateKeyPair()
  const srv = generateKeyPair()
  const now = new Date().toISOString()
  const receipt = createBilateralReceipt({
    requestingAgentId: 'req',
    servingAgentId: 'srv',
    outcome: { toolName: 't', requestHash: 'r', responseHash: 's', status: 'success', summary: 'ok' },
    requestedAt: now,
    completedAt: now,
    requestingAgentPrivateKey: req.privateKey,
    servingAgentPrivateKey: srv.privateKey,
    aud: bindAudience([RECIPIENT_A]),
  })
  const tampered = { ...receipt, aud: bindAudience([RECIPIENT_B]) }
  const v = verifyBilateralReceipt(tampered, req.publicKey, srv.publicKey)
  assert.equal(v.valid, false)
  assert.equal(v.requestingAgentSignatureValid, false)
  assert.equal(v.servingAgentSignatureValid, false)
})

test('audience-free receipt verifies exactly as before (no aud key in body)', () => {
  const req = generateKeyPair()
  const srv = generateKeyPair()
  const now = new Date().toISOString()
  const receipt = createBilateralReceipt({
    requestingAgentId: 'req',
    servingAgentId: 'srv',
    outcome: { toolName: 't', requestHash: 'r', responseHash: 's', status: 'success', summary: 'ok' },
    requestedAt: now,
    completedAt: now,
    requestingAgentPrivateKey: req.privateKey,
    servingAgentPrivateKey: srv.privateKey,
  })
  assert.equal(verifyBilateralReceipt(receipt, req.publicKey, srv.publicKey).valid, true)
  assert.equal(receipt.aud, undefined)
})

// ══════════════════════════════════════════════════════════════════
// 5. Reconciliation with cross_chain (no double-deny, no contradiction)
// ══════════════════════════════════════════════════════════════════

function crossChainFail(): ConstraintFailure {
  return {
    facet: 'cross_chain',
    status: 'fail',
    code: 'taint_block',
    severity: 'hard',
    retryable: false,
    message: 'cross-chain flow blocked',
  }
}

test('audienceFailure emits a canonical ConstraintFailure on the audience facet', () => {
  const r = checkAudience({ aud: bindAudience([RECIPIENT_A]) }, { recipientId: RECIPIENT_B })
  const f = audienceFailure(r)
  assert.notEqual(f, null)
  assert.equal(f!.facet, 'audience')
  assert.equal(f!.status, 'fail')
  assert.equal(f!.code, 'audience_mismatch')
  assert.equal(f!.severity, 'hard')
  assert.equal(f!.retryable, false)
})

test('audienceFailure returns null for a non-failure', () => {
  const pass = checkAudience({ aud: bindAudience([RECIPIENT_A]) }, { recipientId: RECIPIENT_A })
  assert.equal(audienceFailure(pass), null)
  const na = checkAudience({}, { recipientId: RECIPIENT_A })
  assert.equal(audienceFailure(na), null)
})

test('reconcile: audience pass + cross_chain fail is consistent, cross_chain primary', () => {
  const pass = checkAudience({ aud: bindAudience([RECIPIENT_A]) }, { recipientId: RECIPIENT_A })
  const rec = reconcileAudienceWithCrossChain(pass, crossChainFail())
  assert.equal(rec.consistent, true)
  assert.equal(rec.bothFailed, false)
  // Only the cross_chain failure is present (audience passed → no failure).
  assert.equal(rec.failures.length, 1)
  assert.equal(rec.failures[0].facet, 'cross_chain')
  assert.equal(rec.primary?.facet, 'cross_chain')
})

test('reconcile: audience fail + no cross_chain fail yields a single audience denial', () => {
  const fail = checkAudience({ aud: bindAudience([RECIPIENT_A]) }, { recipientId: RECIPIENT_B })
  const rec = reconcileAudienceWithCrossChain(fail, null)
  assert.equal(rec.failures.length, 1)
  assert.equal(rec.failures[0].facet, 'audience')
  assert.equal(rec.primary?.facet, 'audience')
  assert.equal(rec.bothFailed, false)
})

test('reconcile: both fail → no double-deny on a facet, audience primary, both preserved', () => {
  const fail = checkAudience({ aud: bindAudience([RECIPIENT_A]) }, { recipientId: RECIPIENT_B })
  const rec = reconcileAudienceWithCrossChain(fail, crossChainFail())
  assert.equal(rec.bothFailed, true)
  assert.equal(rec.consistent, true)
  // Exactly two failures, one per facet (no duplicate facet entries).
  assert.equal(rec.failures.length, 2)
  const facets = rec.failures.map(f => f.facet).sort()
  assert.deepEqual(facets, ['audience', 'cross_chain'])
  // Presentation-layer audience is primary; cross_chain preserved for audit.
  assert.equal(rec.primary?.facet, 'audience')
})

test('reconcile rejects a non-cross_chain failure passed as the cross-chain arg', () => {
  const fail = checkAudience({ aud: bindAudience([RECIPIENT_A]) }, { recipientId: RECIPIENT_B })
  const wrong: ConstraintFailure = {
    facet: 'scope',
    status: 'fail',
    code: 'x',
    severity: 'hard',
    retryable: false,
    message: 'wrong facet',
  }
  assert.throws(() => reconcileAudienceWithCrossChain(fail, wrong), /cross_chain/)
})

// ══════════════════════════════════════════════════════════════════
// 6. Compose M1 RFC 9421 request-binding via @authority (no byte changes)
// ══════════════════════════════════════════════════════════════════

const M1_SIGNER = (() => {
  const kp = generateKeyPair()
  const vm = 'did:key:test#test'
  const signer: SignerKey = { privateKeyHex: kp.privateKey, verificationMethod: vm }
  const verifier: VerifierKey = { publicKeyHex: kp.publicKey, verificationMethod: vm }
  return { signer, verifier }
})()

function signFor(url: string, created: number) {
  const request: RequestContext = { method: 'GET', url }
  const profile = signRequest({
    request,
    signer: M1_SIGNER.signer,
    params: { created, nonce: `n-${created}-${url}` },
  })
  return { request, profile }
}

function m1Policy(created: number): VerifyPolicy {
  return { expectedTag: APS_REQUEST_BINDING_TAG, maxSkewSeconds: 300, nowSeconds: created }
}

test('M1 compose: request to host A verifies with matching expectedAuthority', () => {
  const created = 1700000000
  const { request, profile } = signFor('https://service-a.example.com/op', created)
  const r = verifyRequestWithAudience({
    profile,
    request,
    keys: [M1_SIGNER.verifier],
    policy: m1Policy(created),
    audiencePolicy: { expectedAuthority: 'service-a.example.com' },
  })
  assert.equal(r.inner.valid, true)
  assert.equal(r.audienceStatus, 'pass')
  assert.equal(r.valid, true)
})

test('M1 compose: a request signed for host A is rejected at expectedAuthority B', () => {
  const created = 1700000100
  const { request, profile } = signFor('https://service-a.example.com/op', created)
  const r = verifyRequestWithAudience({
    profile,
    request,
    keys: [M1_SIGNER.verifier],
    policy: m1Policy(created),
    audiencePolicy: { expectedAuthority: 'service-b.example.com' },
  })
  // Inner crypto is valid for the real host, but the relying party expected B.
  assert.equal(r.inner.valid, true)
  assert.equal(r.audienceStatus, 'fail')
  assert.equal(r.reason, 'authority_audience_mismatch')
  assert.equal(r.valid, false)
})

test('M1 compose: lifting A-signed profile onto a B-bound request fails inner crypto first', () => {
  const created = 1700000200
  const { profile } = signFor('https://service-a.example.com/op', created)
  // Attacker presents the A-signature with a request claiming host B.
  const forgedRequest: RequestContext = { method: 'GET', url: 'https://service-b.example.com/op' }
  const r = verifyRequestWithAudience({
    profile,
    request: forgedRequest,
    keys: [M1_SIGNER.verifier],
    policy: m1Policy(created),
    audiencePolicy: { expectedAuthority: 'service-b.example.com' },
  })
  // The base reconstructs over host B, so the signature check fails BEFORE the
  // audience overlay can be trusted → audienceStatus unknown, overall invalid.
  assert.equal(r.inner.valid, false)
  assert.equal(r.audienceStatus, 'unknown')
  assert.equal(r.valid, false)
})

test('M1 compose: no expectedAuthority leaves verifyRequest behavior unchanged', () => {
  const created = 1700000300
  const { request, profile } = signFor('https://service-a.example.com/op', created)
  const r = verifyRequestWithAudience({
    profile,
    request,
    keys: [M1_SIGNER.verifier],
    policy: m1Policy(created),
  })
  assert.equal(r.inner.valid, true)
  assert.equal(r.audienceStatus, 'not_applicable')
  assert.equal(r.valid, true)
})
