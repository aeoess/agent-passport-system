// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Day-145 Track A regression: threshold evaluation must verify signatures
// before counting them. Before this fix, evaluateThreshold counted a signer
// from public-key membership alone (keyClass match + eligibleKeys.includes),
// so a forged or empty signature counted toward a governance threshold.
//
// Note for fail-before runs against unfixed code: this file intentionally
// imports nothing added by the fix. The 3rd evaluateThreshold argument is
// ignored at runtime by the old 2-parameter implementation, which makes the
// old counting behavior directly observable.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, sign,
  createCharter, verifyCharter,
  createAmendment, signAmendment, verifyAmendment,
  evaluateThreshold,
  createApprovalRequest, addApprovalSignature, evaluateApprovalRequest,
} from '../src/index.js'
import type {
  Office, MultiClassThresholdPolicy, ApprovalPolicy,
  DissolutionPolicy, DelegationSurvival,
} from '../src/index.js'

const SUBJECT = 'approval_test:amend_subject_1'

function makePolicy(boardKeys: string[], required: number): MultiClassThresholdPolicy {
  return {
    policyId: 'policy_vbc',
    requirements: [
      { role: 'board', requiredSignatures: required, eligibleKeys: boardKeys },
    ],
    collectionTimeoutSeconds: 3600,
    onTimeout: 'reject',
    reevaluateOnRevocation: true,
  }
}

function makeOffice(id: string, holderKey: string): Office {
  return {
    officeId: id,
    name: id,
    holderMode: 'single',
    holderSet: [{
      publicKey: holderKey,
      appointedAt: new Date().toISOString(),
      appointedBy: 'charter_founding',
      isInterim: false,
    }],
    delegationPolicy: { allowedScopes: ['*'], maxSpendPerAction: 1000, maxDelegationDepth: 3 },
    successionOrder: [],
    status: 'active',
    effectiveAt: new Date().toISOString(),
  }
}

const SURVIVAL: DelegationSurvival = {
  onOfficeChange: 'require_reconfirmation',
  onCharterAmendment: 'survive_if_compatible',
}

function makeDissolution(boardKeys: string[]): DissolutionPolicy {
  return {
    requiresThreshold: makePolicy(boardKeys, boardKeys.length),
    gracePeriodSeconds: 86400,
    activeEscrowHandling: 'settle_first',
  }
}

describe('Threshold — verify before count (Day-145 Track A)', () => {
  it('(a) rejects a forged signature from an eligible public key', () => {
    const board1 = generateKeyPair()
    const board2 = generateKeyPair()
    const attacker = generateKeyPair()
    const policy = makePolicy([board1.publicKey, board2.publicKey], 2)

    const sigs = [
      // board1 genuinely signs the subject
      { publicKey: board1.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: sign(SUBJECT, board1.privateKey) },
      // attacker signs with their own key but claims board2's ELIGIBLE public key
      { publicKey: board2.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: sign(SUBJECT, attacker.privateKey) },
    ]

    const result = evaluateThreshold(policy, sigs, SUBJECT)
    assert.equal(result.met, false, 'forged signature must not satisfy the threshold')
    assert.equal(result.classStatus[0].collected, 1, 'only the genuine signer counts')
    assert.ok(
      result.errors.some(e => e.includes('invalid signature')),
      `errors must name the invalid signature, got: ${result.errors.join(' | ')}`,
    )
  })

  it('(b) rejects an empty-string signature from an eligible public key', () => {
    const board1 = generateKeyPair()
    const policy = makePolicy([board1.publicKey], 1)

    const sigs = [
      { publicKey: board1.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: '' },
    ]

    const result = evaluateThreshold(policy, sigs, SUBJECT)
    assert.equal(result.met, false, 'empty signature must not satisfy the threshold')
    assert.equal(result.classStatus[0].collected, 0)
    assert.ok(result.errors.some(e => e.includes('invalid signature')))
  })

  it('(b2) rejects a malformed (non-hex garbage) signature', () => {
    const board1 = generateKeyPair()
    const policy = makePolicy([board1.publicKey], 1)

    const sigs = [
      { publicKey: board1.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: 'zz-not-a-signature' },
    ]

    const result = evaluateThreshold(policy, sigs, SUBJECT)
    assert.equal(result.met, false)
    assert.equal(result.classStatus[0].collected, 0)
  })

  it('(a3) rejects a genuine signature over the WRONG subject', () => {
    const board1 = generateKeyPair()
    const policy = makePolicy([board1.publicKey], 1)

    const sigs = [
      { publicKey: board1.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: sign('some-other-subject', board1.privateKey) },
    ]

    const result = evaluateThreshold(policy, sigs, SUBJECT)
    assert.equal(result.met, false, 'signature over a different subject must not count')
    assert.equal(result.classStatus[0].collected, 0)
  })

  it('(c) meets the threshold with the required number of genuine signatures', () => {
    const board1 = generateKeyPair()
    const board2 = generateKeyPair()
    const policy = makePolicy([board1.publicKey, board2.publicKey], 2)

    const sigs = [
      { publicKey: board1.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: sign(SUBJECT, board1.privateKey) },
      { publicKey: board2.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: sign(SUBJECT, board2.privateKey) },
    ]

    const result = evaluateThreshold(policy, sigs, SUBJECT)
    assert.equal(result.met, true, `genuine signatures must meet the threshold: ${result.errors.join(' | ')}`)
    assert.equal(result.classStatus[0].collected, 2)
    assert.equal(result.totalValidSignatures, 2)
  })

  it('distinguishes not-eligible from invalid-signature in errors[]', () => {
    const board1 = generateKeyPair()
    const rando = generateKeyPair()
    const attacker = generateKeyPair()
    const policy = makePolicy([board1.publicKey], 1)

    const sigs = [
      // eligible key, forged bytes -> invalid signature
      { publicKey: board1.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: sign(SUBJECT, attacker.privateKey) },
      // ineligible key, genuine bytes -> not eligible
      { publicKey: rando.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: sign(SUBJECT, rando.privateKey) },
    ]

    const result = evaluateThreshold(policy, sigs, SUBJECT)
    assert.equal(result.met, false)
    assert.ok(result.errors.some(e => e.includes('invalid signature')), 'invalid-signature reason present')
    assert.ok(result.errors.some(e => e.includes('not eligible')), 'not-eligible reason present')
  })

  // ── Call site 1: verifyCharter quorum (founding signatures over contentHash)

  it('verifyCharter quorum rejects a tampered founding signature', () => {
    const founder = generateKeyPair()
    const attacker = generateKeyPair()

    const charter = createCharter({
      name: 'Quorum VBC',
      offices: [makeOffice('ops', founder.publicKey)],
      amendmentPolicy: makePolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolution([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    // Swap the founding signature bytes for a signature by a different key.
    // The public key stays eligible, so pre-fix counting accepted it.
    const forged = {
      ...charter,
      foundingSignatures: [{
        ...charter.foundingSignatures[0],
        signature: sign(charter.contentHash, attacker.privateKey),
      }],
    }

    const result = verifyCharter(forged)
    assert.equal(result.quorumMet, false, 'forged founding signature must not satisfy quorum')
    assert.equal(result.valid, false)
  })

  it('verifyCharter quorum passes with genuine founding signatures', () => {
    const founder = generateKeyPair()
    const charter = createCharter({
      name: 'Quorum VBC positive',
      offices: [makeOffice('ops', founder.publicKey)],
      amendmentPolicy: makePolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolution([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })
    const result = verifyCharter(charter)
    assert.equal(result.quorumMet, true, result.errors.join(' | '))
    assert.equal(result.valid, true)
  })

  // ── Call site 2: verifyAmendment threshold (signatures over amendmentSignContent)

  it('verifyAmendment threshold rejects an injected forged co-signature', () => {
    const founder = generateKeyPair()
    const board2 = generateKeyPair()
    const attacker = generateKeyPair()

    const charter = createCharter({
      name: 'Amendment VBC',
      offices: [makeOffice('ops', founder.publicKey)],
      amendmentPolicy: makePolicy([founder.publicKey, board2.publicKey], 1),
      dissolutionPolicy: makeDissolution([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    const proposed = createCharter({
      name: 'Amendment VBC v2',
      offices: [makeOffice('ops', founder.publicKey)],
      amendmentPolicy: makePolicy([founder.publicKey, board2.publicKey], 1),
      dissolutionPolicy: makeDissolution([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
      version: '2.0.0',
    })

    const amendment = createAmendment({
      charter,
      proposedCharter: proposed,
      description: 'vbc test',
      proposerPrivateKey: founder.privateKey,
      proposerPublicKey: founder.publicKey,
    })

    // Inject a signature entry claiming eligible board2 but signed by the
    // attacker. The proposer sig has role 'proposer' and never counts toward
    // the 'board' class, so the threshold rests entirely on the forgery.
    const withForged = {
      ...amendment,
      signatures: [
        ...amendment.signatures,
        {
          publicKey: board2.publicKey,
          role: 'board',
          signedAt: new Date().toISOString(),
          signature: sign('unrelated-bytes', attacker.privateKey),
        },
      ],
    }

    const result = verifyAmendment(withForged, charter)
    assert.equal(result.thresholdMet, false, 'forged co-signature must not meet the amendment threshold')
    assert.equal(result.valid, false)
  })

  it('verifyAmendment threshold passes with a genuine co-signature', () => {
    const founder = generateKeyPair()
    const board2 = generateKeyPair()

    const charter = createCharter({
      name: 'Amendment VBC positive',
      offices: [makeOffice('ops', founder.publicKey)],
      amendmentPolicy: makePolicy([founder.publicKey, board2.publicKey], 1),
      dissolutionPolicy: makeDissolution([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    const proposed = createCharter({
      name: 'Amendment VBC positive v2',
      offices: [makeOffice('ops', founder.publicKey)],
      amendmentPolicy: makePolicy([founder.publicKey, board2.publicKey], 1),
      dissolutionPolicy: makeDissolution([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
      version: '2.0.0',
    })

    const amendment = createAmendment({
      charter,
      proposedCharter: proposed,
      description: 'vbc positive',
      proposerPrivateKey: founder.privateKey,
      proposerPublicKey: founder.publicKey,
    })
    const signed = signAmendment(amendment, board2.privateKey, board2.publicKey, 'board')

    const result = verifyAmendment(signed, charter)
    assert.equal(result.thresholdMet, true, result.errors.join(' | '))
    assert.equal(result.valid, true, result.errors.join(' | '))
  })

  // ── Call site 3: evaluateApprovalRequest threshold (signatures over requestId:subject)

  it('approval threshold rejects an injected forged signature', () => {
    const board1 = generateKeyPair()
    const board2 = generateKeyPair()
    const attacker = generateKeyPair()

    const policy: ApprovalPolicy = {
      policyId: 'pol_vbc',
      type: 'threshold',
      threshold: makePolicy([board1.publicKey, board2.publicKey], 2),
      timeoutAction: 'deny',
      timeoutSeconds: 3600,
    }

    let req = createApprovalRequest('pol_vbc', 'amend_777', 'charter_amendment', board1.publicKey, 3600)
    req = addApprovalSignature(req, board1.privateKey, board1.publicKey, 'board')

    // Inject a second signature claiming eligible board2 but forged by the
    // attacker (bypassing addApprovalSignature, as a hostile caller would).
    req = {
      ...req,
      signatures: [
        ...req.signatures,
        {
          publicKey: board2.publicKey,
          keyClass: 'board',
          signedAt: new Date().toISOString(),
          signature: sign(req.requestId + ':' + req.subject, attacker.privateKey),
        },
      ],
    }

    const result = evaluateApprovalRequest(req, policy)
    assert.equal(result.evaluation.met, false, 'forged approval signature must not be counted')
    assert.equal(result.request.status, 'pending')
  })

  it('approval threshold approves with genuine signatures via addApprovalSignature', () => {
    const board1 = generateKeyPair()
    const board2 = generateKeyPair()

    const policy: ApprovalPolicy = {
      policyId: 'pol_vbc2',
      type: 'threshold',
      threshold: makePolicy([board1.publicKey, board2.publicKey], 2),
      timeoutAction: 'deny',
      timeoutSeconds: 3600,
    }

    let req = createApprovalRequest('pol_vbc2', 'amend_778', 'charter_amendment', board1.publicKey, 3600)
    req = addApprovalSignature(req, board1.privateKey, board1.publicKey, 'board')
    req = addApprovalSignature(req, board2.privateKey, board2.publicKey, 'board')

    const result = evaluateApprovalRequest(req, policy)
    assert.equal(result.evaluation.met, true, result.evaluation.errors.join(' | '))
    assert.equal(result.request.status, 'approved')
  })
})
