// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for Charter & Approval — Institutional Governance Layer

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createCharter, signCharter, verifyCharter,
  createAmendment, signAmendment, verifyAmendment,
  evaluateThreshold,
  createOfficeRegistry,
  createOfficeTransfer,
  createApprovalRequest, addApprovalSignature, evaluateApprovalRequest,
  findOffice, findOfficesByHolder, resolveSuccessor,
  checkIncompatibility, checkQuorum,
} from '../src/index.js'
import type {
  Office, MultiClassThresholdPolicy, ApprovalPolicy,
  DissolutionPolicy, DelegationSurvival, QuorumFailurePolicy,
} from '../src/index.js'


// ══════════════════════════════════════
// Test Fixtures
// ══════════════════════════════════════

function makeThresholdPolicy(
  boardKeys: string[],
  boardRequired: number,
  counselKeys: string[] = [],
  counselRequired: number = 0,
): MultiClassThresholdPolicy {
  const requirements = [
    { role: 'board', requiredSignatures: boardRequired, eligibleKeys: boardKeys },
  ]
  if (counselKeys.length > 0) {
    requirements.push({ role: 'counsel', requiredSignatures: counselRequired, eligibleKeys: counselKeys })
  }
  return {
    policyId: 'policy_test',
    requirements,
    collectionTimeoutSeconds: 3600,
    onTimeout: 'reject' as const,
    reevaluateOnRevocation: true,
  }
}

function makeOffice(id: string, name: string, holderKey: string, opts?: {
  incompatible?: string[],
  successionOrder?: string[],
}): Office {
  return {
    officeId: id,
    name,
    holderMode: 'single',
    holderSet: [{
      publicKey: holderKey,
      appointedAt: new Date().toISOString(),
      appointedBy: 'charter_founding',
      isInterim: false,
    }],
    delegationPolicy: {
      allowedScopes: ['*'],
      maxSpendPerAction: 1000,
      maxDelegationDepth: 3,
    },
    successionOrder: opts?.successionOrder ?? [],
    status: 'active',
    effectiveAt: new Date().toISOString(),
    incompatibleOffices: opts?.incompatible,
  }
}

function makeDissolutionPolicy(boardKeys: string[]): DissolutionPolicy {
  return {
    requiresThreshold: makeThresholdPolicy(boardKeys, boardKeys.length),
    gracePeriodSeconds: 86400,
    activeEscrowHandling: 'settle_first',
  }
}

const SURVIVAL: DelegationSurvival = {
  onOfficeChange: 'require_reconfirmation',
  onCharterAmendment: 'survive_if_compatible',
}

// ══════════════════════════════════════
// Charter Creation & Verification
// ══════════════════════════════════════

describe('Charter — Create & Verify', () => {
  it('creates a charter with valid structure', () => {
    const founder = generateKeyPair()
    const treasury = generateKeyPair()
    const ops = generateKeyPair()

    const offices = [
      makeOffice('treasury', 'Treasury', treasury.publicKey),
      makeOffice('operations', 'Operations', ops.publicKey, { successionOrder: ['treasury'] }),
    ]

    const charter = createCharter({
      name: 'Test Institution',
      offices,
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    assert.ok(charter.charterId.startsWith('charter_'))
    assert.equal(charter.name, 'Test Institution')
    assert.equal(charter.version, '1.0.0')
    assert.equal(charter.status, 'active')
    assert.equal(charter.offices.length, 2)
    assert.equal(charter.foundingSignatures.length, 1)
    assert.equal(charter.foundingSignatures[0].role, 'board')
    assert.ok(charter.contentHash.length > 0)
    assert.ok(charter.signature.length > 0)
  })

  it('verifies a valid charter', () => {
    const founder = generateKeyPair()
    const charter = createCharter({
      name: 'Verified Institution',
      offices: [makeOffice('ops', 'Operations', founder.publicKey)],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    const result = verifyCharter(charter)
    assert.ok(result.valid, `Expected valid charter: ${result.errors.join(', ')}`)
    assert.ok(result.contentIntegrity)
    assert.ok(result.signaturesValid)
    assert.ok(result.quorumMet)
    assert.ok(result.notDissolved)
    assert.ok(result.officesValid)
    assert.ok(result.incompatibilityClean)
  })

  it('rejects duplicate office IDs', () => {
    const founder = generateKeyPair()
    assert.throws(() => createCharter({
      name: 'Bad',
      offices: [
        makeOffice('ops', 'Ops', founder.publicKey),
        makeOffice('ops', 'Ops2', founder.publicKey),
      ],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    }), /Duplicate office ID/)
  })

  it('adds a founding signature with signCharter', () => {
    const founder = generateKeyPair()
    const counsel = generateKeyPair()

    const charter = createCharter({
      name: 'Multi-signer',
      offices: [makeOffice('ops', 'Ops', founder.publicKey)],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey, counsel.publicKey], 2),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    assert.equal(charter.foundingSignatures.length, 1)

    const signed = signCharter(charter, counsel.privateKey, counsel.publicKey, 'counsel', founder.privateKey)
    assert.equal(signed.foundingSignatures.length, 2)
    assert.equal(signed.foundingSignatures[1].role, 'counsel')
  })

  it('rejects duplicate signer in signCharter', () => {
    const founder = generateKeyPair()
    const charter = createCharter({
      name: 'Dup test',
      offices: [makeOffice('ops', 'Ops', founder.publicKey)],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    assert.throws(() =>
      signCharter(charter, founder.privateKey, founder.publicKey, 'board', founder.privateKey),
      /already signed/
    )
  })

  it('detects incompatible office holders (GPT #20)', () => {
    const holder = generateKeyPair()
    const founder = generateKeyPair()

    const offices = [
      makeOffice('treasury', 'Treasury', holder.publicKey, { incompatible: ['counsel'] }),
      makeOffice('counsel', 'Counsel', holder.publicKey, { incompatible: ['treasury'] }),
    ]

    const charter = createCharter({
      name: 'Incompatible test',
      offices,
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    const result = verifyCharter(charter)
    assert.ok(!result.incompatibilityClean, 'Should detect incompatibility')
    assert.ok(result.errors.some(e => e.includes('incompatible')))
  })
})

// ══════════════════════════════════════
// Multi-Class Threshold Evaluation
// ══════════════════════════════════════

describe('Approval — Multi-Class Threshold (Consilium Q5)', () => {
  it('passes when all class requirements met', () => {
    const board1 = generateKeyPair()
    const board2 = generateKeyPair()
    const counsel = generateKeyPair()

    const policy = makeThresholdPolicy(
      [board1.publicKey, board2.publicKey], 2,
      [counsel.publicKey], 1,
    )

    const sigs = [
      { publicKey: board1.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: 'sig1' },
      { publicKey: board2.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: 'sig2' },
      { publicKey: counsel.publicKey, keyClass: 'counsel', signedAt: new Date().toISOString(), signature: 'sig3' },
    ]

    const result = evaluateThreshold(policy, sigs)
    assert.ok(result.met)
    assert.equal(result.classStatus.length, 2)
    assert.ok(result.classStatus[0].satisfied) // board
    assert.ok(result.classStatus[1].satisfied) // counsel
    assert.equal(result.totalValidSignatures, 3)
    assert.equal(result.totalRequired, 3)
  })

  it('fails when a class requirement is not met', () => {
    const board1 = generateKeyPair()
    const board2 = generateKeyPair()
    const counsel = generateKeyPair()

    const policy = makeThresholdPolicy(
      [board1.publicKey, board2.publicKey], 2,
      [counsel.publicKey], 1,
    )

    // Only 1 board sig — need 2
    const sigs = [
      { publicKey: board1.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: 'sig1' },
      { publicKey: counsel.publicKey, keyClass: 'counsel', signedAt: new Date().toISOString(), signature: 'sig3' },
    ]

    const result = evaluateThreshold(policy, sigs)
    assert.ok(!result.met)
    assert.ok(!result.classStatus[0].satisfied)
    assert.ok(result.classStatus[1].satisfied)
    assert.equal(result.errors.length, 1)
    assert.ok(result.errors[0].includes('board'))
  })

  it('deduplicates same key signing twice for same class', () => {
    const board1 = generateKeyPair()
    const policy = makeThresholdPolicy([board1.publicKey], 2) // requires 2 but only 1 key

    const sigs = [
      { publicKey: board1.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: 'sig1' },
      { publicKey: board1.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: 'sig2' },
    ]

    const result = evaluateThreshold(policy, sigs)
    assert.ok(!result.met, 'Same key twice should count as 1')
    assert.equal(result.classStatus[0].collected, 1)
  })

  it('rejects signatures from ineligible keys', () => {
    const board1 = generateKeyPair()
    const rando = generateKeyPair()
    const policy = makeThresholdPolicy([board1.publicKey], 1)

    // rando is not in the eligible keys list
    const sigs = [
      { publicKey: rando.publicKey, keyClass: 'board', signedAt: new Date().toISOString(), signature: 'sig1' },
    ]

    const result = evaluateThreshold(policy, sigs)
    assert.ok(!result.met, 'Ineligible key should not count')
    assert.equal(result.classStatus[0].collected, 0)
  })
})

// ══════════════════════════════════════
// Charter Amendments
// ══════════════════════════════════════

describe('Charter — Amendments', () => {
  it('creates and verifies an amendment with sufficient signatures', () => {
    const founder = generateKeyPair()
    const charter = createCharter({
      name: 'Amendment Test',
      offices: [makeOffice('ops', 'Ops', founder.publicKey)],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    // Create proposed charter with a new office
    const newOps = generateKeyPair()
    const proposed = createCharter({
      name: 'Amendment Test v2',
      offices: [
        makeOffice('ops', 'Ops', founder.publicKey),
        makeOffice('audit', 'Audit', newOps.publicKey),
      ],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
      version: '2.0.0',
    })

    const amendment = createAmendment({
      charter,
      proposedCharter: proposed,
      description: 'Add audit office',
      proposerPrivateKey: founder.privateKey,
      proposerPublicKey: founder.publicKey,
    })

    assert.ok(amendment.amendmentId.startsWith('amend_'))
    assert.equal(amendment.fromVersion, '1.0.0')
    assert.equal(amendment.toVersion, '2.0.0')
    assert.equal(amendment.status, 'proposed')
    assert.equal(amendment.signatures.length, 1)

    // Proposer already signed — add a second board member to meet threshold
    const board2 = generateKeyPair()
    // Recreate with 2-of-2 threshold to test multi-sig
    const charter2 = createCharter({
      name: 'Amendment Test',
      offices: [makeOffice('ops', 'Ops', founder.publicKey)],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey, board2.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    const amendment2 = createAmendment({
      charter: charter2,
      proposedCharter: proposed,
      description: 'Add audit office',
      proposerPrivateKey: founder.privateKey,
      proposerPublicKey: founder.publicKey,
    })

    const signed = signAmendment(amendment2, board2.privateKey, board2.publicKey, 'board')
    assert.equal(signed.signatures.length, 2)

    const result = verifyAmendment(signed, charter2)
    assert.ok(result.charterExists)
    assert.ok(result.versionMatch)
    assert.ok(result.signaturesValid)
    assert.ok(result.thresholdMet, `Threshold not met: ${result.errors.join(', ')}`)
    assert.ok(result.proposedCharterValid)
    assert.ok(result.valid, `Expected valid amendment: ${result.errors.join(', ')}`)
  })

  it('rejects amendment against dissolved charter', () => {
    const founder = generateKeyPair()
    const charter = createCharter({
      name: 'Dissolved',
      offices: [makeOffice('ops', 'Ops', founder.publicKey)],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    const dissolved = { ...charter, status: 'dissolved' as const }

    assert.throws(() => createAmendment({
      charter: dissolved,
      proposedCharter: charter,
      description: 'Should fail',
      proposerPrivateKey: founder.privateKey,
      proposerPublicKey: founder.publicKey,
    }), /Cannot amend a dissolved charter/)
  })

  it('rejects duplicate signer in signAmendment', () => {
    const founder = generateKeyPair()
    const charter = createCharter({
      name: 'Dup amend test',
      offices: [makeOffice('ops', 'Ops', founder.publicKey)],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    const amendment = createAmendment({
      charter,
      proposedCharter: charter,
      description: 'dup test',
      proposerPrivateKey: founder.privateKey,
      proposerPublicKey: founder.publicKey,
    })

    // proposer already signed at creation
    assert.throws(() =>
      signAmendment(amendment, founder.privateKey, founder.publicKey, 'board'),
      /already signed/
    )
  })
})

// ══════════════════════════════════════
// Approval Request Lifecycle
// ══════════════════════════════════════

describe('Approval — Request Lifecycle', () => {
  it('creates, signs, and evaluates a threshold approval', () => {
    const board1 = generateKeyPair()
    const board2 = generateKeyPair()

    const policy: ApprovalPolicy = {
      policyId: 'pol_test',
      type: 'threshold',
      threshold: makeThresholdPolicy([board1.publicKey, board2.publicKey], 2),
      timeoutAction: 'deny',
      timeoutSeconds: 3600,
    }

    let req = createApprovalRequest('pol_test', 'charter_abc', 'charter_amendment', board1.publicKey, 3600)
    assert.equal(req.status, 'pending')
    assert.equal(req.signatures.length, 0)

    // First signature — not enough yet
    req = addApprovalSignature(req, board1.privateKey, board1.publicKey, 'board')
    assert.equal(req.signatures.length, 1)

    let result = evaluateApprovalRequest(req, policy)
    assert.equal(result.request.status, 'pending')
    assert.ok(!result.evaluation.met)

    // Second signature — threshold met
    req = addApprovalSignature(req, board2.privateKey, board2.publicKey, 'board')
    assert.equal(req.signatures.length, 2)

    result = evaluateApprovalRequest(req, policy)
    assert.equal(result.request.status, 'approved')
    assert.ok(result.evaluation.met)
    assert.equal(result.evaluation.totalValidSignatures, 2)
  })

  it('rejects duplicate signer in addApprovalSignature', () => {
    const signer = generateKeyPair()
    let req = createApprovalRequest('pol_test', 'sub_1', 'delegation', signer.publicKey, 3600)
    req = addApprovalSignature(req, signer.privateKey, signer.publicKey, 'board')
    assert.throws(() =>
      addApprovalSignature(req, signer.privateKey, signer.publicKey, 'board'),
      /already signed/
    )
  })

  it('rejects signing an expired request', () => {
    const signer = generateKeyPair()
    let req = createApprovalRequest('pol_test', 'sub_1', 'delegation', signer.publicKey, 3600)
    // Manually set expiresAt to the past
    req = { ...req, expiresAt: new Date(Date.now() - 10000).toISOString() }
    assert.throws(() =>
      addApprovalSignature(req, signer.privateKey, signer.publicKey, 'board'),
      /expired/
    )
  })

  it('evaluates role_required approval', () => {
    const treasury = generateKeyPair()
    const counsel = generateKeyPair()

    const policy: ApprovalPolicy = {
      policyId: 'pol_role',
      type: 'role_required',
      requiredRoles: ['treasury', 'counsel'],
      timeoutAction: 'deny',
      timeoutSeconds: 3600,
    }

    let req = createApprovalRequest('pol_role', 'escrow_1', 'escrow_release', treasury.publicKey, 3600)
    req = addApprovalSignature(req, treasury.privateKey, treasury.publicKey, 'board', 'treasury')
    
    // Only treasury signed — counsel still missing
    let result = evaluateApprovalRequest(req, policy)
    assert.ok(!result.evaluation.met)
    assert.equal(result.request.status, 'pending')

    req = addApprovalSignature(req, counsel.privateKey, counsel.publicKey, 'board', 'counsel')
    result = evaluateApprovalRequest(req, policy)
    assert.ok(result.evaluation.met)
    assert.equal(result.request.status, 'approved')
  })

  it('evaluates sequential approval in correct order', () => {
    const first = generateKeyPair()
    const second = generateKeyPair()

    const policy: ApprovalPolicy = {
      policyId: 'pol_seq',
      type: 'sequential',
      sequentialOrder: ['ops', 'treasury'],
      timeoutAction: 'deny',
      timeoutSeconds: 3600,
    }

    // Sign in correct order
    let req = createApprovalRequest('pol_seq', 'transfer_1', 'office_transfer', first.publicKey, 3600)
    req = addApprovalSignature(req, first.privateKey, first.publicKey, 'board', 'ops')
    req = addApprovalSignature(req, second.privateKey, second.publicKey, 'board', 'treasury')

    const result = evaluateApprovalRequest(req, policy)
    assert.ok(result.evaluation.met)
    assert.equal(result.request.status, 'approved')
  })

  it('rejects sequential approval in wrong order', () => {
    const first = generateKeyPair()
    const second = generateKeyPair()

    const policy: ApprovalPolicy = {
      policyId: 'pol_seq',
      type: 'sequential',
      sequentialOrder: ['ops', 'treasury'],
      timeoutAction: 'deny',
      timeoutSeconds: 3600,
    }

    // Sign in WRONG order: treasury first, then ops
    let req = createApprovalRequest('pol_seq', 'transfer_2', 'office_transfer', first.publicKey, 3600)
    req = addApprovalSignature(req, second.privateKey, second.publicKey, 'board', 'treasury')
    req = addApprovalSignature(req, first.privateKey, first.publicKey, 'board', 'ops')

    const result = evaluateApprovalRequest(req, policy)
    assert.ok(!result.evaluation.met, 'Wrong order should fail')
    assert.equal(result.request.status, 'pending')
  })
})

// ══════════════════════════════════════
// Office Helpers
// ══════════════════════════════════════

describe('Charter — Office Helpers', () => {
  const founder = generateKeyPair()
  const treasuryHolder = generateKeyPair()
  const opsHolder = generateKeyPair()
  const counselHolder = generateKeyPair()

  function makeTestCharter() {
    return createCharter({
      name: 'Office Test',
      offices: [
        makeOffice('treasury', 'Treasury', treasuryHolder.publicKey, {
          incompatible: ['counsel'],
          successionOrder: ['operations'],
        }),
        makeOffice('operations', 'Operations', opsHolder.publicKey, {
          successionOrder: ['treasury'],
        }),
        makeOffice('counsel', 'Counsel', counselHolder.publicKey, {
          incompatible: ['treasury'],
        }),
      ],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })
  }

  it('findOffice returns office by ID', () => {
    const charter = makeTestCharter()
    const office = findOffice(charter, 'treasury')
    assert.ok(office)
    assert.equal(office.name, 'Treasury')
    assert.equal(findOffice(charter, 'nonexistent'), undefined)
  })

  it('findOfficesByHolder returns offices held by a key', () => {
    const charter = makeTestCharter()
    const offices = findOfficesByHolder(charter, treasuryHolder.publicKey)
    assert.equal(offices.length, 1)
    assert.equal(offices[0].officeId, 'treasury')
  })

  it('resolveSuccessor finds the first non-vacant successor', () => {
    const charter = makeTestCharter()
    const successor = resolveSuccessor(charter, 'treasury')
    assert.ok(successor)
    assert.equal(successor.officeId, 'operations')
  })

  it('resolveSuccessor returns null when no successors defined', () => {
    const charter = makeTestCharter()
    const successor = resolveSuccessor(charter, 'counsel')
    assert.equal(successor, null)
  })

  it('checkIncompatibility detects conflicts (GPT #20)', () => {
    const charter = makeTestCharter()
    // Treasury holder trying to also hold Counsel — should conflict
    const result = checkIncompatibility(charter, 'counsel', treasuryHolder.publicKey)
    assert.ok(!result.compatible)
    assert.ok(result.conflicts.length > 0)
    assert.ok(result.conflicts.some(c => c.includes('incompatible')))
  })

  it('checkIncompatibility passes for non-conflicting holder', () => {
    const charter = makeTestCharter()
    const newHolder = generateKeyPair()
    const result = checkIncompatibility(charter, 'counsel', newHolder.publicKey)
    assert.ok(result.compatible)
    assert.equal(result.conflicts.length, 0)
  })

  it('checkQuorum passes with sufficient holders', () => {
    const charter = makeTestCharter()
    const office = findOffice(charter, 'treasury')!
    const policy: QuorumFailurePolicy = {
      officeId: 'treasury',
      minimumHolders: 1,
      onQuorumLoss: 'freeze_office',
      maxFreezeDurationSeconds: 86400,
    }
    const result = checkQuorum(office, policy)
    assert.ok(result.hasQuorum)
    assert.equal(result.holders, 1)
    assert.equal(result.required, 1)
  })

  it('checkQuorum fails when holders below minimum (GPT #17)', () => {
    const charter = makeTestCharter()
    const office = findOffice(charter, 'treasury')!
    const policy: QuorumFailurePolicy = {
      officeId: 'treasury',
      minimumHolders: 3, // needs 3 but only has 1
      onQuorumLoss: 'escalate_to_parent',
      maxFreezeDurationSeconds: 86400,
    }
    const result = checkQuorum(office, policy)
    assert.ok(!result.hasQuorum)
    assert.equal(result.holders, 1)
    assert.equal(result.required, 3)
  })
})

// ══════════════════════════════════════
// Office Transfer & Registry
// ══════════════════════════════════════

describe('Charter — Office Transfer & Registry', () => {
  it('creates an office transfer record', () => {
    const founder = generateKeyPair()
    const oldHolder = generateKeyPair()
    const newHolder = generateKeyPair()

    const charter = createCharter({
      name: 'Transfer Test',
      offices: [makeOffice('treasury', 'Treasury', oldHolder.publicKey)],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    const transfer = createOfficeTransfer({
      charter,
      officeId: 'treasury',
      fromHolder: oldHolder.publicKey,
      toHolder: newHolder.publicKey,
      trigger: 'explicit_transfer',
      delegationHandling: 'transferred',
      approvalSignatures: [],
      signerPrivateKey: founder.privateKey,
    })

    assert.ok(transfer.transferId.startsWith('transfer_'))
    assert.equal(transfer.charterId, charter.charterId)
    assert.equal(transfer.officeId, 'treasury')
    assert.equal(transfer.fromHolder, oldHolder.publicKey)
    assert.equal(transfer.toHolder, newHolder.publicKey)
    assert.equal(transfer.trigger, 'explicit_transfer')
    assert.equal(transfer.delegationHandling, 'transferred')
    assert.ok(transfer.signature.length > 0)
  })

  it('rejects transfer for unknown office', () => {
    const founder = generateKeyPair()
    const charter = createCharter({
      name: 'Bad Transfer',
      offices: [makeOffice('ops', 'Ops', founder.publicKey)],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    assert.throws(() => createOfficeTransfer({
      charter,
      officeId: 'nonexistent',
      fromHolder: null,
      toHolder: founder.publicKey,
      trigger: 'appointment',
      delegationHandling: 'frozen',
      approvalSignatures: [],
      signerPrivateKey: founder.privateKey,
    }), /not found/)
  })

  it('creates an office registry from charter', () => {
    const founder = generateKeyPair()
    const charter = createCharter({
      name: 'Registry Test',
      offices: [
        makeOffice('treasury', 'Treasury', founder.publicKey),
        makeOffice('ops', 'Ops', founder.publicKey),
      ],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    const successionRules = [{
      ruleId: 'rule_1',
      triggerCondition: 'heartbeat_failure' as const,
      fromOffice: 'treasury',
      toOffice: 'ops',
      requiredApprovals: makeThresholdPolicy([founder.publicKey], 1),
      gracePeriodSeconds: 3600,
      delegationHandling: 'freeze' as const,
    }]

    const quorumPolicies: QuorumFailurePolicy[] = [{
      officeId: 'treasury',
      minimumHolders: 1,
      onQuorumLoss: 'freeze_office',
      maxFreezeDurationSeconds: 86400,
    }]

    const registry = createOfficeRegistry(charter, successionRules, quorumPolicies, founder.privateKey)

    assert.equal(registry.charterId, charter.charterId)
    assert.equal(registry.charterVersion, charter.version)
    assert.equal(registry.offices.length, 2)
    assert.equal(registry.successionRules.length, 1)
    assert.equal(registry.quorumFailurePolicies.length, 1)
    assert.ok(registry.contentHash.length > 0)
    assert.ok(registry.signature.length > 0)
  })
})


// ══════════════════════════════════════
// INV-5: No Amendment During Suspension/Dissolution
// ══════════════════════════════════════

describe('Charter — INV-5 Amendment Guard', () => {
  it('rejects amendment on suspended charter', () => {
    const founder = generateKeyPair()
    const charter = createCharter({
      name: 'Suspended test',
      offices: [makeOffice('ops', 'Ops', founder.publicKey)],
      amendmentPolicy: makeThresholdPolicy([founder.publicKey], 1),
      dissolutionPolicy: makeDissolutionPolicy([founder.publicKey]),
      delegationSurvival: SURVIVAL,
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    })

    const suspended = { ...charter, status: 'suspended' as const }
    assert.throws(() => createAmendment({
      charter: suspended,
      proposedCharter: charter,
      description: 'Should fail',
      proposerPrivateKey: founder.privateKey,
      proposerPublicKey: founder.publicKey,
    }), /Cannot amend a suspended charter/)
  })
})
