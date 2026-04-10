// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Credential Check Policy — verification timing for governance metadata
// Proposed by @piiiico on a2aproject/A2A governance metadata thread.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createDelegation,
  revokeDelegation,
  verifyOnAccept,
  evaluateCredentialCheck,
  resolveCheckMode,
} from '../../src/index.js'
import type { Delegation, AcceptanceStamp, CredentialCheckPolicy } from '../../src/index.js'

function makeDelegation(opts: {
  policy?: CredentialCheckPolicy
  scope?: string[]
} = {}): { delegation: Delegation; delegator: ReturnType<typeof generateKeyPair>; delegate: ReturnType<typeof generateKeyPair> } {
  const delegator = generateKeyPair()
  const delegate = generateKeyPair()
  const delegation = createDelegation({
    delegatedTo: delegate.publicKey,
    delegatedBy: delegator.publicKey,
    scope: opts.scope ?? ['api:read'],
    spendLimit: 1000,
    expiresInHours: 24,
    privateKey: delegator.privateKey,
    ...(opts.policy ? { credentialCheckPolicy: opts.policy } : {}),
  })
  return { delegation, delegator, delegate }
}

describe('resolveCheckMode', () => {
  it('returns "on-process" when no policy is set (backward compat)', () => {
    const { delegation } = makeDelegation()
    assert.equal(resolveCheckMode(delegation), 'on-process')
  })

  it('returns the declared mode when policy is present', () => {
    const { delegation: a } = makeDelegation({ policy: { mode: 'on-accept' } })
    assert.equal(resolveCheckMode(a), 'on-accept')
    const { delegation: b } = makeDelegation({ policy: { mode: 'both' } })
    assert.equal(resolveCheckMode(b), 'both')
  })
})

describe('verifyOnAccept', () => {
  it('produces a valid stamp for a freshly created delegation', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'on-accept' } })
    const { valid, errors, stamp } = verifyOnAccept({ delegation, verifierId: 'gateway-test' })
    assert.equal(valid, true, `errors: ${errors.join(', ')}`)
    assert.ok(stamp)
    assert.equal(stamp!.delegation_id, delegation.delegationId)
    assert.equal(stamp!.verifier_id, 'gateway-test')
    assert.ok(stamp!.verified_at.length > 0)
  })

  it('fails on a revoked delegation', () => {
    const { delegation, delegator } = makeDelegation({ policy: { mode: 'both' } })
    revokeDelegation(delegation.delegationId, delegator.publicKey, 'test revocation', delegator.privateKey)
    const result = verifyOnAccept({ delegation })
    assert.equal(result.valid, false)
    assert.equal(result.stamp, undefined)
    assert.ok(result.errors.some(e => /revoked/i.test(e)))
  })
})

describe('evaluateCredentialCheck — on-accept mode', () => {
  it('credential verified at accept, revoked after, action still permitted (trusts snapshot)', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'on-accept' } })
    const { stamp } = verifyOnAccept({ delegation })
    // Even though live state is "revoked" (liveStateValid: false),
    // on-accept trusts the acceptance stamp.
    const result = evaluateCredentialCheck({
      delegation,
      acceptanceStamp: stamp,
      liveStateValid: false,
    })
    assert.equal(result.permitted, true)
    assert.equal(result.mode, 'on-accept')
    assert.equal(result.requiresLiveCheck, false)
  })

  it('on-accept without acceptance stamp denies with CREDENTIAL_NOT_ACCEPTED', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'on-accept' } })
    const result = evaluateCredentialCheck({ delegation, liveStateValid: true })
    assert.equal(result.permitted, false)
    assert.equal(result.denialCode, 'CREDENTIAL_NOT_ACCEPTED')
  })
})

describe('evaluateCredentialCheck — on-process mode (default)', () => {
  it('credential not pre-verified, revoked before action, action denied (catches live revocation)', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'on-process' } })
    const result = evaluateCredentialCheck({
      delegation,
      // No acceptance stamp — that's fine for on-process
      liveStateValid: false,
    })
    assert.equal(result.permitted, false)
    assert.equal(result.denialCode, 'PROCESS_TIME_INVALID')
    assert.equal(result.mode, 'on-process')
  })

  it('on-process with valid live state permits', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'on-process' } })
    const result = evaluateCredentialCheck({ delegation, liveStateValid: true })
    assert.equal(result.permitted, true)
    assert.equal(result.requiresLiveCheck, true)
  })
})

describe('evaluateCredentialCheck — both mode', () => {
  it('valid acceptance + valid live state → permit', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'both' } })
    const { stamp } = verifyOnAccept({ delegation })
    const result = evaluateCredentialCheck({
      delegation,
      acceptanceStamp: stamp,
      liveStateValid: true,
    })
    assert.equal(result.permitted, true)
    assert.equal(result.mode, 'both')
    assert.equal(result.requiresLiveCheck, true)
  })

  it('valid acceptance + revoked live state → deny with PROCESS_TIME_INVALID', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'both' } })
    const { stamp } = verifyOnAccept({ delegation })
    const result = evaluateCredentialCheck({
      delegation,
      acceptanceStamp: stamp,
      liveStateValid: false,
    })
    assert.equal(result.permitted, false)
    assert.equal(result.denialCode, 'PROCESS_TIME_INVALID')
  })

  it('missing acceptance + valid live state → deny with CREDENTIAL_NOT_ACCEPTED', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'both' } })
    const result = evaluateCredentialCheck({
      delegation,
      // no acceptanceStamp
      liveStateValid: true,
    })
    assert.equal(result.permitted, false)
    assert.equal(result.denialCode, 'CREDENTIAL_NOT_ACCEPTED')
  })
})

describe('evaluateCredentialCheck — max_acceptance_age', () => {
  it('acceptance stamp older than max_acceptance_age denies with CREDENTIAL_ACCEPT_STALE', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'on-accept', max_acceptance_age: 60 } })
    // Stamp from 2 minutes ago — exceeds 60s max age
    const stamp: AcceptanceStamp = {
      delegation_id: delegation.delegationId,
      verified_at: new Date(Date.now() - 120_000).toISOString(),
    }
    const result = evaluateCredentialCheck({
      delegation,
      acceptanceStamp: stamp,
      liveStateValid: true,
    })
    assert.equal(result.permitted, false)
    assert.equal(result.denialCode, 'CREDENTIAL_ACCEPT_STALE')
    assert.match(result.reason!, /max_acceptance_age/)
  })

  it('acceptance stamp within max_acceptance_age permits', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'on-accept', max_acceptance_age: 3600 } })
    const { stamp } = verifyOnAccept({ delegation })
    const result = evaluateCredentialCheck({
      delegation,
      acceptanceStamp: stamp,
      liveStateValid: true,
    })
    assert.equal(result.permitted, true)
  })

  it('max_acceptance_age in "both" mode also enforces freshness', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'both', max_acceptance_age: 10 } })
    const stamp: AcceptanceStamp = {
      delegation_id: delegation.delegationId,
      verified_at: new Date(Date.now() - 60_000).toISOString(),
    }
    const result = evaluateCredentialCheck({
      delegation,
      acceptanceStamp: stamp,
      liveStateValid: true,
    })
    assert.equal(result.permitted, false)
    assert.equal(result.denialCode, 'CREDENTIAL_ACCEPT_STALE')
  })

  it('acceptance stamp delegation_id mismatch denies with CREDENTIAL_NOT_ACCEPTED', () => {
    const { delegation } = makeDelegation({ policy: { mode: 'both' } })
    const wrongStamp: AcceptanceStamp = {
      delegation_id: 'del_wrong_id',
      verified_at: new Date().toISOString(),
    }
    const result = evaluateCredentialCheck({
      delegation,
      acceptanceStamp: wrongStamp,
      liveStateValid: true,
    })
    assert.equal(result.permitted, false)
    assert.equal(result.denialCode, 'CREDENTIAL_NOT_ACCEPTED')
    assert.match(result.reason!, /does not match/)
  })
})

describe('evaluateCredentialCheck — backward compatibility', () => {
  it('unspecified policy behaves as on-process: live valid → permit', () => {
    // No credentialCheckPolicy field at all — represents every existing
    // delegation in the wild. Must continue to work unchanged.
    const { delegation } = makeDelegation()
    assert.equal(delegation.credentialCheckPolicy, undefined)

    const result = evaluateCredentialCheck({ delegation, liveStateValid: true })
    assert.equal(result.permitted, true)
    assert.equal(result.mode, 'on-process')
  })

  it('unspecified policy behaves as on-process: live invalid → deny', () => {
    const { delegation } = makeDelegation()
    const result = evaluateCredentialCheck({ delegation, liveStateValid: false })
    assert.equal(result.permitted, false)
    assert.equal(result.denialCode, 'PROCESS_TIME_INVALID')
  })

  it('unspecified policy ignores any provided acceptance stamp', () => {
    const { delegation } = makeDelegation()
    const stamp: AcceptanceStamp = {
      delegation_id: delegation.delegationId,
      verified_at: new Date().toISOString(),
    }
    // Even with a stamp, on-process still requires live valid state
    const result = evaluateCredentialCheck({
      delegation,
      acceptanceStamp: stamp,
      liveStateValid: false,
    })
    assert.equal(result.permitted, false)
    assert.equal(result.denialCode, 'PROCESS_TIME_INVALID')
  })
})
