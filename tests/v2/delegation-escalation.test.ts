// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// v2 HumanEscalationFlag — per-action-class owner-confirmation tests.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createV2Delegation, clearV2DelegationStore,
  createPolicyContext,
  checkEscalationRequired, requestOwnerConfirmation, recordOwnerConfirmation,
  verifyOwnerConfirmation, isConfirmationValid, verifyV2DelegationForAction,
  hashActionDetails, DEFAULT_FLAGGED_ACTION_CLASSES,
} from '../../src/index.js'
import type {
  V2Delegation, V2ScopeDefinition, EscalationRequirement,
  ConfirmationRequest, OwnerConfirmation,
} from '../../src/v2/types.js'

const owner = generateKeyPair()
const stranger = generateKeyPair()
const agent = generateKeyPair()

function policy() {
  return createPolicyContext({
    policy_version: 'v1',
    values_floor_version: 'v1',
    trust_epoch: 1,
    issuer_id: 'issuer-1',
    valid_from: new Date(Date.now() - 1000).toISOString(),
    valid_until: new Date(Date.now() + 3600_000).toISOString(),
  })
}

function mkDelegation(requirements: EscalationRequirement[] = []): V2Delegation {
  const scope: V2ScopeDefinition = {
    action_categories: ['org_creation', 'spend', 'read'],
    escalation_requirements: requirements.length ? requirements : undefined,
  }
  return createV2Delegation({
    delegator: owner.publicKey,
    delegatee: agent.publicKey,
    scope,
    policy_context: policy(),
    delegator_private_key: owner.privateKey,
  })
}

const PER_ACTION: EscalationRequirement = {
  action_class: 'org_creation',
  requires_owner_confirmation: true,
  confirmation_ttl_ms: 60_000,
  confirmation_scope: 'per_action',
}
const PER_SESSION: EscalationRequirement = {
  action_class: 'spend',
  requires_owner_confirmation: true,
  confirmation_ttl_ms: 60_000,
  confirmation_scope: 'per_session',
}
const TIME_WINDOW: EscalationRequirement = {
  action_class: 'org_creation',
  requires_owner_confirmation: true,
  confirmation_ttl_ms: 60_000,
  confirmation_scope: 'time_window',
}

describe('HumanEscalationFlag — default flagged classes', () => {
  it('documents the canonical high-stakes action classes', () => {
    assert.ok(DEFAULT_FLAGGED_ACTION_CLASSES.includes('org_creation'))
    assert.ok(DEFAULT_FLAGGED_ACTION_CLASSES.includes('third_party_attribution'))
    assert.ok(DEFAULT_FLAGGED_ACTION_CLASSES.includes('spend_above_threshold'))
    assert.ok(DEFAULT_FLAGGED_ACTION_CLASSES.includes('charter_amendment'))
    assert.ok(DEFAULT_FLAGGED_ACTION_CLASSES.includes('delegation_scope_expansion'))
  })
})

describe('HumanEscalationFlag — checkEscalationRequired', () => {
  beforeEach(() => clearV2DelegationStore())

  it('unflagged action class passes without confirmation', () => {
    const d = mkDelegation([])
    const r = checkEscalationRequired(d, { action_class: 'read', action_details: {} })
    assert.equal(r.required, false)
  })

  it('flagged action class reports required=true with the requirement', () => {
    const d = mkDelegation([PER_ACTION])
    const r = checkEscalationRequired(d, { action_class: 'org_creation', action_details: { name: 'Foo' } })
    assert.equal(r.required, true)
    assert.equal(r.requirement?.action_class, 'org_creation')
    assert.ok(r.reason?.includes('action_requires_confirmation'))
  })

  it('flagged requirement with requires_owner_confirmation=false does not require', () => {
    const disabled: EscalationRequirement = { ...PER_ACTION, requires_owner_confirmation: false }
    const d = mkDelegation([disabled])
    const r = checkEscalationRequired(d, { action_class: 'org_creation', action_details: {} })
    assert.equal(r.required, false)
  })
})

describe('HumanEscalationFlag — verify chain (verifyV2DelegationForAction)', () => {
  beforeEach(() => clearV2DelegationStore())

  it('unflagged scope passes without any confirmations (backwards compatible)', () => {
    const d = mkDelegation([])
    const r = verifyV2DelegationForAction(d, { action_class: 'read', action_details: {} })
    assert.equal(r.valid, true)
    assert.notEqual(r.escalation_required, true)
  })

  it('flagged action without confirmation: verify fails', () => {
    const d = mkDelegation([PER_ACTION])
    const r = verifyV2DelegationForAction(d, { action_class: 'org_creation', action_details: { n: 1 } })
    assert.equal(r.valid, false)
    assert.equal(r.escalation_required, true)
    assert.equal(r.reason, 'action_requires_confirmation')
  })

  it('flagged action with valid confirmation: passes', () => {
    const d = mkDelegation([PER_ACTION])
    const action = { action_class: 'org_creation', action_details: { n: 1 } }
    const req = requestOwnerConfirmation(d, action)
    const conf = recordOwnerConfirmation({ request: req, delegation: d, owner_private_key: owner.privateKey })
    const r = verifyV2DelegationForAction(d, action, [conf])
    assert.equal(r.valid, true)
    assert.equal(r.escalation_required, true)
  })
})

describe('HumanEscalationFlag — per_action scope', () => {
  beforeEach(() => clearV2DelegationStore())

  it('per_action confirmation covers exactly one action (hash match)', () => {
    const d = mkDelegation([PER_ACTION])
    const a = { action_class: 'org_creation', action_details: { name: 'Acme' } }
    const req = requestOwnerConfirmation(d, a)
    const conf = recordOwnerConfirmation({ request: req, delegation: d, owner_private_key: owner.privateKey })
    const v = verifyOwnerConfirmation(conf, a, d)
    assert.equal(v.valid, true)
  })

  it('per_action confirmation for different action_details: fails', () => {
    const d = mkDelegation([PER_ACTION])
    const a1 = { action_class: 'org_creation', action_details: { name: 'Acme' } }
    const a2 = { action_class: 'org_creation', action_details: { name: 'Other' } }
    const req = requestOwnerConfirmation(d, a1)
    const conf = recordOwnerConfirmation({ request: req, delegation: d, owner_private_key: owner.privateKey })
    const v = verifyOwnerConfirmation(conf, a2, d)
    assert.equal(v.valid, false)
    assert.match(v.reason!, /per_action details hash mismatch/)
  })

  it('hashActionDetails is deterministic and sensitive to content', () => {
    const h1 = hashActionDetails({ a: 1 })
    const h2 = hashActionDetails({ a: 1 })
    const h3 = hashActionDetails({ a: 2 })
    assert.equal(h1, h2)
    assert.notEqual(h1, h3)
  })
})

describe('HumanEscalationFlag — per_session scope', () => {
  beforeEach(() => clearV2DelegationStore())

  it('per_session confirmation covers multiple actions of same class in session', () => {
    const d = mkDelegation([PER_SESSION])
    const a1 = { action_class: 'spend', action_details: { amt: 10 }, session_id: 'S1' }
    const a2 = { action_class: 'spend', action_details: { amt: 20 }, session_id: 'S1' }
    const req = requestOwnerConfirmation(d, a1)
    const conf = recordOwnerConfirmation({ request: req, delegation: d, owner_private_key: owner.privateKey })
    assert.equal(verifyOwnerConfirmation(conf, a1, d).valid, true)
    assert.equal(verifyOwnerConfirmation(conf, a2, d).valid, true)
  })

  it('per_session confirmation rejects action from different session', () => {
    const d = mkDelegation([PER_SESSION])
    const a1 = { action_class: 'spend', action_details: { amt: 10 }, session_id: 'S1' }
    const a2 = { action_class: 'spend', action_details: { amt: 20 }, session_id: 'S2' }
    const req = requestOwnerConfirmation(d, a1)
    const conf = recordOwnerConfirmation({ request: req, delegation: d, owner_private_key: owner.privateKey })
    const v = verifyOwnerConfirmation(conf, a2, d)
    assert.equal(v.valid, false)
    assert.match(v.reason!, /per_session/)
  })

  it('requestOwnerConfirmation throws when per_session action lacks session_id', () => {
    const d = mkDelegation([PER_SESSION])
    assert.throws(
      () => requestOwnerConfirmation(d, { action_class: 'spend', action_details: {} }),
      /session_id/,
    )
  })
})

describe('HumanEscalationFlag — time_window scope', () => {
  beforeEach(() => clearV2DelegationStore())

  it('time_window confirmation valid for any same-class action within ttl', () => {
    const d = mkDelegation([TIME_WINDOW])
    const a1 = { action_class: 'org_creation', action_details: { n: 1 } }
    const a2 = { action_class: 'org_creation', action_details: { n: 99 } }
    const req = requestOwnerConfirmation(d, a1)
    const conf = recordOwnerConfirmation({ request: req, delegation: d, owner_private_key: owner.privateKey })
    assert.equal(verifyOwnerConfirmation(conf, a1, d).valid, true)
    assert.equal(verifyOwnerConfirmation(conf, a2, d).valid, true)
  })

  it('expired confirmation fails (even within scope)', () => {
    const shortTtl: EscalationRequirement = { ...TIME_WINDOW, confirmation_ttl_ms: 1 }
    const d = mkDelegation([shortTtl])
    const a = { action_class: 'org_creation', action_details: {} }
    const req = requestOwnerConfirmation(d, a)
    const conf = recordOwnerConfirmation({ request: req, delegation: d, owner_private_key: owner.privateKey })
    const future = new Date(Date.now() + 60_000)
    assert.equal(isConfirmationValid(conf, future), false)
    const v = verifyOwnerConfirmation(conf, a, d, future)
    assert.equal(v.valid, false)
    assert.match(v.reason!, /expired/)
  })
})

describe('HumanEscalationFlag — signature & principal binding', () => {
  beforeEach(() => clearV2DelegationStore())

  it('confirmation signed by wrong principal: fails', () => {
    const d = mkDelegation([PER_ACTION])
    const a = { action_class: 'org_creation', action_details: { n: 1 } }
    const req = requestOwnerConfirmation(d, a)
    // Stranger signs the confirmation body
    const conf = recordOwnerConfirmation({ request: req, delegation: d, owner_private_key: stranger.privateKey })
    // confirmed_by is still the delegator (owner), so signature won't verify
    const v = verifyOwnerConfirmation(conf, a, d)
    assert.equal(v.valid, false)
    assert.match(v.reason!, /signature/)
  })

  it('tampered confirmation signature: fails', () => {
    const d = mkDelegation([PER_ACTION])
    const a = { action_class: 'org_creation', action_details: { n: 1 } }
    const req = requestOwnerConfirmation(d, a)
    const conf = recordOwnerConfirmation({ request: req, delegation: d, owner_private_key: owner.privateKey })
    const tampered: OwnerConfirmation = { ...conf, action_class: 'read' as any }
    const v = verifyOwnerConfirmation(tampered, { ...a, action_class: 'read' }, d)
    assert.equal(v.valid, false)
  })

  it('confirmation from mismatched delegation_id: fails', () => {
    const d1 = mkDelegation([PER_ACTION])
    const d2 = mkDelegation([PER_ACTION])
    const a = { action_class: 'org_creation', action_details: { n: 1 } }
    const req = requestOwnerConfirmation(d1, a)
    const conf = recordOwnerConfirmation({ request: req, delegation: d1, owner_private_key: owner.privateKey })
    const v = verifyOwnerConfirmation(conf, a, d2)
    assert.equal(v.valid, false)
    assert.match(v.reason!, /delegation_id/)
  })

  it('recordOwnerConfirmation rejects request whose delegation_id does not match', () => {
    const d1 = mkDelegation([PER_ACTION])
    const d2 = mkDelegation([PER_ACTION])
    const a = { action_class: 'org_creation', action_details: { n: 1 } }
    const req = requestOwnerConfirmation(d1, a)
    assert.throws(
      () => recordOwnerConfirmation({ request: req, delegation: d2, owner_private_key: owner.privateKey }),
      /delegation_id/,
    )
  })
})

describe('HumanEscalationFlag — isConfirmationValid', () => {
  beforeEach(() => clearV2DelegationStore())

  it('returns true before expiry, false after', () => {
    const d = mkDelegation([PER_ACTION])
    const a = { action_class: 'org_creation', action_details: { n: 1 } }
    const req = requestOwnerConfirmation(d, a)
    const conf = recordOwnerConfirmation({ request: req, delegation: d, owner_private_key: owner.privateKey })
    assert.equal(isConfirmationValid(conf, new Date()), true)
    assert.equal(isConfirmationValid(conf, new Date(Date.now() + 120_000)), false)
  })
})
