/**
 * APS v2 Bridge Tests
 * Run with: npx tsx --test tests/v2-bridge.test.ts
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { generateKeyPair } from '../src/crypto/keys.js'
import { createDelegation } from '../src/core/delegation.js'

import {
  sha256, hashObject, signObject, verifyObject,
  createPolicyContext, isPolicyContextActive, isPolicyContextInGrace,
  v1DelegationToV2, v2DelegationToV1,
  createArtifactProvenance, verifyArtifactIntegrity,
  computeDecayedWeight,
  getUncertaintyRequirements, resolveUncertaintyLevel,
  evaluateConditions,
} from '../src/v2/bridge.js'

const root = generateKeyPair()
const agent = generateKeyPair()

function futureDate(days: number): string {
  const d = new Date(); d.setDate(d.getDate() + days); return d.toISOString()
}
function pastDate(days: number): string {
  const d = new Date(); d.setDate(d.getDate() - days); return d.toISOString()
}

describe('v2 Crypto Bridge', () => {
  it('sha256 produces consistent 64-char hex', () => {
    const h1 = sha256('hello')
    const h2 = sha256('hello')
    assert.equal(h1, h2)
    assert.equal(h1.length, 64)
  })

  it('hashObject deterministic regardless of key order', () => {
    const a = { z: 1, a: 2 } as any
    const b = { a: 2, z: 1 } as any
    assert.equal(hashObject(a), hashObject(b))
  })

  it('signObject and verifyObject round-trip with v1 keys', () => {
    const obj = { action: 'test', ts: Date.now() } as any
    const sig = signObject(obj, root.privateKey)
    assert.ok(verifyObject(obj, sig, root.publicKey))
  })

  it('verifyObject rejects tampered data', () => {
    const obj = { data: 'original' } as any
    const sig = signObject(obj, root.privateKey)
    assert.ok(!verifyObject({ data: 'tampered' } as any, sig, root.publicKey))
  })

  it('verifyObject rejects wrong key', () => {
    const obj = { data: 'test' } as any
    const sig = signObject(obj, root.privateKey)
    assert.ok(!verifyObject(obj, sig, agent.publicKey))
  })
})

describe('v2 PolicyContext', () => {
  it('creates valid PolicyContext with mandatory sunset', () => {
    const ctx = createPolicyContext({
      policy_version: '2.0.0', values_floor_version: '1.0.0',
      trust_epoch: 1, issuer_id: root.publicKey,
      valid_until: futureDate(90),
    })
    assert.equal(ctx.policy_version, '2.0.0')
    assert.ok(ctx.valid_until)
    assert.ok(ctx.created_at)
  })

  it('rejects missing valid_until', () => {
    assert.throws(() => {
      createPolicyContext({
        policy_version: '2.0.0', values_floor_version: '1.0.0',
        trust_epoch: 1, issuer_id: root.publicKey,
        valid_until: '',
      })
    })
  })

  it('rejects lifetime exceeding 180 days', () => {
    assert.throws(() => {
      createPolicyContext({
        policy_version: '2.0.0', values_floor_version: '1.0.0',
        trust_epoch: 1, issuer_id: root.publicKey,
        valid_until: futureDate(365),
      })
    })
  })

  it('isPolicyContextActive checks validity window', () => {
    const ctx = createPolicyContext({
      policy_version: '2.0.0', values_floor_version: '1.0.0',
      trust_epoch: 1, issuer_id: root.publicKey,
      valid_until: futureDate(90),
    })
    assert.ok(isPolicyContextActive(ctx))
    const expired = { ...ctx, valid_from: pastDate(100), valid_until: pastDate(10) }
    assert.ok(!isPolicyContextActive(expired))
  })

  it('isPolicyContextInGrace detects grace period', () => {
    const ctx = createPolicyContext({
      policy_version: '2.0.0', values_floor_version: '1.0.0',
      trust_epoch: 1, issuer_id: root.publicKey,
      valid_until: futureDate(90),
    })
    const expiredYesterday = { ...ctx, valid_from: pastDate(100), valid_until: pastDate(1) }
    assert.ok(!isPolicyContextActive(expiredYesterday))
    assert.ok(isPolicyContextInGrace(expiredYesterday))
  })
})

describe('v1 ↔ v2 Delegation Conversion', () => {
  it('converts v1 Delegation to v2 and back', () => {
    const v1Del = createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: root.publicKey,
      scope: ['analysis', 'communication'],
      expiresAt: futureDate(30), maxDepth: 3, currentDepth: 0,
      privateKey: root.privateKey,
    })
    const ctx = createPolicyContext({
      policy_version: '2.0.0', values_floor_version: '1.0.0',
      trust_epoch: 1, issuer_id: root.publicKey, valid_until: futureDate(90),
    })
    const v2Del = v1DelegationToV2(v1Del, ctx)
    assert.equal(v2Del.id, v1Del.delegationId)
    assert.equal(v2Del.delegator, root.publicKey)
    assert.equal(v2Del.delegatee, agent.publicKey)
    assert.deepEqual(v2Del.scope.action_categories, ['analysis', 'communication'])
    assert.equal(v2Del.version, 1)
    assert.equal(v2Del.status, 'active')

    const backToV1 = v2DelegationToV1(v2Del)
    assert.equal(backToV1.delegationId, v1Del.delegationId)
    assert.deepEqual(backToV1.scope, v1Del.scope)
  })
})

describe('v2 Artifact Provenance', () => {
  it('creates provenance with content hash and verifies integrity', () => {
    const content = 'SELECT * FROM orders WHERE status = "pending";'
    const ctx = createPolicyContext({
      policy_version: '2.0.0', values_floor_version: '1.0.0',
      trust_epoch: 1, issuer_id: root.publicKey, valid_until: futureDate(90),
    })
    const prov = createArtifactProvenance({
      authoring_agent: agent.publicKey,
      authority_scope: { action_categories: ['data_retrieval'] },
      delegation_ref: 'del-001', intended_use: 'Query pending orders',
      risk_class: 'medium', requires_human_execution: true,
      content, artifact_type: 'database_query',
      policy_context: ctx, agent_private_key: agent.privateKey,
    })
    assert.equal(prov.content_hash.length, 64)
    assert.ok(prov.signature)
    assert.ok(verifyArtifactIntegrity(prov, content))
    assert.ok(!verifyArtifactIntegrity(prov, 'DROP TABLE orders;'))
  })
})

describe('v2 Reputation Decay', () => {
  it('no decay in same epoch', () => {
    assert.equal(computeDecayedWeight(100, 1, 1), 100)
  })
  it('15% decay per epoch (default)', () => {
    const w = computeDecayedWeight(100, 1, 2)
    assert.ok(Math.abs(w - 85) < 0.01)
  })
  it('domain-specific decay rates', () => {
    const cyber = computeDecayedWeight(100, 1, 3, 'cybersecurity')
    const doc = computeDecayedWeight(100, 1, 3, 'document_processing')
    assert.ok(cyber < doc, 'Cybersecurity should decay faster')
  })
})

describe('v2 Semantic Uncertainty', () => {
  it('low: no requirements', () => {
    const r = getUncertaintyRequirements('low')
    assert.ok(!r.requires_attestation)
    assert.equal(r.review_mode, 'none')
  })
  it('critical: full enforcement', () => {
    const r = getUncertaintyRequirements('critical')
    assert.ok(r.requires_attestation)
    assert.ok(r.requires_external_cosign)
    assert.equal(r.review_mode, 'sync')
    assert.equal(r.audit_sample_rate, 1.0)
  })
  it('agents can only raise uncertainty', () => {
    assert.equal(resolveUncertaintyLevel('medium', 'high'), 'high')
    assert.equal(resolveUncertaintyLevel('high', 'low'), 'high')
  })
})

describe('v2 Emergency Conditions', () => {
  it('evaluates all_of conditions', () => {
    assert.ok(evaluateConditions(
      { all_of: [{ field: 'level', operator: 'gte', value: 9 }] },
      { level: 10 }
    ))
    assert.ok(!evaluateConditions(
      { all_of: [{ field: 'level', operator: 'gte', value: 9 }] },
      { level: 3 }
    ))
  })
  it('evaluates any_of conditions', () => {
    assert.ok(evaluateConditions(
      { any_of: [
        { field: 'temp', operator: 'gt', value: 100 },
        { field: 'alert', operator: 'eq', value: true },
      ]},
      { temp: 50, alert: true }
    ))
  })
  it('fails on missing field', () => {
    assert.ok(!evaluateConditions(
      { all_of: [{ field: 'nonexistent', operator: 'eq', value: true }] },
      { other: 'data' }
    ))
  })
})
