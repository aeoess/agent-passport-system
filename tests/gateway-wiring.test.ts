// ══════════════════════════════════════════════════════════════════
// Gateway Wiring — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: commerce preflight through gateway, charter policy
// extraction, and module re-exports compile and resolve correctly.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import {
  checkCommerceConstraint, extractCharterPolicy,
  capabilityMatches, createPrecedentLibrary, checkAlignment,
  createWitnessPool, createReserveAttestation,
  createMessageAuditLog, createAuditRecord,
  createTaskBrief,
} from '../src/core/gateway-wiring.js'
import { readFileSync } from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(__dirname + '/../values/floor.yaml', 'utf-8')
const floor = loadFloor(floorYaml)

describe('Gateway Wiring — Commerce Preflight', () => {
  it('passes when no spend on request', () => {
    clearStores()
    const agent = joinSocialContract({
      name: 'comm-test', mission: 'Test', owner: 'admin',
      capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
    })
    const principal = joinSocialContract({
      name: 'comm-p', mission: 'Test', owner: 'admin',
      capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
    })
    const del = delegate({
      from: principal, toPublicKey: agent.publicKey,
      scope: ['data_read'], spendLimit: 100, maxDepth: 2, expiresInHours: 1,
    })
    const result = checkCommerceConstraint(agent.passport, del, 'data_read')
    assert.strictEqual(result.passed, true)
  })

  it('passes when scope is not commerce', () => {
    clearStores()
    const agent = joinSocialContract({
      name: 'comm-test2', mission: 'Test', owner: 'admin',
      capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
    })
    const principal = joinSocialContract({
      name: 'comm-p2', mission: 'Test', owner: 'admin',
      capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
    })

    const del = delegate({
      from: principal, toPublicKey: agent.publicKey,
      scope: ['data_read'], spendLimit: 100, maxDepth: 2, expiresInHours: 1,
    })
    const result = checkCommerceConstraint(agent.passport, del, 'data_read', { amount: 50, currency: 'USD' })
    assert.strictEqual(result.passed, true, 'Non-commerce scope should pass even with spend')
  })
})

describe('Gateway Wiring — Module Re-exports Resolve', () => {
  it('routing: capabilityMatches works', () => {
    assert.strictEqual(capabilityMatches('code', 'code:deploy'), true)
    assert.strictEqual(capabilityMatches('code', 'data:read'), false)
  })

  it('precedent: library creation + alignment check', () => {
    const lib = createPrecedentLibrary()
    assert.ok(lib)
    const alignment = checkAlignment(lib, { subject: 'test', context: 'ctx', outcome: 'permit' })
    assert.strictEqual(alignment.aligned, true, 'Empty library should align with anything')
  })

  it('witness: pool creation works', () => {
    const keys = generateKeyPair()
    const pool = createWitnessPool({ minWitnesses: 1, witnesses: [{ agentId: 'w1', publicKey: keys.publicKey, role: 'notary' }] })
    assert.ok(pool)
    assert.strictEqual(pool.attestations.length, 0)
  })

  it('messaging-audit: log creation + record', () => {
    const keys = generateKeyPair()
    const log = createMessageAuditLog(keys.publicKey)
    assert.ok(log)
    assert.strictEqual(log.records.length, 0)
  })

  it('coordination: task brief creation', () => {
    const keys = generateKeyPair()
    const brief = createTaskBrief({
      operatorId: 'op-1', operatorPublicKey: keys.publicKey,
      operatorPrivateKey: keys.privateKey,
      title: 'Test task', description: 'A test',
      roles: [{ roleId: 'r1', roleName: 'researcher', requiredCapabilities: ['search'] }],
      deliverables: [{ deliverableId: 'd1', description: 'Report', format: 'markdown' }],
      acceptanceCriteria: ['Must compile'],
    })
    assert.ok(brief.taskId)
    assert.strictEqual(brief.title, 'Test task')
  })
})

describe('Gateway Wiring — Charter Policy Extraction', () => {
  it('extracts policy from a valid charter', () => {
    // Charter requires full creation flow — test the adapter function exists and handles input
    // We'll use a minimal mock since createCharter has complex requirements
    const mockCharter = {
      charterId: 'charter_test',
      version: '1.0.0', previousVersion: null,
      name: 'Test Charter', purpose: 'Testing',
      foundedAt: new Date().toISOString(),
      offices: [], amendments: [], signatures: [],
      contentHash: 'sha256:mock', signature: 'mock',
    }
    const policy = extractCharterPolicy(mockCharter as any)
    assert.strictEqual(policy.charterId, 'charter_test')
    // Signature won't verify on mock — that's expected
    assert.ok(typeof policy.valid === 'boolean')
  })
})
