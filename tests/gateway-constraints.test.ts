// ══════════════════════════════════════════════════════════════════
// Constraint Architecture — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: ConstraintVector, AuthorizationWitness, AuthorizationRef,
// ConstraintFailure on denials, and forensic linkage from receipts.
// ══════════════════════════════════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { ProxyGateway, createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { revokeDelegation, clearStores } from '../src/core/delegation.js'
import type { ToolCallRequest, ToolExecutor, GatewayConfig } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ── Test helpers ──
const floorYaml = readFileSync(join(__dirname, '..', 'values', 'floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

const mockExecutor: ToolExecutor = async (tool, params) => ({ success: true, result: { tool, params } })
const failingExecutor: ToolExecutor = async () => ({ success: false, error: 'Tool failed' })

function createTestSetup() {
  clearStores()
  const gwKeys = generateKeyPair()

  // Principal needs to be a social contract result (delegate expects .keyPair)
  const principal = joinSocialContract({
    name: 'test-principal', mission: 'Testing',
    owner: 'admin', capabilities: ['data_read', 'code_execution'],
    platform: 'node', models: ['test'], floor,
    beneficiary: { id: 'admin', relationship: 'creator' },
  })

  const agent = joinSocialContract({
    name: 'constraint-test-agent', mission: 'Testing constraint architecture',
    owner: 'test-principal', capabilities: ['data_read', 'code_execution'],
    platform: 'node', models: ['test'], floor,
    beneficiary: { id: 'test-principal', relationship: 'creator' },
  })

  const agentKeys = agent.keyPair

  const del = delegate({
    from: principal, toPublicKey: agent.publicKey,
    scope: ['data_read', 'code_execution'], spendLimit: 500, maxDepth: 2,
    expiresInHours: 1,
  })

  const config: GatewayConfig = {
    gatewayId: 'gw-constraint-test',
    gatewayPublicKey: gwKeys.publicKey,
    gatewayPrivateKey: gwKeys.privateKey,
    floor, recheckRevocationOnExecute: true,
  }

  const gateway = createProxyGateway(config, mockExecutor)
  gateway.registerAgent(agent.passport, agent.attestation, [del])

  function makeRequest(overrides?: Partial<ToolCallRequest>): ToolCallRequest {
    const base = {
      requestId: 'req-' + Math.random().toString(36).slice(2, 10),
      agentId: agent.agentId,
      agentPublicKey: agent.publicKey,
      tool: 'database_query',
      params: { query: 'SELECT 1' },
      scopeRequired: 'data_read',
      ...overrides,
    }
    const payload = canonicalize({ requestId: base.requestId, agentId: base.agentId, tool: base.tool, params: base.params, scopeRequired: base.scopeRequired, spend: (base as any).spend })
    return { ...base, signature: sign(payload, agentKeys.privateKey) }
  }

  return { gateway, agent, del, principal, agentKeys, gwKeys, makeRequest }
}

// ══════════════════════════════════════════════════════════════════
// Test Suite: Constraint Vector on Permitted Actions
// ══════════════════════════════════════════════════════════════════

describe('Constraint Architecture — Permitted Actions', () => {
  it('successful execution produces a ConstraintVector with outcome=permitted', async () => {
    const { gateway, makeRequest } = createTestSetup()
    const result = await gateway.processToolCall(makeRequest())

    assert.strictEqual(result.executed, true)
    assert.ok(result.constraintVector, 'constraintVector must be present on successful execution')
    assert.strictEqual(result.constraintVector.outcome, 'permitted')
    assert.strictEqual(result.constraintVector.failures.length, 0)
    assert.strictEqual(result.constraintVector.primaryFailure, undefined)
  })

  it('constraint vector contains per-facet evaluations', async () => {
    const { gateway, makeRequest } = createTestSetup()
    const result = await gateway.processToolCall(makeRequest())

    const cv = result.constraintVector!
    assert.ok(cv.facets.length >= 4, `Expected at least 4 facet evaluations, got ${cv.facets.length}`)

    const facetNames = cv.facets.map(f => f.facet)
    assert.ok(facetNames.includes('identity'), 'Must evaluate identity facet')
    assert.ok(facetNames.includes('replay'), 'Must evaluate replay facet')
    assert.ok(facetNames.includes('scope'), 'Must evaluate scope facet')
    assert.ok(facetNames.includes('revocation'), 'Must evaluate revocation facet')

    // All should pass
    for (const facet of cv.facets) {
      assert.ok(facet.status === 'pass' || facet.status === 'not_applicable',
        `Facet ${facet.facet} should be pass or not_applicable, got ${facet.status}`)
    }
  })

  it('time facet includes headroom when delegation has expiry', async () => {
    const { gateway, makeRequest } = createTestSetup()
    const result = await gateway.processToolCall(makeRequest())

    const timeFacet = result.constraintVector!.facets.find(f => f.facet === 'time')
    assert.ok(timeFacet, 'time facet must be present')
    assert.strictEqual(timeFacet.status, 'pass')
    assert.ok(timeFacet.headroom !== undefined, 'time facet should have headroom')
  })
})

// ══════════════════════════════════════════════════════════════════
// Test Suite: Authorization Witness
// ══════════════════════════════════════════════════════════════════

describe('Constraint Architecture — Authorization Witness', () => {
  it('successful execution produces an AuthorizationWitness', async () => {
    const { gateway, makeRequest } = createTestSetup()
    const result = await gateway.processToolCall(makeRequest())

    assert.ok(result.authorizationWitness, 'authorizationWitness must be present')
    const aw = result.authorizationWitness
    assert.strictEqual(aw.status, 'valid')
    assert.ok(aw.witnessId.startsWith('aw_'), 'witnessId must start with aw_')
    assert.ok(aw.gatewaySignature.length > 0, 'witness must be signed by gateway')
    assert.ok(aw.authorizationHash.length > 0, 'witness must have integrity hash')
    assert.ok(aw.timestamp, 'witness must have timestamp')
  })

  it('witness contains the constraint vector', async () => {
    const { gateway, makeRequest } = createTestSetup()
    const result = await gateway.processToolCall(makeRequest())

    const aw = result.authorizationWitness!
    assert.ok(aw.constraints, 'witness must embed the constraint vector')
    assert.strictEqual(aw.constraints.outcome, 'permitted')
    assert.strictEqual(aw.constraints.failures.length, 0)
  })

  it('witness records delegation scope', async () => {
    const { gateway, makeRequest } = createTestSetup()
    const result = await gateway.processToolCall(makeRequest())

    const aw = result.authorizationWitness!
    assert.ok(aw.scopeAuthorized.includes('data_read'), 'witness should record authorized scope')
    assert.ok(aw.delegationId, 'witness should reference delegation')
  })
})

// ══════════════════════════════════════════════════════════════════
// Test Suite: Receipt ↔ Authorization Linkage (Forensic Chain)
// ══════════════════════════════════════════════════════════════════

describe('Constraint Architecture — Forensic Linkage', () => {
  it('receipt contains authorizationRef linking to witness', async () => {
    const { gateway, makeRequest } = createTestSetup()
    const result = await gateway.processToolCall(makeRequest())

    assert.ok(result.receipt, 'receipt must be present')
    assert.ok(result.receipt.authorizationRef, 'receipt must contain authorizationRef')

    const ref = result.receipt.authorizationRef
    const aw = result.authorizationWitness!
    assert.strictEqual(ref.witnessId, aw.witnessId, 'ref must point to the witness')
    assert.strictEqual(ref.witnessHash, aw.authorizationHash, 'ref hash must match witness hash')
    assert.strictEqual(ref.status, 'valid')
    assert.strictEqual(ref.constraintOutcome, 'permitted')
    assert.strictEqual(ref.failureCount, 0)
    assert.strictEqual(ref.primaryFailureFacet, undefined)
  })
})

// ══════════════════════════════════════════════════════════════════
// Test Suite: Structured Constraint Failures (replaces free-text)
// ══════════════════════════════════════════════════════════════════

describe('Constraint Architecture — Structured Denials', () => {
  it('replay denial produces structured ConstraintFailure with facet=replay', async () => {
    const { gateway, makeRequest } = createTestSetup()
    const req = makeRequest({ requestId: 'replay-test-001' })
    await gateway.processToolCall(req) // first call succeeds

    // Same requestId = replay
    const result = await gateway.processToolCall(req)
    assert.strictEqual(result.executed, false)
    assert.ok(result.constraintFailures, 'must have structured failures')
    assert.strictEqual(result.constraintFailures.length, 1)
    assert.strictEqual(result.constraintFailures[0].facet, 'replay')
    assert.strictEqual(result.constraintFailures[0].code, 'REPLAY_DETECTED')
    assert.strictEqual(result.constraintFailures[0].severity, 'hard')
    assert.strictEqual(result.constraintFailures[0].retryable, false)
    // Backward compat: denialReason still present
    assert.ok(result.denialReason, 'denialReason must still be present for backward compat')
  })

  it('unregistered agent denial has facet=identity code=AGENT_NOT_REGISTERED', async () => {
    const { gateway, agentKeys } = createTestSetup()
    const payload = canonicalize({ requestId: 'unreg-001', agentId: 'fake-agent', tool: 'test', params: {}, scopeRequired: 'data_read', spend: undefined })
    const result = await gateway.processToolCall({
      requestId: 'unreg-001', agentId: 'fake-agent', agentPublicKey: agentKeys.publicKey,
      tool: 'test', params: {}, scopeRequired: 'data_read',
      signature: sign(payload, agentKeys.privateKey),
    })

    assert.strictEqual(result.executed, false)
    assert.ok(result.constraintFailures)
    assert.strictEqual(result.constraintFailures[0].facet, 'identity')
    assert.strictEqual(result.constraintFailures[0].code, 'AGENT_NOT_REGISTERED')
  })

  it('scope violation denial has facet=scope code=NO_VALID_DELEGATION', async () => {
    const { gateway, makeRequest } = createTestSetup()
    // Request a scope not in the delegation
    const req = makeRequest({ scopeRequired: 'admin_access', tool: 'admin_panel' })
    const result = await gateway.processToolCall(req)

    assert.strictEqual(result.executed, false)
    assert.ok(result.constraintFailures)
    assert.strictEqual(result.constraintFailures[0].facet, 'scope')
    assert.strictEqual(result.constraintFailures[0].code, 'NO_VALID_DELEGATION')
    assert.strictEqual(result.constraintFailures[0].actual, 'admin_access')
  })

  it('revocation denial has facet=revocation code=REVOKED_AT_EXECUTION', async () => {
    const { gateway, makeRequest, del, principal } = createTestSetup()
    // Revoke the delegation
    revokeDelegation(del.delegationId, principal.publicKey, 'test revoke', principal.keyPair.privateKey)
    const result = await gateway.processToolCall(makeRequest())

    assert.strictEqual(result.executed, false)
    assert.ok(result.constraintFailures)
    // Could be revocation or time facet depending on which check fires first
    const revFail = result.constraintFailures.find(f => f.facet === 'revocation')
    assert.ok(revFail, 'must have revocation failure')
  })

  it('denied results include constraintVector with outcome=denied', async () => {
    const { gateway, makeRequest } = createTestSetup()
    const req = makeRequest({ scopeRequired: 'admin_access', tool: 'admin_panel' })
    const result = await gateway.processToolCall(req)

    assert.ok(result.constraintVector, 'denied results must also have constraintVector')
    assert.strictEqual(result.constraintVector.outcome, 'denied')
    assert.ok(result.constraintVector.failures.length > 0, 'must have at least one failure')
    assert.ok(result.constraintVector.primaryFailure, 'must identify primary failure')
  })

  it('invalid signature denial has facet=identity code=INVALID_SIGNATURE', async () => {
    const { gateway, agent } = createTestSetup()
    const wrongKeys = generateKeyPair()
    const payload = canonicalize({ requestId: 'badsig-001', agentId: agent.agentId, tool: 'test', params: {}, scopeRequired: 'data_read', spend: undefined })
    const result = await gateway.processToolCall({
      requestId: 'badsig-001', agentId: agent.agentId, agentPublicKey: agent.publicKey,
      tool: 'test', params: {}, scopeRequired: 'data_read',
      signature: sign(payload, wrongKeys.privateKey), // wrong key
    })

    assert.strictEqual(result.executed, false)
    assert.ok(result.constraintFailures)
    assert.strictEqual(result.constraintFailures[0].facet, 'identity')
    assert.strictEqual(result.constraintFailures[0].code, 'INVALID_SIGNATURE')
  })
})
