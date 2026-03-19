// ══════════════════════════════════════════════════════════════════
// Gateway — Governance Enforcement Tests (Module 21 / INV-2)
// ══════════════════════════════════════════════════════════════════
//
// Core invariant: governance can only strengthen; weakening requires
// higher-order authorization (more approvals from authorized signers).
// Agents must re-attest when governance updates.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { ProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import {
  createGovernanceArtifact, upgradeGovernanceArtifact,
  approveArtifact, createGovernanceEnvelope
} from '../src/core/governance.js'
import { DEFAULT_LOAD_POLICY } from '../src/types/governance.js'
import type { GatewayConfig, ToolExecutor, ToolCallRequest } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

// ── Helpers ──

const makeExecutor = (): ToolExecutor =>
  async () => ({ success: true, result: 'ok' })

function setup(opts: { governance?: boolean } = {}) {
  clearStores()
  const gatewayKeys = generateKeyPair()
  const issuerKeys = generateKeyPair()    // governance artifact issuer
  const approverKeys = generateKeyPair()  // higher-order approver

  const principal = joinSocialContract({
    name: 'Principal', mission: 'Gov test', owner: 'tester',
    capabilities: ['testing'], platform: 'test', models: ['test-model'], floor
  })
  const agent = joinSocialContract({
    name: 'Gov Agent', mission: 'Governance test', owner: 'tester',
    capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
  })

  const delegation = delegate({
    from: principal, toPublicKey: agent.publicKey,
    scope: ['data:read', 'data:write'], spendLimit: 1000, maxDepth: 2
  })

  // Create initial governance artifact (v1.0.0)
  const govArtifact = createGovernanceArtifact({
    artifactType: 'floor',
    version: '1.0.0',
    content: floorYaml,
    issuerPrivateKey: issuerKeys.privateKey,
    issuerPublicKey: issuerKeys.publicKey,
    changeType: 'initial',
    additions: ['F-001', 'F-002', 'F-003', 'F-004', 'F-005', 'F-006', 'F-007', 'F-008'],
  })
  const govEnvelope = createGovernanceEnvelope(govArtifact)

  const config: GatewayConfig = {
    gatewayId: 'gw-gov-test',
    gatewayPublicKey: gatewayKeys.publicKey,
    gatewayPrivateKey: gatewayKeys.privateKey,
    floor,
    enableGovernanceEnforcement: opts.governance ?? true,
    governanceEnvelope: govEnvelope,
    governanceLoadPolicy: {
      ...DEFAULT_LOAD_POLICY,
      allowedIssuers: [issuerKeys.publicKey],
    },
  }

  const gw = new ProxyGateway(config, makeExecutor())
  const regResult = gw.registerAgent(agent.passport, agent.attestation!, [delegation])
  assert.ok(regResult.registered, `Registration failed: ${regResult.error}`)

  function makeRequest(scopeRequired = 'data:read'): ToolCallRequest {
    const requestId = 'req-' + Math.random().toString(36).slice(2, 8)
    const payload = canonicalize({
      requestId, agentId: agent.agentId, tool: 'read_data', params: {},
      scopeRequired, spend: undefined
    })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool: 'read_data', params: {}, scopeRequired,
    }
  }

  return { gw, agent, principal, delegation, issuerKeys, approverKeys, makeRequest, govArtifact }
}

// ══════════════════════════════════════
// TESTS
// ══════════════════════════════════════

describe('Gateway — Governance Enforcement (INV-2)', () => {

  it('agent with current governance version can execute normally', async () => {
    const { gw, makeRequest } = setup()
    const result = await gw.processToolCall(makeRequest())
    assert.equal(result.executed, true, 'Should execute when governance is current')
  })

  it('agent blocked when governance version is stale', async () => {
    const { gw, agent, issuerKeys, makeRequest, govArtifact } = setup()

    // Upgrade governance to v1.1.0 (strengthening — add principle)
    const newArtifact = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0',
      content: floorYaml + '\n# v1.1.0 addition',
      issuerPrivateKey: issuerKeys.privateKey,
      issuerPublicKey: issuerKeys.publicKey,
      changeType: 'strengthening',
      additions: ['F-009'],
    })
    const envelope = createGovernanceEnvelope(newArtifact)
    const updateResult = gw.updateGovernance(envelope, govArtifact)
    assert.equal(updateResult.accepted, true, 'Strengthening update should be accepted')

    // Agent still attested to v1.0.0 → should be blocked
    const result = await gw.processToolCall(makeRequest())
    assert.equal(result.executed, false)
    assert.ok(result.denialReason?.includes('Governance stale'))
  })

  it('agent unblocked after re-attestation to new governance', async () => {
    const { gw, agent, issuerKeys, makeRequest, govArtifact } = setup()

    // Upgrade governance
    const newArtifact = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0', content: floorYaml + '\n# v1.1.0',
      issuerPrivateKey: issuerKeys.privateKey, issuerPublicKey: issuerKeys.publicKey,
      changeType: 'strengthening', additions: ['F-009'],
    })
    gw.updateGovernance(createGovernanceEnvelope(newArtifact), govArtifact)

    // Re-attest
    const reattest = gw.reattestGovernance(agent.agentId)
    assert.equal(reattest.success, true)

    // Now should work
    const result = await gw.processToolCall(makeRequest())
    assert.equal(result.executed, true, 'Should execute after re-attestation')
  })

  it('strengthening update accepted without extra approvals', async () => {
    const { gw, issuerKeys, govArtifact } = setup()

    const newArtifact = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0', content: floorYaml + '\n# strengthened',
      issuerPrivateKey: issuerKeys.privateKey, issuerPublicKey: issuerKeys.publicKey,
      changeType: 'strengthening', additions: ['F-009'],
    })
    const result = gw.updateGovernance(createGovernanceEnvelope(newArtifact), govArtifact)
    assert.equal(result.accepted, true, 'Strengthening should be accepted without extra approvals')
  })

  it('weakening update BLOCKED without approval', async () => {
    const { gw, issuerKeys, govArtifact } = setup()

    const weakened = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0', content: '# weakened floor',
      issuerPrivateKey: issuerKeys.privateKey, issuerPublicKey: issuerKeys.publicKey,
      changeType: 'weakening', removals: ['F-007'],
    })
    // No approvals — should be blocked by default policy
    const result = gw.updateGovernance(createGovernanceEnvelope(weakened), govArtifact)
    assert.equal(result.accepted, false, 'Weakening without approval should be rejected')
    assert.ok(result.error?.includes('approvals'))
  })

  it('weakening update accepted WITH sufficient approvals', async () => {
    const { gw, issuerKeys, approverKeys, govArtifact } = setup()
    const approver2Keys = generateKeyPair()  // second approver for removals

    const weakened = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0', content: '# weakened floor',
      issuerPrivateKey: issuerKeys.privateKey, issuerPublicKey: issuerKeys.publicKey,
      changeType: 'weakening', removals: ['F-007'],
    })
    // Need 2 approvals for removals (default policy)
    const approval1 = approveArtifact(weakened, approverKeys.privateKey, approverKeys.publicKey)
    const approval2 = approveArtifact(weakened, approver2Keys.privateKey, approver2Keys.publicKey)
    const envelope = createGovernanceEnvelope(weakened, [approval1, approval2])
    const result = gw.updateGovernance(envelope, govArtifact)
    assert.equal(result.accepted, true, 'Weakening with 2 approvals should be accepted')
  })

  it('removal requires more approvals than weakening', async () => {
    const { gw, issuerKeys, approverKeys, govArtifact } = setup()

    const removed = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0', content: '# removed principle',
      issuerPrivateKey: issuerKeys.privateKey, issuerPublicKey: issuerKeys.publicKey,
      changeType: 'weakening', removals: ['F-006', 'F-007'],
    })
    // 1 approval — enough for weakening but not removal (default: 2 required)
    const approval1 = approveArtifact(removed, approverKeys.privateKey, approverKeys.publicKey)
    const envelope = createGovernanceEnvelope(removed, [approval1])
    const result = gw.updateGovernance(envelope, govArtifact)
    assert.equal(result.accepted, false, 'Removal with 1 approval should fail (needs 2)')
  })

  it('gateway rejects unsigned governance artifact', async () => {
    const { gw, govArtifact } = setup()
    const fakeKeys = generateKeyPair()  // unknown issuer

    const fake = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0', content: '# fake update',
      issuerPrivateKey: fakeKeys.privateKey, issuerPublicKey: fakeKeys.publicKey,
      changeType: 'strengthening', additions: ['F-009'],
    })
    const result = gw.updateGovernance(createGovernanceEnvelope(fake), govArtifact)
    assert.equal(result.accepted, false, 'Artifact from unknown issuer should be rejected')
    assert.ok(result.error?.includes('not in allowed issuers'))
  })

  it('governance stats tracked correctly', async () => {
    const { gw, issuerKeys, govArtifact } = setup()

    // Successful update
    const v110 = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0', content: floorYaml + '\n# v1.1.0',
      issuerPrivateKey: issuerKeys.privateKey, issuerPublicKey: issuerKeys.publicKey,
      changeType: 'strengthening', additions: ['F-009'],
    })
    gw.updateGovernance(createGovernanceEnvelope(v110), govArtifact)

    // Failed weakening
    const weak = upgradeGovernanceArtifact(v110, {
      version: '1.2.0', content: '# weakened',
      issuerPrivateKey: issuerKeys.privateKey, issuerPublicKey: issuerKeys.publicKey,
      changeType: 'weakening', removals: ['F-001'],
    })
    gw.updateGovernance(createGovernanceEnvelope(weak), v110)

    const stats = gw.getStats()
    assert.equal(stats.governanceUpdates, 1)
    assert.equal(stats.governanceWeakeningBlocked, 1)
  })

  it('governance version tracking works', async () => {
    const { gw, agent, issuerKeys, govArtifact } = setup()

    assert.equal(gw.getGovernanceVersion(), '1.0.0')
    assert.equal(gw.getAgentGovernanceVersion(agent.agentId), '1.0.0')

    // Upgrade
    const v110 = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0', content: floorYaml + '\n# v1.1.0',
      issuerPrivateKey: issuerKeys.privateKey, issuerPublicKey: issuerKeys.publicKey,
      changeType: 'strengthening', additions: ['F-009'],
    })
    gw.updateGovernance(createGovernanceEnvelope(v110), govArtifact)

    assert.equal(gw.getGovernanceVersion(), '1.1.0')
    assert.equal(gw.getAgentGovernanceVersion(agent.agentId), '1.0.0') // still old

    gw.reattestGovernance(agent.agentId)
    assert.equal(gw.getAgentGovernanceVersion(agent.agentId), '1.1.0') // updated
  })

  it('governance enforcement disabled — agent not blocked by stale version', async () => {
    const { gw, makeRequest } = setup({ governance: false })
    // Even without governance enforcement, tool calls work fine
    const result = await gw.processToolCall(makeRequest())
    assert.equal(result.executed, true)
  })

  it('updateGovernance returns diff for strengthening', async () => {
    const { gw, issuerKeys, govArtifact } = setup()

    const v110 = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0', content: floorYaml + '\n# added F-009',
      issuerPrivateKey: issuerKeys.privateKey, issuerPublicKey: issuerKeys.publicKey,
      changeType: 'strengthening', additions: ['F-009'],
    })
    const result = gw.updateGovernance(createGovernanceEnvelope(v110), govArtifact)
    assert.equal(result.accepted, true)
    assert.ok(result.diff)
    assert.equal(result.diff!.changeType, 'strengthening')
    assert.deepEqual(result.diff!.additions, ['F-009'])
    assert.equal(result.diff!.isStrengthening, true)
    assert.equal(result.diff!.isWeakening, false)
  })

  it('reattestGovernance fails for unknown agent', () => {
    const { gw } = setup()
    const result = gw.reattestGovernance('nonexistent-agent')
    assert.equal(result.success, false)
    assert.ok(result.error?.includes('not registered'))
  })

  it('stale governance blocks executeApproval path too', async () => {
    const { gw, agent, issuerKeys, makeRequest, govArtifact } = setup()

    // Get an approval first
    const approveResult = gw.approve(makeRequest())
    assert.ok(approveResult.approved, 'Should approve before governance update')
    const approvalId = approveResult.approval!.approvalId

    // NOW update governance
    const v110 = upgradeGovernanceArtifact(govArtifact, {
      version: '1.1.0', content: floorYaml + '\n# v1.1.0',
      issuerPrivateKey: issuerKeys.privateKey, issuerPublicKey: issuerKeys.publicKey,
      changeType: 'strengthening', additions: ['F-009'],
    })
    gw.updateGovernance(createGovernanceEnvelope(v110), govArtifact)

    // Execute the pre-approved action — should fail because governance changed
    const result = await gw.executeApproval(approvalId)
    assert.equal(result.executed, false, 'Execution should fail after governance update')
    assert.ok(result.denialReason?.includes('Governance stale'))
  })
})
