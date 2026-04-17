// ══════════════════════════════════════════════════════════════
// The Social Contract — High-Level API Test
// ══════════════════════════════════════════════════════════════
// This is how someone ACTUALLY uses the protocol.
// If this test doesn't feel simple, we failed.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  joinSocialContract, verifySocialContract,
  delegate, recordWork, proveContributions, auditCompliance,
  generateKeyPair, loadFloor, clearStores
} from '../src/index.js'

const FLOOR = `
version: "0.1"
schema: "agent-social-contract/values-floor"
last_updated: "2026-02-20"
governance_uri: "https://aeoess.com/protocol.html"
floor:
  - id: "F-001"
    name: "Traceability"
    principle: "Every action traceable to a human"
    enforcement:
      technical: true
      mechanism: "Delegation chains"
    weight: "mandatory"
  - id: "F-002"
    name: "Honest Identity"
    principle: "No identity misrepresentation"
    enforcement:
      technical: true
      mechanism: "Passport verification"
    weight: "mandatory"
  - id: "F-003"
    name: "Scoped Authority"
    principle: "Act within delegated scope"
    enforcement:
      technical: true
      mechanism: "Delegation scope limits"
    weight: "mandatory"
  - id: "F-004"
    name: "Revocability"
    principle: "Humans can revoke authority"
    enforcement:
      technical: true
      mechanism: "Revocation registry"
    weight: "mandatory"
  - id: "F-005"
    name: "Auditability"
    principle: "All actions auditable"
    enforcement:
      technical: true
      mechanism: "Action receipts"
    weight: "mandatory"
  - id: "F-006"
    name: "Non-Deception"
    principle: "No deception"
    enforcement:
      technical: false
      mechanism: "Reputation"
    weight: "strong_consideration"
  - id: "F-007"
    name: "Proportionality"
    principle: "Autonomy proportional to trust"
    enforcement:
      technical: false
      mechanism: "Reputation"
    weight: "strong_consideration"
`

test('The Simple Version — Complete workflow in 20 lines', async (t) => {
  clearStores()
  const floor = loadFloor(FLOOR)

  // 1. HUMAN: creates a keypair (represents the human principal)
  const human = generateKeyPair()

  // 2. JOIN: Agent joins the social contract
  const agent = joinSocialContract({
    name: 'Aeoess',
    mission: 'Autonomous research and implementation',
    owner: 'Tymofii',
    capabilities: ['code_execution', 'web_search', 'git_operations'],
    platform: 'mac-mini',
    models: ['claude-sonnet'],
    floor: FLOOR,
    beneficiary: { id: 'tymofii-pidlisnyi', relationship: 'creator' }
  })

  console.log('\n🤝 THE SOCIAL CONTRACT — Simple API')
  console.log('━'.repeat(45))
  console.log(`  Agent: ${agent.agentId}`)
  console.log(`  Floor attested: ${agent.attestation ? 'yes' : 'no'}`)

  // 3. VERIFY: Another agent (or service) checks trust
  const trust = verifySocialContract(agent.passport, agent.attestation)
  assert.ok(trust.overall, 'Agent is trusted')
  assert.ok(trust.identity.valid, 'Identity verified')
  assert.ok(trust.values?.valid, 'Values attestation verified')
  console.log(`  Trusted: ${trust.overall}`)

  // 4. DELEGATE: Human grants authority
  const delegation = delegate({
    from: { ...agent, keyPair: { ...human, publicKey: human.publicKey, privateKey: human.privateKey }, publicKey: human.publicKey },
    toPublicKey: agent.publicKey,
    scope: ['code_execution', 'web_search', 'git_operations'],
    spendLimit: 500
  })
  console.log(`  Delegation: scope=[${delegation.scope.join(', ')}], limit=$${delegation.spendLimit}`)

  // 5. WORK: Agent does things, signs receipts
  const receipt1 = recordWork(agent, delegation,
    [human.publicKey, agent.publicKey],
    { type: 'research', target: 'agent-governance-papers', scope: 'web_search',
      spend: 5, result: 'success', summary: 'Found 12 papers' }
  )

  const receipt2 = recordWork(agent, delegation,
    [human.publicKey, agent.publicKey],
    { type: 'implementation', target: 'values-floor-engine', scope: 'code_execution',
      spend: 20, result: 'success', summary: 'Built 400 lines of protocol code' }
  )

  const receipt3 = recordWork(agent, delegation,
    [human.publicKey, agent.publicKey],
    { type: 'deployment', target: 'github-push', scope: 'git_operations',
      spend: 2, result: 'success', summary: 'Pushed to main branch' }
  )

  console.log(`  Receipts: ${3} signed`)

  // 6. PROVE: proveContributions moved to @aeoess/gateway (scope-weighted
  // report generation is product policy). Confirm the SDK stub throws
  // the migration pointer, and verify the primitives the proof would
  // be assembled from still work in-SDK.
  const allReceipts = [receipt1, receipt2, receipt3]
  assert.throws(
    () => proveContributions(agent, allReceipts, [delegation], 'tymofii-pidlisnyi'),
    /Moved to @aeoess\/gateway/
  )

  // 7. AUDIT: Independent verifier checks compliance
  const verifier = generateKeyPair()
  const delegationContext = new Map([[
    delegation.delegationId,
    { scope: delegation.scope, revoked: false }
  ]])
  const compliance = auditCompliance(
    agent.agentId, allReceipts, floor, delegationContext, verifier
  )

  assert.ok(compliance.overallCompliance > 0.8)
  const enforced = compliance.checks.filter(c => c.status === 'enforced').length
  console.log(`  Compliance: ${(compliance.overallCompliance * 100).toFixed(1)}% (${enforced}/7 enforced)`)

  console.log('\n' + '━'.repeat(45))
  console.log('  ✓ Join → Verify → Delegate → Work → Audit (Prove → gateway)')
  console.log('')
})

test('Edge: Join without floor still works', () => {
  clearStores()
  const agent = joinSocialContract({
    name: 'Minimal',
    mission: 'Just exist',
    owner: 'test',
    capabilities: ['web_search'],
    platform: 'cloud',
    models: ['test']
  })

  assert.ok(agent.agentId.startsWith('agent-minimal'))
  assert.equal(agent.attestation, null, 'No attestation without floor')

  const trust = verifySocialContract(agent.passport)
  assert.ok(trust.overall, 'Still trusted without floor')
  assert.equal(trust.values, null, 'No values to check')
})

test('Edge: Verify agent with expired attestation', () => {
  clearStores()
  const agent = joinSocialContract({
    name: 'Expired',
    mission: 'Test expiry',
    owner: 'test',
    capabilities: ['web_search'],
    platform: 'cloud',
    models: ['test'],
    floor: FLOOR,
    floorExtensions: []
  })

  // Manually expire the attestation
  if (agent.attestation) {
    (agent.attestation as any).expiresAt = '2020-01-01T00:00:00.000Z'
  }

  const trust = verifySocialContract(agent.passport, agent.attestation)
  assert.ok(trust.identity.valid, 'Identity still valid')
  assert.ok(!trust.values?.valid, 'Values attestation expired')
  assert.ok(!trust.overall, 'Overall: not trusted')
})
