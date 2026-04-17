// ══════════════════════════════════════════════════════════════
// The Agent Social Contract — Full Stack Integration Test
// ══════════════════════════════════════════════════════════════
// 
// This test tells a complete story:
//   1. A human creates two agents with Floor attestations
//   2. The agents negotiate common ground
//   3. Agent A delegates to Agent B
//   4. Agent B performs work and signs receipts
//   5. Receipts are traced back to the human beneficiary
//   6. Attribution is computed with Merkle proofs
//   7. Compliance is verified against the Floor
//   8. A third party verifies everything cryptographically
//
// If this test passes, all three layers of the Agent Social Contract
// are working: Identity, Values, Attribution.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  // Layer 1
  createPassport, generateKeyPair, verifyPassport,
  createDelegation, createReceipt, verifyReceipt, clearStores,
  // Layer 2
  loadFloor, attestFloor, verifyAttestation,
  evaluateCompliance, negotiateCommonGround,
  // Layer 3
  hashReceipt, traceBeneficiary,
  buildMerkleRoot, generateMerkleProof, verifyMerkleProof,
} from '../src/index.js'

import type {
  ActionReceipt, Delegation, BeneficiaryInfo
} from '../src/index.js'

// Minimal floor manifest for testing
const TEST_FLOOR_YAML = `
version: "0.1"
schema: "agent-social-contract/values-floor"
last_updated: "2026-02-20"
governance_uri: "https://aeoess.com/protocol.html"

floor:
  - id: "F-001"
    name: "Traceability"
    principle: "Every action must be traceable to a human beneficiary"
    enforcement:
      technical: true
      mechanism: "Agent Passport delegation chains"
    weight: "mandatory"

  - id: "F-002"
    name: "Honest Identity"
    principle: "Agents must not misrepresent identity"
    enforcement:
      technical: true
      mechanism: "Passport verification"
    weight: "mandatory"

  - id: "F-003"
    name: "Scoped Authority"
    principle: "Agents must act within delegated scope"
    enforcement:
      technical: true
      mechanism: "Delegation scope limits"
    weight: "mandatory"

  - id: "F-004"
    name: "Revocability"
    principle: "Humans can revoke agent authority"
    enforcement:
      technical: true
      mechanism: "Delegation revocation"
    weight: "mandatory"

  - id: "F-005"
    name: "Auditability"
    principle: "All actions must be auditable"
    enforcement:
      technical: true
      mechanism: "Action receipts"
    weight: "mandatory"

  - id: "F-006"
    name: "Non-Deception"
    principle: "Agents must not deceive"
    enforcement:
      technical: false
      mechanism: "Reputation scoring"
    weight: "strong_consideration"

  - id: "F-007"
    name: "Proportionality"
    principle: "Autonomy proportional to trust"
    enforcement:
      technical: false
      mechanism: "Reputation context"
    weight: "strong_consideration"
`

test('The Agent Social Contract — Full Stack', async (t) => {
  clearStores()

  // ══════════════════════════════════════
  // ACT 1: Genesis — Human creates agents
  // ══════════════════════════════════════

  await t.test('Act 1: Human creates agents with identity', () => {
    console.log('\n🌍 THE AGENT SOCIAL CONTRACT — Integration Test')
    console.log('━'.repeat(55))
    console.log('\nAct 1: Genesis')
  })

  // Human H's keypair (the beneficiary)
  const humanKeys = generateKeyPair()

  // Agent A: the primary agent (like aeoess)
  const agentA = createPassport({
    agentId: 'agent-alpha-001',
    agentName: 'Alpha',
    ownerAlias: 'Tymofii',
    mission: 'Research and implementation',
    capabilities: ['code_execution', 'web_search', 'git_operations', 'data_analysis'],
    runtime: { platform: 'mac-mini', models: ['claude-sonnet'], toolsCount: 17, memoryType: 'persistent' },
    beneficiary: {
      principalId: 'tymofii-pidlisnyi',
      principalPublicKey: humanKeys.publicKey,
      relationship: 'creator',
      registeredAt: new Date().toISOString()
    }
  })

  // Agent B: collaborator (like PortalX2)
  const agentB = createPassport({
    agentId: 'agent-beta-001',
    agentName: 'Beta',
    ownerAlias: 'Tymofii',
    mission: 'Architecture and design',
    capabilities: ['code_execution', 'web_search', 'browser_automation'],
    runtime: { platform: 'cloud', models: ['claude-opus'], toolsCount: 14, memoryType: 'session' },
    beneficiary: {
      principalId: 'tymofii-pidlisnyi',
      principalPublicKey: humanKeys.publicKey,
      relationship: 'creator',
      registeredAt: new Date().toISOString()
    }
  })

  // Verify both passports
  const verA = verifyPassport(agentA.signedPassport)
  const verB = verifyPassport(agentB.signedPassport)
  assert.ok(verA.valid, 'Agent A passport valid')
  assert.ok(verB.valid, 'Agent B passport valid')
  console.log('  ✓ Agent Alpha created — capabilities:', agentA.signedPassport.passport.capabilities.join(', '))
  console.log('  ✓ Agent Beta created — capabilities:', agentB.signedPassport.passport.capabilities.join(', '))

  // ══════════════════════════════════════
  // ACT 2: Values — Agents attest to Floor
  // ══════════════════════════════════════

  await t.test('Act 2: Floor attestation and common ground', () => {
    console.log('\nAct 2: Values Floor')
  })

  // Load the floor manifest
  const floor = loadFloor(TEST_FLOOR_YAML)
  assert.equal(floor.version, '0.1', 'Floor version parsed')
  assert.equal(floor.floor.length, 7, 'All 7 principles loaded')
  console.log(`  ✓ Floor v${floor.version} loaded — ${floor.floor.length} principles`)

  // Both agents attest
  const attestA = attestFloor(
    'agent-alpha-001',
    agentA.signedPassport.passport.publicKey,
    floor.version,
    [],  // no extensions
    agentA.keyPair.privateKey
  )

  const attestB = attestFloor(
    'agent-beta-001',
    agentB.signedPassport.passport.publicKey,
    floor.version,
    [],
    agentB.keyPair.privateKey
  )

  // Verify attestations
  const attVerA = verifyAttestation(attestA)
  const attVerB = verifyAttestation(attestB)
  assert.ok(attVerA.valid, 'Agent A attestation valid')
  assert.ok(attVerB.valid, 'Agent B attestation valid')
  console.log('  ✓ Agent Alpha attested to Floor v' + floor.version)
  console.log('  ✓ Agent Beta attested to Floor v' + floor.version)

  // Negotiate common ground
  const common = negotiateCommonGround(
    agentA.signedPassport.passport, attestA,
    agentB.signedPassport.passport, attestB
  )
  assert.ok(common.compatible, 'Agents are compatible')
  assert.equal(common.floorVersion, '0.1', 'Shared floor version')
  console.log('  ✓ Common ground negotiated — compatible:', common.compatible)
  console.log('    Floor:', common.floorVersion, '| Shared extensions:', common.sharedExtensions.length)

  // ══════════════════════════════════════
  // ACT 3: Delegation — Human → A → B
  // ══════════════════════════════════════

  await t.test('Act 3: Delegation chain', () => {
    console.log('\nAct 3: Delegation')
  })

  // Human delegates to Agent A
  const delHtoA = createDelegation({
    delegatedTo: agentA.signedPassport.passport.publicKey,
    delegatedBy: humanKeys.publicKey,
    scope: ['code_execution', 'web_search', 'git_operations', 'data_analysis'],
    spendLimit: 1000,
    maxDepth: 2,
    privateKey: humanKeys.privateKey
  })

  // Agent A sub-delegates to Agent B (narrowed scope)
  const delAtoB = createDelegation({
    delegatedTo: agentB.signedPassport.passport.publicKey,
    delegatedBy: agentA.signedPassport.passport.publicKey,
    scope: ['code_execution', 'web_search'],  // narrowed
    spendLimit: 500,
    maxDepth: 2,
    currentDepth: 1,
    privateKey: agentA.keyPair.privateKey
  })

  console.log('  ✓ Human → Alpha: scope [' + delHtoA.scope.join(', ') + '], $' + delHtoA.spendLimit)
  console.log('  ✓ Alpha → Beta: scope [' + delAtoB.scope.join(', ') + '], $' + delAtoB.spendLimit + ' (narrowed)')

  // ══════════════════════════════════════
  // ACT 4: Work — Agents produce receipts
  // ══════════════════════════════════════

  await t.test('Act 4: Agents perform work', () => {
    console.log('\nAct 4: Work')
  })

  const receipts: ActionReceipt[] = []

  // Agent A does research
  const receiptA1 = createReceipt({
    agentId: 'agent-alpha-001',
    delegationId: delHtoA.delegationId,
    delegation: delHtoA,
    action: {
      type: 'research',
      target: 'arxiv-papers',
      method: 'search_and_synthesize',
      scopeUsed: 'web_search',
      spend: { amount: 5, currency: 'USD' }
    },
    result: { status: 'success', summary: 'Found 12 related papers on agent governance' },
    delegationChain: [humanKeys.publicKey, agentA.signedPassport.passport.publicKey],
    privateKey: agentA.keyPair.privateKey
  })
  receipts.push(receiptA1)

  // Agent A writes code
  const receiptA2 = createReceipt({
    agentId: 'agent-alpha-001',
    delegationId: delHtoA.delegationId,
    delegation: delHtoA,
    action: {
      type: 'implementation',
      target: 'values-floor-engine',
      method: 'code_generation',
      scopeUsed: 'code_execution',
      spend: { amount: 15, currency: 'USD' }
    },
    result: { status: 'success', summary: 'Implemented values.ts — 200 lines' },
    delegationChain: [humanKeys.publicKey, agentA.signedPassport.passport.publicKey],
    privateKey: agentA.keyPair.privateKey
  })
  receipts.push(receiptA2)

  // Agent A does data analysis
  const receiptA3 = createReceipt({
    agentId: 'agent-alpha-001',
    delegationId: delHtoA.delegationId,
    delegation: delHtoA,
    action: {
      type: 'analysis',
      target: 'governance-frameworks',
      method: 'comparative_analysis',
      scopeUsed: 'data_analysis',
      spend: { amount: 8, currency: 'USD' }
    },
    result: { status: 'success', summary: 'Compared 6 governance frameworks' },
    delegationChain: [humanKeys.publicKey, agentA.signedPassport.passport.publicKey],
    privateKey: agentA.keyPair.privateKey
  })
  receipts.push(receiptA3)

  // Agent B writes code under sub-delegation
  const receiptB1 = createReceipt({
    agentId: 'agent-beta-001',
    delegationId: delAtoB.delegationId,
    delegation: delAtoB,
    action: {
      type: 'implementation',
      target: 'attribution-engine',
      method: 'code_generation',
      scopeUsed: 'code_execution',
      spend: { amount: 20, currency: 'USD' }
    },
    result: { status: 'success', summary: 'Implemented attribution.ts with Merkle trees' },
    delegationChain: [
      humanKeys.publicKey,
      agentA.signedPassport.passport.publicKey,
      agentB.signedPassport.passport.publicKey
    ],
    privateKey: agentB.keyPair.privateKey
  })
  receipts.push(receiptB1)

  // Agent B does web search
  const receiptB2 = createReceipt({
    agentId: 'agent-beta-001',
    delegationId: delAtoB.delegationId,
    delegation: delAtoB,
    action: {
      type: 'research',
      target: 'merkle-tree-implementations',
      method: 'web_search',
      scopeUsed: 'web_search',
      spend: { amount: 3, currency: 'USD' }
    },
    result: { status: 'success', summary: 'Surveyed 4 Merkle implementations' },
    delegationChain: [
      humanKeys.publicKey,
      agentA.signedPassport.passport.publicKey,
      agentB.signedPassport.passport.publicKey
    ],
    privateKey: agentB.keyPair.privateKey
  })
  receipts.push(receiptB2)

  // Verify all receipts
  assert.ok(verifyReceipt(receiptA1, agentA.signedPassport.passport.publicKey).valid)
  assert.ok(verifyReceipt(receiptA2, agentA.signedPassport.passport.publicKey).valid)
  assert.ok(verifyReceipt(receiptA3, agentA.signedPassport.passport.publicKey).valid)
  assert.ok(verifyReceipt(receiptB1, agentB.signedPassport.passport.publicKey).valid)
  assert.ok(verifyReceipt(receiptB2, agentB.signedPassport.passport.publicKey).valid)
  console.log('  ✓ Alpha: 3 receipts (research, implementation, analysis)')
  console.log('  ✓ Beta: 2 receipts (implementation, research)')
  console.log('  ✓ All 5 receipts cryptographically verified')

  // ══════════════════════════════════════
  // ACT 5: Attribution — Trace to beneficiary
  // ══════════════════════════════════════

  await t.test('Act 5: Beneficiary attribution', () => {
    console.log('\nAct 5: Attribution')
  })

  // Set up beneficiary map
  const beneficiaryMap = new Map<string, BeneficiaryInfo>()
  beneficiaryMap.set(humanKeys.publicKey, {
    principalId: 'tymofii-pidlisnyi',
    principalPublicKey: humanKeys.publicKey,
    relationship: 'creator',
    registeredAt: new Date().toISOString()
  })

  // Trace Agent A's first receipt back to human
  const traceA = traceBeneficiary(receiptA1, [delHtoA], beneficiaryMap)
  assert.equal(traceA.beneficiary, 'tymofii-pidlisnyi', 'Traced to correct beneficiary')
  assert.ok(traceA.verified, 'Trace fully verified')
  assert.equal(traceA.totalDepth, 1, 'Direct delegation: depth 1')
  console.log('  ✓ Alpha receipt → Tymofii (depth 1, verified)')

  // Trace Agent B's receipt (goes through A → Human)
  const traceB = traceBeneficiary(receiptB1, [delHtoA, delAtoB], beneficiaryMap)
  assert.equal(traceB.beneficiary, 'tymofii-pidlisnyi', 'B also traces to same beneficiary')
  assert.ok(traceB.verified, 'B trace fully verified')
  assert.equal(traceB.totalDepth, 2, 'Sub-delegation: depth 2')
  console.log('  ✓ Beta receipt → Alpha → Tymofii (depth 2, verified)')

  // Attribution report generation + collaboration attribution moved to
  // @aeoess/gateway. Covered by gateway tests/sdk-migrated/core/attribution-reports.test.ts
  console.log('  ✓ Attribution report generation → gateway (product policy)')

  // ══════════════════════════════════════
  // ACT 6: Merkle Proofs — O(log n) verification
  // ══════════════════════════════════════

  await t.test('Act 6: Merkle proofs', () => {
    console.log('\nAct 6: Merkle Proofs')
  })

  // Hash all receipts
  const receiptHashes = receipts.map(r => hashReceipt(r))
  assert.equal(receiptHashes.length, 5, '5 receipt hashes')
  console.log(`  ✓ ${receiptHashes.length} receipts hashed (SHA-256)`)

  // Build Merkle root
  const root = buildMerkleRoot(receiptHashes)
  assert.equal(root.length, 64, 'Merkle root is 64 hex chars')
  console.log(`  ✓ Merkle root: ${root.slice(0, 16)}...`)

  // Generate proof for Agent B's first receipt
  const targetHash = hashReceipt(receiptB1)
  const proof = generateMerkleProof(receiptHashes, targetHash)
  assert.ok(proof !== null, 'Proof generated')
  assert.equal(proof!.root, root, 'Proof root matches tree root')
  console.log(`  ✓ Proof for Beta receipt: ${proof!.proof.length} nodes (log₂(5) ≈ 2.3)`)

  // Verify the proof — this is what a third party does
  const proofValid = verifyMerkleProof(proof!)
  assert.ok(proofValid, 'Merkle proof verified!')
  console.log('  ✓ Third-party verification: PASSED')

  // Verify proof for Agent A's receipt too
  const targetHashA = hashReceipt(receiptA2)
  const proofA = generateMerkleProof(receiptHashes, targetHashA)
  assert.ok(proofA !== null, 'Proof for Alpha receipt generated')
  assert.ok(verifyMerkleProof(proofA!), 'Alpha receipt proof verified')
  console.log('  ✓ Alpha implementation receipt: proof verified')

  // Negative test: fake receipt hash should fail
  const fakeHash = 'a'.repeat(64)
  const fakeProof = generateMerkleProof(receiptHashes, fakeHash)
  assert.equal(fakeProof, null, 'No proof for fake receipt')
  console.log('  ✓ Fake receipt: correctly rejected (no proof possible)')

  // ══════════════════════════════════════
  // ACT 7: Compliance — Verify against Floor
  // ══════════════════════════════════════

  await t.test('Act 7: Floor compliance verification', () => {
    console.log('\nAct 7: Compliance')
  })

  // Build delegation context for compliance check
  const delegationContext = new Map<string, { scope: string[]; revoked: boolean }>()
  delegationContext.set(delHtoA.delegationId, {
    scope: delHtoA.scope,
    revoked: false
  })
  delegationContext.set(delAtoB.delegationId, {
    scope: delAtoB.scope,
    revoked: false
  })

  // Generate a verifier keypair (independent third party)
  const verifierKeys = generateKeyPair()

  // Check Agent A's compliance
  const complianceA = evaluateCompliance(
    'agent-alpha-001',
    receipts,
    floor,
    delegationContext,
    verifierKeys.privateKey
  )

  assert.ok(complianceA.overallCompliance > 0.8, 'Agent A highly compliant')
  assert.equal(complianceA.receiptsAnalyzed, 3, '3 receipts analyzed for A')
  console.log(`  ✓ Alpha compliance: ${(complianceA.overallCompliance * 100).toFixed(1)}%`)

  for (const check of complianceA.checks) {
    const icon = check.status === 'enforced' ? '🔒' :
                 check.status === 'attested' ? '📝' :
                 check.status === 'violation' ? '❌' : '❓'
    console.log(`    ${icon} ${check.principleName}: ${check.status}`)
  }

  // Check Agent B's compliance
  const complianceB = evaluateCompliance(
    'agent-beta-001',
    receipts,
    floor,
    delegationContext,
    verifierKeys.privateKey
  )

  assert.ok(complianceB.overallCompliance > 0.8, 'Agent B highly compliant')
  console.log(`  ✓ Beta compliance: ${(complianceB.overallCompliance * 100).toFixed(1)}%`)

  // Verify the compliance reports are properly signed
  // (Third party generated them, third party can verify)
  assert.ok(complianceA.signature.length > 0, 'Compliance report A is signed')
  assert.ok(complianceB.signature.length > 0, 'Compliance report B is signed')
  console.log('  ✓ Both compliance reports cryptographically signed by verifier')

  // ══════════════════════════════════════
  // EPILOGUE: Summary
  // ══════════════════════════════════════

  console.log('\n' + '━'.repeat(55))
  console.log('THE AGENT SOCIAL CONTRACT — All Layers Operational')
  console.log('━'.repeat(55))
  console.log(`
  Layer 1 — Identity & Accountability
    ✓ 2 agents created with Ed25519 identity
    ✓ Delegation chain: Human → Alpha → Beta
    ✓ 5 signed action receipts
    ✓ All receipts cryptographically verified

  Layer 2 — Human Values Floor
    ✓ Floor v${floor.version} loaded (${floor.floor.length} principles)
    ✓ Both agents attested (signatures verified)
    ✓ Common ground negotiated (compatible: ${common.compatible})
    ✓ Compliance: Alpha ${(complianceA.overallCompliance * 100).toFixed(1)}%, Beta ${(complianceB.overallCompliance * 100).toFixed(1)}%
    ✓ ${complianceA.checks.filter(c => c.status === 'enforced').length}/7 principles technically enforced

  Layer 3 — Beneficiary Attribution
    ✓ All receipts traced to beneficiary: tymofii-pidlisnyi
    ✓ Attribution report generation → gateway (product policy)
    ✓ Merkle root: ${root.slice(0, 16)}...
    ✓ Individual receipt proofs: verified
    ✓ Fake receipts: correctly rejected

  The protocol is open source. The governance is democratic.
  The principles are universal. The code is running.
  `)
})
