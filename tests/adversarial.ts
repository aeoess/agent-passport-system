// ══════════════════════════════════════════════════════════════
// Adversarial & Edge Case Tests — Break Everything
// ══════════════════════════════════════════════════════════════
// If the protocol can't handle adversarial inputs, it's not ready.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  createPassport, generateKeyPair, createDelegation, createReceipt,
  clearStores, verifyReceipt,
  loadFloor, attestFloor, verifyAttestation, evaluateCompliance,
  negotiateCommonGround,
  hashReceipt, traceBeneficiary,
  buildMerkleRoot, generateMerkleProof, verifyMerkleProof,
} from '../src/index.js'

import type { ActionReceipt, BeneficiaryInfo } from '../src/index.js'

const FLOOR_YAML = `
version: "0.1"
schema: "test"
last_updated: "2026-02-20"
governance_uri: "https://test.com"

floor:
  - id: "F-001"
    name: "Traceability"
    principle: "trace"
    enforcement:
      technical: true
      mechanism: "chains"
    weight: "mandatory"
  - id: "F-002"
    name: "Honest Identity"
    principle: "honest"
    enforcement:
      technical: true
      mechanism: "passport"
    weight: "mandatory"
  - id: "F-003"
    name: "Scoped Authority"
    principle: "scope"
    enforcement:
      technical: true
      mechanism: "delegation"
    weight: "mandatory"
  - id: "F-004"
    name: "Revocability"
    principle: "revoke"
    enforcement:
      technical: true
      mechanism: "revocation"
    weight: "mandatory"
  - id: "F-005"
    name: "Auditability"
    principle: "audit"
    enforcement:
      technical: true
      mechanism: "receipts"
    weight: "mandatory"
  - id: "F-006"
    name: "Non-Deception"
    principle: "no deception"
    enforcement:
      technical: false
      mechanism: "reputation"
    weight: "strong_consideration"
  - id: "F-007"
    name: "Proportionality"
    principle: "proportional"
    enforcement:
      technical: false
      mechanism: "reputation"
    weight: "strong_consideration"
`

test('Adversarial: Merkle tree edge cases', async (t) => {
  clearStores()

  await t.test('Empty receipt set', () => {
    const root = buildMerkleRoot([])
    assert.ok(root.length === 64, 'Empty tree still produces valid hash')
  })

  await t.test('Single receipt', () => {
    const hashes = ['a'.repeat(64)]
    const root = buildMerkleRoot(hashes)
    assert.equal(root, hashes[0], 'Single leaf IS the root')
    const proof = generateMerkleProof(hashes, hashes[0])
    assert.ok(proof !== null, 'Can prove single element')
    assert.ok(verifyMerkleProof(proof!), 'Single element proof verifies')
  })

  await t.test('Two receipts', () => {
    const hashes = ['a'.repeat(64), 'b'.repeat(64)]
    const root = buildMerkleRoot(hashes)
    const proof0 = generateMerkleProof(hashes, hashes[0])
    const proof1 = generateMerkleProof(hashes, hashes[1])
    assert.ok(proof0 && verifyMerkleProof(proof0), 'First element provable')
    assert.ok(proof1 && verifyMerkleProof(proof1), 'Second element provable')
  })

  await t.test('Odd number of receipts (3, 5, 7)', () => {
    for (const count of [3, 5, 7]) {
      const hashes = Array.from({ length: count }, (_, i) =>
        i.toString(16).padStart(64, '0')
      )
      const root = buildMerkleRoot(hashes)
      assert.ok(root.length === 64, `${count} elements: valid root`)

      // Every element should be provable
      for (const hash of hashes) {
        const proof = generateMerkleProof(hashes, hash)
        assert.ok(proof !== null, `${count} elements: proof exists for ${hash.slice(0, 8)}`)
        assert.ok(verifyMerkleProof(proof!), `${count} elements: proof verifies for ${hash.slice(0, 8)}`)
      }
    }
  })

  await t.test('Large set (100 receipts)', () => {
    const hashes = Array.from({ length: 100 }, (_, i) =>
      i.toString(16).padStart(64, '0')
    )
    const root = buildMerkleRoot(hashes)
    assert.ok(root.length === 64)

    // Random samples should be provable
    for (const idx of [0, 1, 49, 50, 98, 99]) {
      const proof = generateMerkleProof(hashes, hashes[idx])
      assert.ok(proof !== null, `Proof exists for index ${idx}`)
      assert.ok(verifyMerkleProof(proof!), `Proof verifies for index ${idx}`)
      // Proof should be O(log n) ≈ 7 nodes for 100 elements
      assert.ok(proof!.proof.length <= 8, `Proof size ${proof!.proof.length} is O(log 100)`)
    }
  })

  await t.test('Tampered proof should fail', () => {
    const hashes = ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)]
    const proof = generateMerkleProof(hashes, hashes[0])
    assert.ok(proof !== null)

    // Tamper with the proof
    const tampered = { ...proof!, receiptHash: 'f'.repeat(64) }
    assert.ok(!verifyMerkleProof(tampered), 'Tampered receipt hash: rejected')

    if (proof!.proof.length > 0) {
      const tamperedNode = {
        ...proof!,
        proof: [{ ...proof!.proof[0], hash: 'f'.repeat(64) }, ...proof!.proof.slice(1)]
      }
      assert.ok(!verifyMerkleProof(tamperedNode), 'Tampered proof node: rejected')
    }
  })

  await t.test('Deterministic: same inputs always same root', () => {
    const hashes = ['c'.repeat(64), 'a'.repeat(64), 'b'.repeat(64)]
    const root1 = buildMerkleRoot(hashes)
    const root2 = buildMerkleRoot(hashes)
    const root3 = buildMerkleRoot([...hashes].reverse())  // different order
    assert.equal(root1, root2, 'Same order = same root')
    assert.equal(root1, root3, 'Different order = same root (sorted internally)')
  })
})

// Adversarial: Attribution gaming — migrated to gateway
// tests/sdk-migrated/core/attribution-reports.test.ts

test('Adversarial: Compliance edge cases', async (t) => {
  clearStores()
  const floor = loadFloor(FLOOR_YAML)
  const verifierKeys = generateKeyPair()

  await t.test('Agent with no receipts = unverifiable, not compliant', () => {
    const delegations = new Map<string, { scope: string[]; revoked: boolean }>()
    const report = evaluateCompliance(
      'ghost-agent', [], floor, delegations, verifierKeys.privateKey
    )
    // Agents with no receipts can't be verified as compliant
    assert.ok(report.overallCompliance < 0.9,
      `No-receipt compliance: ${report.overallCompliance} (not a free pass)`)
    const traceCheck = report.checks.find(c => c.principleId === 'F-001')
    assert.equal(traceCheck?.status, 'unverifiable', 'Traceability: unverifiable with no receipts')
  })

  await t.test('Receipts under revoked delegation = violation', () => {
    const humanKeys = generateKeyPair()
    const agent = createPassport({
      agentId: 'revoked-agent', agentName: 'Bad', ownerAlias: 'test',
      mission: 'test', capabilities: ['code_execution'],
      runtime: { platform: 'test', models: ['test'], toolsCount: 1, memoryType: 'none' }
    })

    const delegation = createDelegation({
      delegatedTo: agent.signedPassport.passport.publicKey,
      delegatedBy: humanKeys.publicKey,
      scope: ['code_execution'], maxDepth: 1,
      privateKey: humanKeys.privateKey
    })

    const receipt = createReceipt({
      agentId: 'revoked-agent',
      delegationId: delegation.delegationId,
      delegation,
      action: { type: 'work', target: 't', scopeUsed: 'code_execution' },
      result: { status: 'success', summary: 'done' },
      delegationChain: [humanKeys.publicKey, agent.signedPassport.passport.publicKey],
      privateKey: agent.keyPair.privateKey
    })

    // Mark delegation as revoked in context
    const delegationContext = new Map<string, { scope: string[]; revoked: boolean }>()
    delegationContext.set(delegation.delegationId, {
      scope: ['code_execution'], revoked: true
    })

    const report = evaluateCompliance(
      'revoked-agent', [receipt], floor, delegationContext, verifierKeys.privateKey
    )

    const revCheck = report.checks.find(c => c.principleId === 'F-004')
    assert.equal(revCheck?.status, 'violation', 'Revocability violation detected')
    assert.ok(report.overallCompliance < 0.9, 'Compliance drops with violation')
    console.log(`  Revoked delegation compliance: ${(report.overallCompliance * 100).toFixed(1)}%`)
  })

  await t.test('Out-of-scope receipt = scoped authority violation', () => {
    const humanKeys = generateKeyPair()
    const agent = createPassport({
      agentId: 'scope-violator', agentName: 'Bad', ownerAlias: 'test',
      mission: 'test', capabilities: ['code_execution', 'email_management'],
      runtime: { platform: 'test', models: ['test'], toolsCount: 1, memoryType: 'none' }
    })

    const delegation = createDelegation({
      delegatedTo: agent.signedPassport.passport.publicKey,
      delegatedBy: humanKeys.publicKey,
      scope: ['code_execution'], maxDepth: 1, // Only code_execution!
      privateKey: humanKeys.privateKey
    })

    // Create a receipt that claims email_management scope
    // But we can't use createReceipt because it validates scope...
    // This is actually a GOOD thing — the protocol prevents this at creation time
    assert.throws(() => {
      createReceipt({
        agentId: 'scope-violator',
        delegationId: delegation.delegationId,
        delegation,
        action: { type: 'email', target: 't', scopeUsed: 'email_management' },
        result: { status: 'success', summary: 'sent email' },
        delegationChain: [humanKeys.publicKey, agent.signedPassport.passport.publicKey],
        privateKey: agent.keyPair.privateKey
      })
    }, /[Ss]cope/, 'Protocol blocks out-of-scope receipt creation')
    console.log('  ✓ Out-of-scope receipt: blocked at creation (not just detection)')
  })
})

test('Adversarial: Values Floor negotiation edge cases', async (t) => {

  await t.test('Incompatible floor versions', () => {
    const keysA = generateKeyPair()
    const keysB = generateKeyPair()

    const agentA = createPassport({
      agentId: 'a', agentName: 'A', ownerAlias: 'test', mission: 'test',
      capabilities: ['code_execution'],
      runtime: { platform: 'test', models: ['test'], toolsCount: 1, memoryType: 'none' }
    })
    const agentB = createPassport({
      agentId: 'b', agentName: 'B', ownerAlias: 'test', mission: 'test',
      capabilities: ['code_execution'],
      runtime: { platform: 'test', models: ['test'], toolsCount: 1, memoryType: 'none' }
    })

    // Agent A attests v0.1, Agent B attests v1.0 (different major version)
    const attA = attestFloor('a', agentA.signedPassport.passport.publicKey, '0.1', [], agentA.keyPair.privateKey)
    const attB = attestFloor('b', agentB.signedPassport.passport.publicKey, '1.0', [], agentB.keyPair.privateKey)

    const ground = negotiateCommonGround(
      agentA.signedPassport.passport, attA,
      agentB.signedPassport.passport, attB
    )

    assert.ok(!ground.compatible, 'Different major versions = incompatible')
    assert.ok(ground.incompatibilityReasons.length > 0, 'Has reason')
    console.log('  ✓ v0.x vs v1.x: correctly flagged incompatible')
  })

  await t.test('Shared and unshared extensions', () => {
    const agentA = createPassport({
      agentId: 'a', agentName: 'A', ownerAlias: 'test', mission: 'test',
      capabilities: ['code_execution'],
      runtime: { platform: 'test', models: ['test'], toolsCount: 1, memoryType: 'none' }
    })
    const agentB = createPassport({
      agentId: 'b', agentName: 'B', ownerAlias: 'test', mission: 'test',
      capabilities: ['code_execution'],
      runtime: { platform: 'test', models: ['test'], toolsCount: 1, memoryType: 'none' }
    })

    const attA = attestFloor('a', agentA.signedPassport.passport.publicKey, '0.1',
      ['ext-healthcare-v1', 'ext-eu-v1'], agentA.keyPair.privateKey)
    const attB = attestFloor('b', agentB.signedPassport.passport.publicKey, '0.1',
      ['ext-eu-v1', 'ext-financial-v1'], agentB.keyPair.privateKey)

    const ground = negotiateCommonGround(
      agentA.signedPassport.passport, attA,
      agentB.signedPassport.passport, attB
    )

    assert.ok(ground.compatible, 'Same floor version = compatible')
    assert.deepEqual(ground.sharedExtensions, ['ext-eu-v1'], 'Only shared extension found')
    console.log('  ✓ Extension negotiation: healthcare∩financial = [eu] only')
  })

  await t.test('Attestation with wrong key fails verification', () => {
    const realKeys = generateKeyPair()
    const fakeKeys = generateKeyPair()

    const att = attestFloor('fake', realKeys.publicKey, '0.1', [], fakeKeys.privateKey)
    // The attestation claims realKeys.publicKey but was signed by fakeKeys
    const ver = verifyAttestation(att)
    assert.ok(!ver.valid, 'Wrong-key attestation rejected')
    assert.ok(ver.errors.some(e => e.includes('signature')), 'Signature error detected')
    console.log('  ✓ Wrong-key attestation: rejected')
  })
})

test('Adversarial: Beneficiary trace edge cases', async (t) => {
  clearStores()

  await t.test('Broken delegation chain = unverified trace', () => {
    const humanKeys = generateKeyPair()
    const agent = createPassport({
      agentId: 'orphan', agentName: 'Orphan', ownerAlias: 'test',
      mission: 'test', capabilities: ['web_search'],
      runtime: { platform: 'test', models: ['test'], toolsCount: 1, memoryType: 'none' }
    })

    const delegation = createDelegation({
      delegatedTo: agent.signedPassport.passport.publicKey,
      delegatedBy: humanKeys.publicKey,
      scope: ['web_search'], maxDepth: 1,
      privateKey: humanKeys.privateKey
    })

    const receipt = createReceipt({
      agentId: 'orphan',
      delegationId: delegation.delegationId,
      delegation,
      action: { type: 'search', target: 't', scopeUsed: 'web_search' },
      result: { status: 'success', summary: 'done' },
      delegationChain: [humanKeys.publicKey, agent.signedPassport.passport.publicKey],
      privateKey: agent.keyPair.privateKey
    })

    // Trace with empty beneficiary map — no human registered
    const trace = traceBeneficiary(receipt, [delegation], new Map())
    assert.ok(!trace.verified || trace.beneficiary === humanKeys.publicKey,
      'Unregistered beneficiary: falls back to public key')
    console.log('  ✓ Unregistered beneficiary: trace falls back to public key')
  })
})
