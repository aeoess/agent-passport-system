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
  // AIVSS §3.6 worked-scenario tests:
  subDelegate, verifyDelegation, computeDelegationChainRoot,
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

// ══════════════════════════════════════════════════════════════
// AIVSS §3.6 Worked Scenarios — OWASP-canonical adversarial fixtures
// Source: AIVSS Scoring System For OWASP Agentic AI Core Security Risks v0.8
//   (OWASP/www-project-artificial-intelligence-vulnerability-scoring-system,
//    assets/publications/, accessed 2026-04-26)
// Score sequence (9.9, 9.7, 9.4, 10.0, 9.3, 8.9, 9.2, 9.7, 8.3, 7.1)
// is preserved into the v1.0 public review draft (Apr 2026, Google Doc
// 1SIO6yN1x4XXTnclLeEsFFHnqzRR-3SOvUJTHF7CGRpI). The §3.3 sub-factor
// structure (DD/PA/CAC + ×1.0/×2.0 multiplier) introduced in v1 is
// additive and does not modify the §3.6 worked scenarios.
//
// Each test maps an AIVSS §3.6 worked scenario to the APS primitive that
// structurally constrains the attack class. APS does not claim to remediate
// the underlying agentic capability — it enforces the boundary the scenario
// relies on remaining unenforced (scope, signature, expiry, revocation,
// audit chain).
// ══════════════════════════════════════════════════════════════

test('AIVSS §3.6 worked scenarios — OWASP-canonical adversarial fixtures', async (t) => {
  clearStores()

  // ── §3.6.1 Agentic AI Tool Misuse ──────────────────────────────────
  // CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H = 9.4
  // AARS factors sum 9.0; AIVSS = 9.9 (Critical).
  // APS primitive: scopeAuthorizes inside createReceipt — a receipt for
  // an action whose scopeUsed is not covered by the delegation must be
  // refused at receipt time, not at policy time.
  await t.test('§3.6.1 Tool Misuse (AIVSS 9.9) — scope narrowing refuses unauthorized tool', () => {
    const principal = generateKeyPair()
    const agent = generateKeyPair()
    const del = createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: principal.publicKey,
      scope: ['code_execution:read'], maxDepth: 1,
      privateKey: principal.privateKey,
    })
    assert.throws(() => {
      createReceipt({
        agentId: agent.publicKey,
        delegationId: del.delegationId, delegation: del,
        action: { type: 'execute', target: 'internal-build', scopeUsed: 'code_execution:write' },
        result: { status: 'success', summary: 'compromised' },
        delegationChain: [principal.publicKey, agent.publicKey],
        privateKey: agent.privateKey,
      })
    }, /scope|Scope/, '§3.6.1: code_execution:write outside [code_execution:read] must be refused')
    console.log('  ✓ §3.6.1 Tool Misuse: out-of-scope action refused at receipt time')
  })

  // ── §3.6.2 Agent Access Control Violation ──────────────────────────
  // CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N = 8.7
  // AARS factors sum 8.0; AIVSS = 9.7 (Critical).
  // APS primitive: verifyDelegation enforces TTL — a delegation past
  // expiresAt fails verification with expired=true, blocking carry-over
  // of administrative authority across sessions.
  await t.test('§3.6.2 Access Control Violation (AIVSS 9.7) — expired delegation blocks credential carry-over', () => {
    const principal = generateKeyPair()
    const agent = generateKeyPair()
    const expired = createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: principal.publicKey,
      scope: ['admin:full'], maxDepth: 1,
      expiresInHours: -1,
      privateKey: principal.privateKey,
    })
    const status = verifyDelegation(expired)
    assert.equal(status.valid, false, '§3.6.2: expired delegation must not verify')
    assert.equal(status.expired, true, '§3.6.2: expired flag must be set')
    console.log('  ✓ §3.6.2 Access Control Violation: expired admin delegation refused (TTL enforced)')
  })

  // ── §3.6.3 Agent Cascading Failures ────────────────────────────────
  // CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:H/SA:H = 7.1
  // AARS factors sum 8.0; AIVSS = 9.4 (Critical).
  // APS primitive: cachedRevocationState in verifyDelegation — once the
  // upstream agent is marked revoked, downstream verifiers reach the same
  // deny verdict without a live registry hit, structurally bounding
  // cascade failure to a single-hop blast radius.
  await t.test('§3.6.3 Cascading Failures (AIVSS 9.4) — cached revocation propagates structurally', () => {
    const principal = generateKeyPair()
    const upstream = generateKeyPair()
    const del = createDelegation({
      delegatedTo: upstream.publicKey, delegatedBy: principal.publicKey,
      scope: ['ticket:triage'], maxDepth: 2,
      privateKey: principal.privateKey,
    })
    const status = verifyDelegation(del, {
      cachedRevocationState: { revoked: true, checkedAt: new Date().toISOString() },
    })
    assert.equal(status.valid, false, '§3.6.3: revoked upstream must not verify')
    assert.equal(status.revoked, true, '§3.6.3: revoked flag must be set')
    console.log('  ✓ §3.6.3 Cascading Failures: cached revocation halts the cascade')
  })

  // ── §3.6.4 Agent Orchestration and Multi-Agent Exploitation ────────
  // CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H = 9.4
  // AARS factors sum 9.5; AIVSS = 10.0 (Critical) — top of scale.
  // APS primitive: subDelegate enforces monotonic narrowing — a
  // compromised orchestrator cannot grant a sub-agent any scope it does
  // not already hold; escalation throws at sign time.
  await t.test('§3.6.4 Multi-Agent Exploitation (AIVSS 10.0) — subDelegate refuses scope escalation', () => {
    const principal = generateKeyPair()
    const orchestrator = generateKeyPair()
    const subagent = generateKeyPair()
    const root = createDelegation({
      delegatedTo: orchestrator.publicKey, delegatedBy: principal.publicKey,
      scope: ['data_analysis'], maxDepth: 4,
      privateKey: principal.privateKey,
    })
    assert.throws(() => {
      subDelegate({
        parentDelegation: root,
        delegatedTo: subagent.publicKey,
        scope: ['data_analysis', 'file_management:write'],
        privateKey: orchestrator.privateKey,
      })
    }, /Scope violation/, '§3.6.4: orchestrator cannot grant file_management:write outside parent scope')
    console.log('  ✓ §3.6.4 Multi-Agent Exploitation: scope escalation refused (monotonic narrowing)')
  })

  // ── §3.6.5 Agent Identity Impersonation ────────────────────────────
  // CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N = 7.4
  // AARS factors sum 7.5; AIVSS = 9.3 (Critical).
  // APS primitive: Ed25519 signature verification in verifyDelegation —
  // a delegation that claims a principal but is signed by a different
  // key fails signature check.
  await t.test('§3.6.5 Identity Impersonation (AIVSS 9.3) — wrong-signer delegation fails verify', () => {
    const realPrincipal = generateKeyPair()
    const impostor = generateKeyPair()
    const agent = generateKeyPair()
    const forged = createDelegation({
      delegatedTo: agent.publicKey,
      delegatedBy: realPrincipal.publicKey,   // claims to be from realPrincipal
      scope: ['*'], maxDepth: 1,
      privateKey: impostor.privateKey,         // …but signed by impostor
    })
    const status = verifyDelegation(forged)
    assert.equal(status.valid, false, '§3.6.5: forged-issuer delegation must not verify')
    assert.ok(status.errors.some(e => /signature/i.test(e)), '§3.6.5: signature error surfaced')
    console.log('  ✓ §3.6.5 Identity Impersonation: forged-issuer delegation refused')
  })

  // ── §3.6.6 Agent Memory and Context Manipulation ───────────────────
  // CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N = 5.8
  // AARS factors sum 7.5; AIVSS = 8.9 (High) — the largest CVSS-to-AIVSS
  // delta after §3.6.10. APS primitive: receipt-payload integrity —
  // tampering with the result field after signing invalidates the receipt
  // signature; a poisoned-RAG receipt cannot be silently rewritten.
  await t.test('§3.6.6 Memory Manipulation (AIVSS 8.9) — tampered receipt fails verifyReceipt', () => {
    const principal = generateKeyPair()
    const agent = generateKeyPair()
    const del = createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: principal.publicKey,
      scope: ['rag:retrieve'], maxDepth: 1,
      privateKey: principal.privateKey,
    })
    const honest = createReceipt({
      agentId: agent.publicKey,
      delegationId: del.delegationId, delegation: del,
      action: { type: 'retrieve', target: 'kb/q4', scopeUsed: 'rag:retrieve' },
      result: { status: 'success', summary: 'returned 3 chunks' },
      delegationChain: [principal.publicKey, agent.publicKey],
      privateKey: agent.privateKey,
    })
    const tampered = { ...honest, result: { ...honest.result, summary: 'leaked internal payroll' } }
    const v = verifyReceipt(tampered as ActionReceipt, agent.publicKey)
    assert.equal(v.valid, false, '§3.6.6: post-sign tamper must invalidate the receipt')
    console.log('  ✓ §3.6.6 Memory Manipulation: post-sign result tamper detected')
  })

  // ── §3.6.7 Insecure Agent Critical Systems Interaction ─────────────
  // CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N = 6.9
  // AARS factors sum 7.5; AIVSS = 9.2 (Critical).
  // APS primitive: scope check on physical-action receipts — a sensor-
  // read delegation does not authorize pump-control; createReceipt
  // throws before the actuator command would issue.
  await t.test('§3.6.7 Critical Systems Interaction (AIVSS 9.2) — sensor-read delegation refuses actuator command', () => {
    const principal = generateKeyPair()
    const agent = generateKeyPair()
    const del = createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: principal.publicKey,
      scope: ['sensor:read'], maxDepth: 1,
      privateKey: principal.privateKey,
    })
    assert.throws(() => {
      createReceipt({
        agentId: agent.publicKey,
        delegationId: del.delegationId, delegation: del,
        action: { type: 'actuate', target: 'pump-3', scopeUsed: 'pump:control' },
        result: { status: 'success', summary: 'shutdown initiated' },
        delegationChain: [principal.publicKey, agent.publicKey],
        privateKey: agent.privateKey,
      })
    }, /scope|Scope/, '§3.6.7: actuator command outside [sensor:read] must be refused')
    console.log('  ✓ §3.6.7 Critical Systems Interaction: actuator command refused')
  })

  // ── §3.6.8 Agent Supply Chain and Dependency Risk ──────────────────
  // CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N = 9.3
  // AARS factors sum 6.5; AIVSS = 9.7 (Critical).
  // APS primitive: computeDelegationChainRoot content-addresses the
  // entire chain — swapping a hop (e.g., a compromised library
  // introducing a forged sub-delegation) changes the root digest, so a
  // downstream verifier sees a different chain than the one that was
  // signed. Demonstrates supply-chain tamper detection at the chain
  // boundary.
  await t.test('§3.6.8 Supply Chain (AIVSS 9.7) — chain-root digest detects swapped hop', () => {
    const principal = generateKeyPair()
    const agent = generateKeyPair()
    const innocentLib = generateKeyPair()
    const compromisedLib = generateKeyPair()
    const honest = createDelegation({
      delegatedTo: innocentLib.publicKey, delegatedBy: principal.publicKey,
      scope: ['build:run'], maxDepth: 2,
      privateKey: principal.privateKey,
    })
    const swapped = createDelegation({
      delegatedTo: compromisedLib.publicKey, delegatedBy: principal.publicKey,
      scope: ['build:run'], maxDepth: 2,
      privateKey: principal.privateKey,
    })
    // Append a leaf receipt-style chain element by reusing the agent.
    // What matters: the two chains differ only in the lib subject, and
    // the chain root must reflect that difference.
    const innocentChain = [honest, createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: innocentLib.publicKey,
      scope: ['build:run'], maxDepth: 2, privateKey: innocentLib.privateKey,
    })]
    const swappedChain = [swapped, createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: compromisedLib.publicKey,
      scope: ['build:run'], maxDepth: 2, privateKey: compromisedLib.privateKey,
    })]
    const innocentRoot = computeDelegationChainRoot(innocentChain)
    const swappedRoot = computeDelegationChainRoot(swappedChain)
    assert.notEqual(innocentRoot, swappedRoot, '§3.6.8: swapped library produces different chain root')
    console.log('  ✓ §3.6.8 Supply Chain: chain root surfaces the swapped dependency')
  })

  // ── §3.6.9 Agent Untraceability ────────────────────────────────────
  // CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N = 5.3
  // AARS factors sum 6.5; AIVSS = 8.3 (High).
  // APS primitive: hashReceipt + buildMerkleRoot + generateMerkleProof
  // — receipts are the audit log; a Merkle-rooted batch admits per-receipt
  // inclusion proofs that survive log gaps in adjacent systems. Positive
  // demonstration: APS-instrumented systems cannot be silently
  // de-instrumented without invalidating their published roots.
  await t.test('§3.6.9 Untraceability (AIVSS 8.3) — Merkle-rooted receipt log is structurally auditable', () => {
    const principal = generateKeyPair()
    const agent = generateKeyPair()
    const del = createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: principal.publicKey,
      scope: ['data_analysis'], maxDepth: 1,
      privateKey: principal.privateKey,
    })
    const receipts = [0, 1, 2, 3].map(i => createReceipt({
      agentId: agent.publicKey,
      delegationId: del.delegationId, delegation: del,
      action: { type: 'analyze', target: `batch-${i}`, scopeUsed: 'data_analysis' },
      result: { status: 'success', summary: `processed batch-${i}` },
      delegationChain: [principal.publicKey, agent.publicKey],
      privateKey: agent.privateKey,
    }))
    const leaves = receipts.map(hashReceipt)
    const root = buildMerkleRoot(leaves)
    const proof = generateMerkleProof(leaves, leaves[2])
    assert.ok(proof, '§3.6.9: inclusion proof must be generated for a leaf in the tree')
    assert.equal(proof!.root, root, '§3.6.9: proof root must match published root')
    assert.equal(verifyMerkleProof(proof!), true, '§3.6.9: Merkle inclusion proof must verify')
    assert.ok(root.length > 0, '§3.6.9: published audit root must be non-empty')
    console.log('  ✓ §3.6.9 Untraceability: Merkle-rooted receipt log admits inclusion proofs')
  })

  // ── §3.6.10 Agent Goal and Instruction Manipulation ────────────────
  // CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N = 2.1
  // AARS factors sum 6.5; AIVSS = 7.1 (High) — the largest CVSS→AIVSS
  // uplift in §3.6 (2.1 → 7.1, +5.0). APS primitive: scope is fixed at
  // sign time. Incremental drift may modify the agent's internal goal
  // representation, but every action that crosses an authorization
  // boundary must produce a receipt whose scopeUsed is checked against
  // the immutable delegation scope. APS bounds the drift; it does NOT
  // detect linguistic drift inside an authorized scope. See §gaps in the
  // ingest report for the semantic-detection gap.
  await t.test('§3.6.10 Goal Manipulation (AIVSS 7.1) — fixed delegation scope bounds drift at action boundary', () => {
    const principal = generateKeyPair()
    const agent = generateKeyPair()
    const del = createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: principal.publicKey,
      scope: ['communication:email'], maxDepth: 1,
      privateKey: principal.privateKey,
    })
    // In-scope action: succeeds.
    const inScope = createReceipt({
      agentId: agent.publicKey,
      delegationId: del.delegationId, delegation: del,
      action: { type: 'send', target: 'user@org', scopeUsed: 'communication:email' },
      result: { status: 'success', summary: 'sent' },
      delegationChain: [principal.publicKey, agent.publicKey],
      privateKey: agent.privateKey,
    })
    assert.ok(verifyReceipt(inScope, agent.publicKey).valid, '§3.6.10: in-scope action receipt must verify')
    // Drift attempt: agent's goal incrementally manipulated to broadcast
    // outside the email scope. APS refuses at the boundary regardless of
    // the linguistic path that produced the action.
    assert.throws(() => {
      createReceipt({
        agentId: agent.publicKey,
        delegationId: del.delegationId, delegation: del,
        action: { type: 'broadcast', target: 'public-feed', scopeUsed: 'communication:slack' },
        result: { status: 'success', summary: 'goal-drifted' },
        delegationChain: [principal.publicKey, agent.publicKey],
        privateKey: agent.privateKey,
      })
    }, /scope|Scope/, '§3.6.10: drifted action outside delegation scope must be refused')
    console.log('  ✓ §3.6.10 Goal Manipulation: drifted action refused at scope boundary (semantic-drift detection: out of scope)')
  })
})
