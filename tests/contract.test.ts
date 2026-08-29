// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
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
  generateKeyPair, loadFloor, clearStores, countersignPassport,
  createPassport, signPassport, verifyPassport
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

// ══════════════════════════════════════════════════════════════════
// Invariant: a function that verifies internal cryptographic structure
// must not report trusted authorization.
// ══════════════════════════════════════════════════════════════════
// verifySocialContract called verifyPassport with no trust anchors, threw
// away its 'self-signed passports are accepted' warning (TrustVerification
// had no field for it), and returned the result as `overall`, which the
// CLI printed as "TRUSTED". A passport signature verifies under the key
// the passport carries, so on its own it establishes structure, not
// standing. The two are now separate fields with separate names.

test('Trust root: a self-signed passport is structurally valid, not issuer-trusted', () => {
  clearStores()
  const agent = joinSocialContract({
    name: 'SelfSigned', mission: 'Test trust roots', owner: 'test',
    capabilities: ['web_search'], platform: 'cloud', models: ['test'],
    floor: FLOOR, floorExtensions: [],
  })
  const trust = verifySocialContract(agent.passport, agent.attestation)
  assert.equal(trust.structurallyValid, true, 'signature and attestation check out')
  assert.equal(trust.issuerTrusted, false, 'nobody external vouched for this passport')
  assert.ok(
    trust.identity.warnings.some(w => w.toLowerCase().includes('self-signed')),
    `expected the self-signed warning to survive, got ${JSON.stringify(trust.identity.warnings)}`,
  )
})

test('Trust root: a countersignature from a supplied trusted issuer is issuer-trusted', () => {
  clearStores()
  const issuer = generateKeyPair()
  const agent = joinSocialContract({
    name: 'Issued', mission: 'Test trust roots', owner: 'test',
    capabilities: ['web_search'], platform: 'cloud', models: ['test'],
    floor: FLOOR, floorExtensions: [],
  })
  const countersigned = countersignPassport(agent.passport, issuer.privateKey, 'test-ca')
  const trust = verifySocialContract(countersigned, agent.attestation, {
    trustedIssuers: [issuer.publicKey],
  })
  assert.equal(trust.structurallyValid, true)
  assert.equal(trust.issuerTrusted, true)
})

test('Trust root: a countersignature from an issuer outside the list is not trusted', () => {
  clearStores()
  const trusted = generateKeyPair()
  const rogue = generateKeyPair()
  const agent = joinSocialContract({
    name: 'Rogue', mission: 'Test trust roots', owner: 'test',
    capabilities: ['web_search'], platform: 'cloud', models: ['test'],
    floor: FLOOR, floorExtensions: [],
  })
  const countersigned = countersignPassport(agent.passport, rogue.privateKey, 'rogue-ca')
  const trust = verifySocialContract(countersigned, agent.attestation, {
    trustedIssuers: [trusted.publicKey],
  })
  assert.equal(trust.issuerTrusted, false)
  assert.equal(trust.issuerChecked, true)
  assert.ok(trust.issuerErrors.length > 0, 'the untrusted countersignature is reported as an issuer error')
  // The bytes of this passport are sound. Only the trust root is missing.
  // Round 1 asserted structurallyValid === false here, which is what made
  // the flag depend on the caller's anchor list.
  assert.equal(trust.structurallyValid, true)
  assert.equal(trust.overall, false, 'the caller asked for issuer trust and did not get it')
})

test('Trust root: a self-signed passport is not issuer-trusted even when issuers are supplied', () => {
  clearStores()
  const issuer = generateKeyPair()
  const agent = joinSocialContract({
    name: 'NoCountersig', mission: 'Test trust roots', owner: 'test',
    capabilities: ['web_search'], platform: 'cloud', models: ['test'],
    floor: FLOOR, floorExtensions: [],
  })
  const trust = verifySocialContract(agent.passport, agent.attestation, {
    trustedIssuers: [issuer.publicKey],
  })
  assert.equal(trust.issuerTrusted, false)
  assert.equal(trust.structurallyValid, true)
  assert.equal(trust.overall, false)
})

// ══════════════════════════════════════════════════════════════════
// Invariant: structural validity is a property of the passport, not of
// the caller's trust configuration.
// ══════════════════════════════════════════════════════════════════
// Round 1 computed structurallyValid from a verifyPassport call that was
// ALSO given the anchors, so a byte-identical passport flipped
// structurallyValid true -> false purely because the caller passed a
// trustedIssuers list, and the CLI printed DOES NOT VERIFY over a passport
// whose signature was fine. The two questions are now answered by two
// calls: one without anchors for structure, one with them for trust.

test('Invariant 5: structurallyValid does not move when anchors are supplied', () => {
  clearStores()
  const issuer = generateKeyPair()
  const agent = joinSocialContract({
    name: 'Stable', mission: 'Test invariant 5', owner: 'test',
    capabilities: ['web_search'], platform: 'cloud', models: ['test'],
    floor: FLOOR, floorExtensions: [],
  })
  const withoutAnchors = verifySocialContract(agent.passport, agent.attestation)
  const withAnchors = verifySocialContract(agent.passport, agent.attestation, {
    trustedIssuers: [issuer.publicKey],
  })
  assert.equal(
    withoutAnchors.structurallyValid,
    withAnchors.structurallyValid,
    'same bytes, same structural verdict',
  )
  assert.equal(withoutAnchors.structurallyValid, true)
  assert.equal(withoutAnchors.issuerChecked, false)
  assert.equal(withAnchors.issuerChecked, true)
})

test('Invariant 5: a tampered passport is structurally invalid with or without anchors', () => {
  clearStores()
  const issuer = generateKeyPair()
  const agent = joinSocialContract({
    name: 'Tampered', mission: 'Test invariant 5', owner: 'test',
    capabilities: ['web_search'], platform: 'cloud', models: ['test'],
    floor: FLOOR, floorExtensions: [],
  })
  const tampered = { ...agent.passport, passport: { ...agent.passport.passport, mission: 'rewritten' } }
  assert.equal(verifySocialContract(tampered).structurallyValid, false)
  assert.equal(
    verifySocialContract(tampered, null, { trustedIssuers: [issuer.publicKey] }).structurallyValid,
    false,
  )
})

test('overall is exactly the old verdict: structure AND whatever trust was demanded', () => {
  clearStores()
  const issuer = generateKeyPair()
  const agent = joinSocialContract({
    name: 'Alias', mission: 'Test the alias', owner: 'test',
    capabilities: ['web_search'], platform: 'cloud', models: ['test'],
    floor: FLOOR, floorExtensions: [],
  })
  const countersigned = countersignPassport(agent.passport, issuer.privateKey, 'ca')

  for (const [label, passport, opts, expected] of [
    ['self-signed, no anchors', agent.passport, undefined, true],
    ['self-signed, anchors demanded', agent.passport, { trustedIssuers: [issuer.publicKey] }, false],
    ['countersigned, no anchors', countersigned, undefined, true],
    ['countersigned, anchors demanded', countersigned, { trustedIssuers: [issuer.publicKey] }, true],
  ] as const) {
    const t = verifySocialContract(passport, agent.attestation, opts)
    assert.equal(t.overall, expected, label)
    assert.equal(
      t.overall,
      t.structurallyValid && (!t.issuerChecked || t.issuerTrusted),
      `${label}: overall must equal structure AND demanded trust`,
    )
  }
})


// ══════════════════════════════════════════════════════════════════
// B4, deferred half: verifyPassport still admits a self-signed
// admin:everything passport. That default is NOT changed here.
// ══════════════════════════════════════════════════════════════════
// Flipping it fails 71 tests across the suite (measured), which makes it a
// protocol decision rather than a local repair, and it is escalated rather
// than taken. What IS closed is the reporting: the self-signed state was
// only available as English inside a warnings array, so no caller could
// branch on it without string-matching. These tests pin the machine-readable
// form, which is what a later flip will be built on.

test('B4: verifyPassport reports self-signed acceptance as a field, not only as prose', () => {
  const p = createPassport({
    agentId: 'attacker', agentName: 'attacker', ownerAlias: 'nobody',
    mission: 'claim everything', capabilities: ['admin:everything'],
    runtime: { platform: 'node', models: ['t'], toolsCount: 0, memoryType: 'none' },
    expiresInDays: 30,
  })
  const signed = signPassport(p.signedPassport.passport, p.keyPair.privateKey)

  const result = verifyPassport(signed)
  // The documented, unchanged default.
  assert.equal(result.valid, true)
  // The part that is now legible to code rather than only to a reader.
  assert.equal(result.issuerTrustChecked, false)
  assert.equal(result.selfSignedAccepted, true)
})

test('B4: a countersigned passport under anchors is not flagged self-signed', () => {
  const issuer = generateKeyPair()
  const p = createPassport({
    agentId: 'issued', agentName: 'issued', ownerAlias: 'owner',
    mission: 'normal', capabilities: ['data:read'],
    runtime: { platform: 'node', models: ['t'], toolsCount: 0, memoryType: 'none' },
    expiresInDays: 30,
  })
  const signed = signPassport(p.signedPassport.passport, p.keyPair.privateKey)
  const countersigned = countersignPassport(signed, issuer.privateKey, 'ca')

  const result = verifyPassport(countersigned, { trustedIssuers: [issuer.publicKey] })
  assert.equal(result.valid, true)
  assert.equal(result.issuerTrustChecked, true)
  assert.equal(result.selfSignedAccepted, false)
})

test('B4: an invalid passport is never flagged as an accepted self-signed one', () => {
  const p = createPassport({
    agentId: 'tampered', agentName: 'tampered', ownerAlias: 'owner',
    mission: 'original', capabilities: ['data:read'],
    runtime: { platform: 'node', models: ['t'], toolsCount: 0, memoryType: 'none' },
    expiresInDays: 30,
  })
  const signed = signPassport(p.signedPassport.passport, p.keyPair.privateKey)
  const tampered = { ...signed, passport: { ...signed.passport, mission: 'rewritten' } }

  const result = verifyPassport(tampered)
  assert.equal(result.valid, false)
  assert.equal(result.selfSignedAccepted, false, 'a failed verdict is not an acceptance of anything')
})
