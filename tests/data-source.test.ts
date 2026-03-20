// Data Source Registration & Access Receipts — Tests (Module 36A)
// 25 tests, 6 suites

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  registerSelfAttestedSource, registerCustodianAttestedSource,
  registerGatewayObservedSource, verifySourceReceipt, revokeSourceReceipt,
  recordDataAccess, verifyDataAccessReceipt,
  checkTermsCompliance, composeTerms,
  buildDataAccessMerkleRoot, proveDataAccessInclusion,
  verifyDataAccessInclusionProof, addDataAccessToLedger,
} from '../src/core/data-source.js'
import { createReceiptLedger } from '../src/core/receipt-ledger.js'
import type { DataTerms } from '../src/types/data-source.js'
import { createHash } from 'crypto'

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex')
}

function makeTerms(overrides?: Partial<DataTerms>): DataTerms {
  return {
    allowedPurposes: ['read', 'analyze', 'summarize'],
    requireAttribution: false,
    requireNotification: false,
    compensation: { type: 'none' },
    derivativePolicy: 'unrestricted',
    auditVisibility: 'public',
    revocable: true,
    ...overrides,
  }
}

// ══════════════════════════════════════
// Suite 1: Source Registration (5 tests)
// ══════════════════════════════════════

describe('Module 36A: Source Registration', () => {
  it('Test 1: registerSelfAttestedSource — valid signature, trustLevel high', async () => {
    const owner = await generateKeyPair()
    const terms = makeTerms()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'principal_alice',
      ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('alice health data v1'),
      contentType: 'document',
      contentDescriptor: 'Alice health records 2026',
      dataTerms: terms,
    })
    assert.ok(receipt.sourceReceiptId.startsWith('srcr_'))
    assert.equal(receipt.sourceMode, 'self_attested')
    assert.equal(receipt.sourcePrincipalId, 'principal_alice')
    assert.equal(receipt.issuedBy, owner.publicKey)
    const v = verifySourceReceipt(receipt)
    assert.ok(v.valid)
    assert.ok(v.signatureValid)
    assert.equal(v.trustLevel, 'high')
  })

  it('Test 2: registerCustodianAttestedSource — custodian signs', async () => {
    const owner = await generateKeyPair()
    const custodian = await generateKeyPair()
    const receipt = registerCustodianAttestedSource({
      ownerPrincipalId: 'principal_bob',
      ownerPublicKey: owner.publicKey,
      custodianPublicKey: custodian.publicKey,
      custodianPrivateKey: custodian.privateKey,
      contentCommitment: sha256('bob dataset'),
      contentType: 'structured_data',
      contentDescriptor: 'Bob API dataset',
      dataTerms: makeTerms(),
    })
    assert.equal(receipt.sourceMode, 'custodian_attested')
    assert.equal(receipt.sourcePrincipalId, 'principal_bob')
    assert.equal(receipt.issuedBy, custodian.publicKey)
    const v = verifySourceReceipt(receipt)
    assert.ok(v.valid)
    assert.equal(v.trustLevel, 'medium')
  })

  it('Test 3: registerGatewayObservedSource — null principal', async () => {
    const gw = await generateKeyPair()
    const receipt = registerGatewayObservedSource({
      gatewayPublicKey: gw.publicKey,
      gatewayPrivateKey: gw.privateKey,
      contentCommitment: sha256('unknown webpage'),
      contentType: 'document',
      contentDescriptor: 'Scraped webpage',
      gatewayDefaultTerms: makeTerms(),
    })
    assert.equal(receipt.sourceMode, 'gateway_observed')
    assert.equal(receipt.sourcePrincipalId, null)
    assert.equal(receipt.issuedBy, gw.publicKey)
    const v = verifySourceReceipt(receipt)
    assert.ok(v.valid)
    assert.equal(v.trustLevel, 'low')
  })

  it('Test 4: verifySourceReceipt — rejects tampered contentCommitment', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('original'), contentType: 'document',
      contentDescriptor: 'test', dataTerms: makeTerms(),
    })
    const tampered = { ...receipt, contentCommitment: sha256('tampered') }
    const v = verifySourceReceipt(tampered)
    assert.ok(!v.valid)
    assert.ok(!v.signatureValid)
  })

  it('Test 5: verifySourceReceipt — rejects expired receipt', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('data'), contentType: 'document',
      contentDescriptor: 'test', dataTerms: makeTerms(),
    })
    // Force expiry in the past
    const expired = { ...receipt, expiresAt: '2020-01-01T00:00:00Z' }
    const v = verifySourceReceipt(expired)
    assert.ok(!v.valid)
    assert.ok(!v.notExpired)
  })

  it('Test 5b: verifySourceReceipt — injecting expiresAt post-creation breaks signature', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('data'), contentType: 'document',
      contentDescriptor: 'test', dataTerms: makeTerms(),
    })
    // Attacker tries to add expiresAt to make receipt appear expired
    const injected = { ...receipt, expiresAt: '2020-01-01T00:00:00Z' }
    const v = verifySourceReceipt(injected)
    // Signature MUST break — expiresAt is part of signed payload
    assert.ok(!v.signatureValid, 'expiresAt injection must invalidate signature')
  })
})

// ══════════════════════════════════════
// Suite 2: Source Lifecycle (3 tests)
// ══════════════════════════════════════

describe('Module 36A: Source Lifecycle', () => {
  it('Test 6: revokeSourceReceipt — sets revokedAt and reason', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('data'), contentType: 'document',
      contentDescriptor: 'test', dataTerms: makeTerms(),
    })
    const revoked = revokeSourceReceipt({
      receipt, reason: 'No longer sharing', revokerPrivateKey: owner.privateKey,
    })
    assert.ok(revoked.revokedAt)
    assert.equal(revoked.revocationReason, 'No longer sharing')
    const v = verifySourceReceipt(revoked)
    assert.ok(!v.valid)
    assert.ok(!v.notRevoked)
  })

  it('Test 7: revokeSourceReceipt — original signature still validates on base fields', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('data'), contentType: 'document',
      contentDescriptor: 'test', dataTerms: makeTerms(),
    })
    const revoked = revokeSourceReceipt({
      receipt, reason: 'done', revokerPrivateKey: owner.privateKey,
    })
    // Signature was computed on original fields (excl revokedAt)
    // So the base receipt signature should still be valid
    assert.equal(revoked.signature, receipt.signature)
  })

  it('Test 7b: revokeSourceReceipt — rejects revocation by wrong key', async () => {
    const owner = await generateKeyPair()
    const attacker = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('data'), contentType: 'document',
      contentDescriptor: 'test', dataTerms: makeTerms(),
    })
    assert.throws(() => {
      revokeSourceReceipt({
        receipt, reason: 'hijack', revokerPrivateKey: attacker.privateKey,
      })
    }, /revoker key does not match/)
  })

  it('Test 8: gateway_observed with default terms frozen into receipt', async () => {
    const gw = await generateKeyPair()
    const defaultTerms = makeTerms({ requireAttribution: true })
    const receipt = registerGatewayObservedSource({
      gatewayPublicKey: gw.publicKey, gatewayPrivateKey: gw.privateKey,
      contentCommitment: sha256('web data'), contentType: 'document',
      contentDescriptor: 'test', gatewayDefaultTerms: defaultTerms,
    })
    assert.ok(receipt.dataTerms.requireAttribution)
  })
})

// ══════════════════════════════════════
// Suite 3: Terms Compliance — Hard vs Advisory (7 tests)
// ══════════════════════════════════════

describe('Module 36A: Terms Compliance', () => {
  it('Test 9: passes with zero violations', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('d'), contentType: 'document',
      contentDescriptor: 't', dataTerms: makeTerms(),
    })
    const result = checkTermsCompliance({
      sourceReceipt: receipt, declaredPurpose: 'read',
      agentId: 'agent1', principalId: 'prin1',
    })
    assert.ok(result.compliant)
    assert.equal(result.hardViolations.length, 0)
    assert.equal(result.advisoryWarnings.length, 0)
  })

  it('Test 10: hardViolation — source revoked', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('d'), contentType: 'document',
      contentDescriptor: 't', dataTerms: makeTerms(),
    })
    const revoked = revokeSourceReceipt({ receipt, revokerPrivateKey: owner.privateKey })
    const result = checkTermsCompliance({
      sourceReceipt: revoked, declaredPurpose: 'read',
      agentId: 'a1', principalId: 'p1',
    })
    assert.ok(!result.compliant)
    assert.ok(result.hardViolations.some(v => v.includes('revoked')))
  })

  it('Test 11: hardViolation — terms expired', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('d'), contentType: 'document',
      contentDescriptor: 't',
      dataTerms: makeTerms({ expiresAt: '2020-01-01T00:00:00Z' }),
    })
    const result = checkTermsCompliance({
      sourceReceipt: receipt, declaredPurpose: 'read',
      agentId: 'a1', principalId: 'p1',
    })
    assert.ok(!result.compliant)
    assert.ok(result.hardViolations.some(v => v.includes('expired')))
  })

  it('Test 12: hardViolation — agent in excludedAgents', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('d'), contentType: 'document',
      contentDescriptor: 't',
      dataTerms: makeTerms({ excludedAgents: ['bad_agent'] }),
    })
    const result = checkTermsCompliance({
      sourceReceipt: receipt, declaredPurpose: 'read',
      agentId: 'bad_agent', principalId: 'p1',
    })
    assert.ok(!result.compliant)
    assert.ok(result.hardViolations.some(v => v.includes('excludedAgents')))
  })

  it('Test 13: hardViolation — maxAccessCount exceeded', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('d'), contentType: 'document',
      contentDescriptor: 't',
      dataTerms: makeTerms({ maxAccessCount: 10 }),
    })
    const result = checkTermsCompliance({
      sourceReceipt: receipt, declaredPurpose: 'read',
      agentId: 'a1', principalId: 'p1',
      currentAccessCount: 10,
    })
    assert.ok(!result.compliant)
    assert.ok(result.hardViolations.some(v => v.includes('Max access count')))
  })

  it('Test 14: advisoryWarning — purpose not in allowedPurposes', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('d'), contentType: 'document',
      contentDescriptor: 't',
      dataTerms: makeTerms({ allowedPurposes: ['read', 'analyze'] }),
    })
    const result = checkTermsCompliance({
      sourceReceipt: receipt, declaredPurpose: 'train',
      agentId: 'a1', principalId: 'p1',
    })
    // Still compliant (purpose is advisory, not hard)
    assert.ok(result.compliant)
    assert.ok(result.advisoryWarnings.some(w => w.includes("'train'")))
  })

  it('Test 15: advisoryWarning — purpose in excludedPurposes', async () => {
    const owner = await generateKeyPair()
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('d'), contentType: 'document',
      contentDescriptor: 't',
      dataTerms: makeTerms({ excludedPurposes: ['train', 'commercial'] }),
    })
    const result = checkTermsCompliance({
      sourceReceipt: receipt, declaredPurpose: 'train',
      agentId: 'a1', principalId: 'p1',
    })
    assert.ok(result.compliant) // advisory only
    assert.ok(result.advisoryWarnings.some(w => w.includes('excludedPurposes')))
  })
})

// ══════════════════════════════════════
// Suite 4: Data Access Receipts (4 tests)
// ══════════════════════════════════════

describe('Module 36A: Data Access Receipts', () => {
  it('Test 16: recordDataAccess — gateway signature valid', async () => {
    const owner = await generateKeyPair()
    const gw = await generateKeyPair()
    const agent = await generateKeyPair()
    const src = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('data'), contentType: 'document',
      contentDescriptor: 'test', dataTerms: makeTerms(),
    })
    const access = recordDataAccess({
      sourceReceipt: src, dataHash: sha256('data'),
      agentId: 'agent_1', agentPublicKey: agent.publicKey,
      principalId: 'p1', executionFrameId: 'frame_001',
      accessScope: 'data:read', accessMethod: 'file_read',
      declaredPurpose: 'read',
      gatewayId: 'gw_1', gatewayPublicKey: gw.publicKey,
      gatewayPrivateKey: gw.privateKey,
    })
    assert.ok(access.accessReceiptId.startsWith('dacr_'))
    assert.equal(access.sourceReceiptId, src.sourceReceiptId)
    assert.equal(access.sourceMode, 'self_attested')
    assert.equal(access.declaredPurpose, 'read')
    const v = verifyDataAccessReceipt(access)
    assert.ok(v.valid)
    assert.ok(v.gatewaySignatureValid)
  })

  it('Test 17: rejects tampered dataHash', async () => {
    const owner = await generateKeyPair()
    const gw = await generateKeyPair()
    const agent = await generateKeyPair()
    const src = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('data'), contentType: 'document',
      contentDescriptor: 'test', dataTerms: makeTerms(),
    })
    const access = recordDataAccess({
      sourceReceipt: src, dataHash: sha256('data'),
      agentId: 'a1', agentPublicKey: agent.publicKey,
      principalId: 'p1', executionFrameId: 'f1',
      accessScope: 'data:read', accessMethod: 'api_call',
      declaredPurpose: 'analyze',
      gatewayId: 'gw1', gatewayPublicKey: gw.publicKey,
      gatewayPrivateKey: gw.privateKey,
    })
    const tampered = { ...access, dataHash: sha256('different data') }
    const v = verifyDataAccessReceipt(tampered)
    assert.ok(!v.valid)
    assert.ok(!v.gatewaySignatureValid)
  })

  it('Test 18: rejects invalid gateway signature', async () => {
    const owner = await generateKeyPair()
    const gw = await generateKeyPair()
    const agent = await generateKeyPair()
    const src = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('d'), contentType: 'document',
      contentDescriptor: 't', dataTerms: makeTerms(),
    })
    const access = recordDataAccess({
      sourceReceipt: src, dataHash: sha256('d'),
      agentId: 'a1', agentPublicKey: agent.publicKey,
      principalId: 'p1', executionFrameId: 'f1',
      accessScope: 'data:read', accessMethod: 'file_read',
      declaredPurpose: 'read',
      gatewayId: 'gw1', gatewayPublicKey: gw.publicKey,
      gatewayPrivateKey: gw.privateKey,
    })
    const forged = { ...access, gatewaySignature: 'deadbeef' }
    const v = verifyDataAccessReceipt(forged)
    assert.ok(!v.valid)
    assert.ok(!v.gatewaySignatureValid)
  })

  it('Test 19: termsAtAccessTime snapshot survives term change', async () => {
    const owner = await generateKeyPair()
    const gw = await generateKeyPair()
    const agent = await generateKeyPair()
    const src = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('d'), contentType: 'document',
      contentDescriptor: 't',
      dataTerms: makeTerms({ requireAttribution: false }),
    })
    const access = recordDataAccess({
      sourceReceipt: src, dataHash: sha256('d'),
      agentId: 'a1', agentPublicKey: agent.publicKey,
      principalId: 'p1', executionFrameId: 'f1',
      accessScope: 'data:read', accessMethod: 'file_read',
      declaredPurpose: 'read',
      gatewayId: 'gw1', gatewayPublicKey: gw.publicKey,
      gatewayPrivateKey: gw.privateKey,
    })
    // Snapshot should be frozen at access time
    assert.equal(access.termsAtAccessTime.requireAttribution, false)
    // Mutating original source terms should NOT change the snapshot
    src.dataTerms.requireAttribution = true
    assert.equal(access.termsAtAccessTime.requireAttribution, false)
  })

  it('Test 19b: termsAtAccessTime deep clone — nested compensation survives mutation', async () => {
    const owner = await generateKeyPair()
    const gw = await generateKeyPair()
    const agent = await generateKeyPair()
    const src = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('d'), contentType: 'document',
      contentDescriptor: 't',
      dataTerms: makeTerms({ compensation: { type: 'per_access', amount: 5, currency: 'USD' } }),
    })
    const access = recordDataAccess({
      sourceReceipt: src, dataHash: sha256('d'),
      agentId: 'a1', agentPublicKey: agent.publicKey,
      principalId: 'p1', executionFrameId: 'f1',
      accessScope: 'data:read', accessMethod: 'file_read',
      declaredPurpose: 'read',
      gatewayId: 'gw1', gatewayPublicKey: gw.publicKey,
      gatewayPrivateKey: gw.privateKey,
    })
    // Mutate the nested compensation object on the source
    const comp = src.dataTerms.compensation as { type: string; amount: number; currency: string }
    comp.amount = 999
    // Snapshot must be unaffected (deep clone, not shallow spread)
    const snapComp = access.termsAtAccessTime.compensation as { type: string; amount: number; currency: string }
    assert.equal(snapComp.amount, 5, 'Deep clone must protect nested compensation object')
  })
})

// ══════════════════════════════════════
// Suite 5: Terms Composition (3 tests)
// ══════════════════════════════════════

describe('Module 36A: Terms Composition', () => {
  it('Test 20: intersection of allowedPurposes', () => {
    const t1 = makeTerms({ allowedPurposes: ['read', 'analyze', 'train'] })
    const t2 = makeTerms({ allowedPurposes: ['read', 'summarize', 'train'] })
    const composed = composeTerms([t1, t2])
    assert.deepEqual(composed.allowedPurposes.sort(), ['read', 'train'])
  })

  it('Test 21: union of excludedPurposes', () => {
    const t1 = makeTerms({ excludedPurposes: ['train'] })
    const t2 = makeTerms({ excludedPurposes: ['commercial'] })
    const composed = composeTerms([t1, t2])
    assert.deepEqual(composed.excludedPurposes?.sort(), ['commercial', 'train'])
  })

  it('Test 22: most restrictive derivativePolicy wins', () => {
    const t1 = makeTerms({ derivativePolicy: 'unrestricted' })
    const t2 = makeTerms({ derivativePolicy: 'attribution_required' })
    const t3 = makeTerms({ derivativePolicy: 'same_terms' })
    const composed = composeTerms([t1, t2, t3])
    assert.equal(composed.derivativePolicy, 'attribution_required')
  })
})

// ══════════════════════════════════════
// Suite 6: Merkle Commitment (3 tests)
// ══════════════════════════════════════

describe('Module 36A: Merkle Commitment', () => {
  async function makeAccessReceipt() {
    const owner = await generateKeyPair()
    const gw = await generateKeyPair()
    const agent = await generateKeyPair()
    const src = registerSelfAttestedSource({
      ownerPrincipalId: 'p1', ownerPublicKey: owner.publicKey,
      ownerPrivateKey: owner.privateKey,
      contentCommitment: sha256('data_' + Math.random()),
      contentType: 'document', contentDescriptor: 'test',
      dataTerms: makeTerms(),
    })
    return recordDataAccess({
      sourceReceipt: src, dataHash: sha256('accessed_' + Math.random()),
      agentId: 'a1', agentPublicKey: agent.publicKey,
      principalId: 'p1', executionFrameId: 'f_' + Math.random(),
      accessScope: 'data:read', accessMethod: 'api_call',
      declaredPurpose: 'read',
      gatewayId: 'gw1', gatewayPublicKey: gw.publicKey,
      gatewayPrivateKey: gw.privateKey,
    })
  }

  it('Test 23: buildDataAccessMerkleRoot — deterministic root', async () => {
    const r1 = await makeAccessReceipt()
    const r2 = await makeAccessReceipt()
    const r3 = await makeAccessReceipt()
    const root1 = buildDataAccessMerkleRoot([r1, r2, r3])
    const root2 = buildDataAccessMerkleRoot([r1, r2, r3])
    assert.equal(root1, root2)
    assert.ok(root1.length === 64) // SHA-256 hex
  })

  it('Test 24: proveDataAccessInclusion — valid proof', async () => {
    const r1 = await makeAccessReceipt()
    const r2 = await makeAccessReceipt()
    const r3 = await makeAccessReceipt()
    const proof = proveDataAccessInclusion([r1, r2, r3], r2.accessReceiptId)
    assert.ok(proof !== null)
    assert.ok(verifyDataAccessInclusionProof(proof!))
  })

  it('Test 25: proveDataAccessInclusion — null for missing receipt', async () => {
    const r1 = await makeAccessReceipt()
    const r2 = await makeAccessReceipt()
    const proof = proveDataAccessInclusion([r1, r2], 'dacr_nonexistent')
    assert.equal(proof, null)
  })
})
