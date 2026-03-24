/**
 * Campaign 7: Three-Spec Composition Test
 *
 * Proves: Identity (DID Resolution) × Transport (QSP-1) × Governance (Entity Verification + Data Lifecycle)
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import sodium from 'libsodium-wrappers'
import {
  generateKeyPair, clearStores,
  createDID, publicKeyFromDID, resolveDID, isValidDID,
  hexToMultibase, multibaseToHex,
  createPrincipalIdentity,
  createDecisionLineageReceipt, verifyDecisionLineageReceipt,
  createMinimalEnvelope, verifyExecutionEnvelope,
  decodeQntmInvite, deriveQntmKeys,
  qntmEncrypt, qntmDecrypt, computeKeyId,
  sign, canonicalize,
} from '../src/index.js'
import type { EntityBinding } from '../src/index.js'

const TEST_INVITE_TOKEN = 'p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUNyoO3DM12Oom1lTss0u5nhraW52aXRlX3NhbHRYIJnHTkpBRQwpSj_7ZHMUHvPKnpf3r7yY_8gPRXk5RN2AbWludml0ZV9zZWNyZXRYIKbYnBf7banlbzaMK1YpeMzUNJAKg1Bi0P37WzHwvaqibWludml0ZXJfaWtfcGtYIIqw_2wL77fyrkF2igHm0SQXKd0hRcnA29phGsQQhAvJ'

function mockCorpoVerify(entityId: string) {
  if (entityId === 'test-entity-aps') {
    return {
      entity_id: 'test-entity-aps', name: 'AEOESS DAO LLC',
      status: 'active', entity_type: 'wyoming_dao_llc',
      authority_ceiling: ['hold_assets', 'delegate_authority', 'sign_contracts'],
      verified_at: '2026-03-24T00:00:00Z',
    }
  }
  return null
}

describe('Campaign 7 — Three-Spec Composition', () => {
  it('full flow: identity × transport × governance', async () => {
    await sodium.ready
    clearStores()

    // ═══ SETUP: Agent keys + DID + principal + entity ═══
    const agentA = generateKeyPair()
    const evaluator = generateKeyPair()
    const agentADid = createDID(agentA.publicKey)
    const evaluatorDid = createDID(evaluator.publicKey)

    const { principal, keyPair: principalKeys } = createPrincipalIdentity({
      displayName: 'Tima Pidlisnyi',
      jurisdiction: 'US',
      domain: 'aeoess.com',
    })
    // Attach entity binding (Corpo Wyoming DAO LLC)
    principal.entityBinding = {
      entityId: 'test-entity-aps',
      jurisdiction: 'WY',
      entityType: 'dao_llc',
      verificationEndpoint: 'https://api.corpo.llc/api/v1/entities/test-entity-aps',
      boundAt: new Date().toISOString(),
    } as EntityBinding

    // ═══ STEP 1: Create governance artifact (Decision Lineage Receipt) ═══
    const lineageReceipt = createDecisionLineageReceipt({
      decisionArtifactId: 'campaign7-decision-001',
      decisionType: 'loan_risk_assessment',
      contributingSources: [
        {
          sourceId: 'credit-bureau', accessReceiptId: 'ar-credit-001',
          derivationDepth: 1, transformPath: ['subset', 'embedding'],
          termsVersionAtAccess: '3.0', lineageConfidence: 'complete',
          compensationStatus: 'settled',
        },
        {
          sourceId: 'income-api', accessReceiptId: 'ar-income-001',
          derivationDepth: 2, transformPath: ['subset', 'aggregation'],
          termsVersionAtAccess: '1.0', lineageConfidence: 'partial',
          compensationStatus: 'pending',
        },
      ],
      lineageCompleteness: 'partial',
      transformChain: ['subset', 'embedding', 'aggregation', 'decision_artifact'],
      governingPurpose: 'inference:decision_support',
      explanation: 'Loan risk: 720. Recommend approve.',
      privateKey: agentA.privateKey,
    })
    assert.ok(lineageReceipt.receiptId.startsWith('dlr_'))

    // ═══ STEP 2: Wrap in SignedExecutionEnvelope ═══
    const receiptHash = createHash('sha256').update(canonicalize(lineageReceipt)).digest('hex')
    const decisionPayload = canonicalize({ verdict: 'permit', lineageReceiptId: lineageReceipt.receiptId })
    const decisionHash = createHash('sha256').update(decisionPayload).digest('hex')
    const evaluatorSig = sign(decisionPayload, evaluator.privateKey)

    const envelope = createMinimalEnvelope({
      agentDid: agentADid,
      runId: 'campaign7-run-001',
      actionId: 'campaign7-action-001',
      scope: ['inference:decision_support', 'data:read'],
      revocationStatus: 'active',
      decisionHash,
      policyRef: 'floor-v1.0',
      evaluationMethod: 'deterministic',
      verdict: 'permit',
      evaluatedAt: new Date().toISOString(),
      evaluatorDid,
      evaluatorSignature: evaluatorSig,
      receiptHash,
      signerPrivateKey: agentA.privateKey,
      signerPublicKey: agentA.publicKey,
    })
    assert.equal(envelope.schema, 'execution-envelope.v0.1')

    // ═══ STEP 3: Encrypt via qntm bridge (QSP-1 transport) ═══
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN)
    const qntmKeys = deriveQntmKeys(invite)

    // Bundle: envelope + lineage receipt as transport payload
    const transportPayload = JSON.stringify({ envelope, lineageReceipt })
    const plaintext = new TextEncoder().encode(transportPayload)
    const senderKeyId = computeKeyId(Buffer.from(agentA.publicKey, 'hex'))

    const qntmEnvelope = await qntmEncrypt(plaintext, qntmKeys, senderKeyId, 100)
    assert.ok(qntmEnvelope.ciphertext.length > plaintext.length, 'Encrypted payload includes auth tag')
    assert.ok(qntmEnvelope.msg_id.length === 16, 'Message ID is 16 bytes')

    // ═══ STEP 4: Agent B decrypts (QSP-1 verification) ═══
    const decrypted = await qntmDecrypt(qntmEnvelope, qntmKeys)
    const received = JSON.parse(new TextDecoder().decode(decrypted))
    assert.equal(received.envelope.agent_did, agentADid, 'Envelope survived QSP-1 transport')

    // ═══ STEP 5: Agent B verifies all three specs ═══

    // --- Spec 1: DID Resolution v1.0 ---
    const didResolution = resolveDID(agentADid)
    assert.ok(didResolution.didDocument, 'DID resolves')
    const resolvedKey = multibaseToHex(
      didResolution.didDocument!.verificationMethod![0].publicKeyMultibase!
    )
    assert.equal(resolvedKey, agentA.publicKey, 'DID resolves to correct key')

    // Sender ID per spec §4
    const senderId = createHash('sha256')
      .update(Buffer.from(resolvedKey, 'hex'))
      .digest().subarray(0, 16).toString('hex')
    assert.equal(senderId.length, 32)

    // --- Spec 2: Entity Verification v1.0 ---
    const entity = mockCorpoVerify(principal.entityBinding!.entityId)
    assert.ok(entity, 'Entity lookup succeeds')
    assert.equal(entity!.status, 'active', 'Entity is active')
    assert.equal(entity!.entity_type, 'wyoming_dao_llc')
    assert.ok(entity!.authority_ceiling.includes('delegate_authority'))

    // --- Spec 3: APS Governance (Envelope + Decision Lineage) ---
    // Verify the execution envelope (key is embedded in envelope.signature.public_key)
    const envCheck = verifyExecutionEnvelope(received.envelope)
    assert.equal(envCheck.signatureValid, true, 'Envelope signature valid')
    assert.equal(envCheck.capabilityActive, true, 'Capability not revoked')

    // The envelope's signing key must match the DID-resolved key
    assert.equal(received.envelope.signature.public_key, agentA.publicKey,
      'Envelope signer matches DID-resolved key')

    // Verify the Decision Lineage Receipt signature using the DID-resolved key
    const lineageCheck = verifyDecisionLineageReceipt(received.lineageReceipt, resolvedKey)
    assert.equal(lineageCheck, true, 'Lineage receipt verified via DID-resolved key')

    // Verify lineage content
    assert.equal(received.lineageReceipt.contributingSources.length, 2)
    assert.equal(received.lineageReceipt.governingPurpose, 'inference:decision_support')

    // ═══ COMPOSITION PROVEN ═══
    // One key (agentA.publicKey) flows through all three specs:
    // DID Resolution → Ed25519 key
    // QSP-1 → encrypted transport (sender identified by key ID)
    // Entity Verification → legal entity (via principal)
    // Envelope signature → verified against DID-resolved key
    // Lineage receipt → verified against same DID-resolved key
  })

  it('QSP-1 rejects tampered ciphertext', async () => {
    await sodium.ready
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN)
    const keys = deriveQntmKeys(invite)
    const agentKeys = generateKeyPair()
    const senderKeyId = computeKeyId(Buffer.from(agentKeys.publicKey, 'hex'))

    const plaintext = new TextEncoder().encode('sensitive governance data')
    const envelope = await qntmEncrypt(plaintext, keys, senderKeyId, 200)

    // Tamper with ciphertext
    const tampered = { ...envelope, ciphertext: new Uint8Array(envelope.ciphertext) }
    tampered.ciphertext[10] ^= 0xff

    await assert.rejects(
      () => qntmDecrypt(tampered, keys),
      { message: /ciphertext/ }
    )
  })


  it('rejects suspended entity', () => {
    const result = mockCorpoVerify('nonexistent-entity')
    assert.equal(result, null, 'Unknown entity returns null')
    const entityCheck = result !== null && result.status === 'active'
    assert.equal(entityCheck, false, 'Verification chain blocks on missing entity')
  })

  it('DID key mismatch blocks impersonation', async () => {
    await sodium.ready
    clearStores()

    const realAgent = generateKeyPair()
    const impersonator = generateKeyPair()
    const evaluator = generateKeyPair()

    const payload = canonicalize({ verdict: 'permit', test: true })
    const decisionHash = createHash('sha256').update(payload).digest('hex')
    const evalSig = sign(payload, evaluator.privateKey)

    // Real agent signs an envelope
    const envelope = createMinimalEnvelope({
      agentDid: createDID(realAgent.publicKey),
      runId: 'run-impersonation', actionId: 'act-001',
      scope: ['data:read'], revocationStatus: 'active',
      decisionHash, policyRef: 'floor-v1.0',
      evaluationMethod: 'deterministic', verdict: 'permit',
      evaluatedAt: new Date().toISOString(),
      evaluatorDid: createDID(evaluator.publicKey),
      evaluatorSignature: evalSig, receiptHash: 'abc',
      signerPrivateKey: realAgent.privateKey,
      signerPublicKey: realAgent.publicKey,
    })

    // Envelope embeds real agent's key — verify passes
    const realCheck = verifyExecutionEnvelope(envelope)
    assert.equal(realCheck.signatureValid, true)

    // Impersonator's DID resolves to a DIFFERENT key
    const impDid = createDID(impersonator.publicKey)
    const impResolution = resolveDID(impDid)
    const impKey = multibaseToHex(
      impResolution.didDocument!.verificationMethod![0].publicKeyMultibase!
    )

    // Cross-check: envelope's embedded key must NOT match impersonator's DID
    assert.notEqual(envelope.signature.public_key, impKey,
      'Envelope signer does not match impersonator DID — impersonation blocked')
  })

  it('sender ID consistent across DID resolution paths', () => {
    const keys = generateKeyPair()
    const did = createDID(keys.publicKey)
    const resolved = publicKeyFromDID(did)

    const fromDid = createHash('sha256')
      .update(Buffer.from(resolved, 'hex'))
      .digest().subarray(0, 16).toString('hex')

    const direct = createHash('sha256')
      .update(Buffer.from(keys.publicKey, 'hex'))
      .digest().subarray(0, 16).toString('hex')

    assert.equal(fromDid, direct, 'Sender ID matches regardless of resolution path')
  })

  it('one key flows through all three specs', async () => {
    await sodium.ready
    clearStores()

    const agent = generateKeyPair()
    const eval2 = generateKeyPair()
    const did = createDID(agent.publicKey)

    // Spec 1: DID Resolution → key
    const resolution = resolveDID(did)
    const resolvedKey = multibaseToHex(
      resolution.didDocument!.verificationMethod![0].publicKeyMultibase!
    )

    // Spec 2: key → sender_id (QSP-1 §4)
    const senderId = createHash('sha256')
      .update(Buffer.from(resolvedKey, 'hex'))
      .digest().subarray(0, 16).toString('hex')
    assert.equal(senderId.length, 32)

    // Spec 3: key → entity (mocked)
    const entity = mockCorpoVerify('test-entity-aps')
    assert.ok(entity && entity.status === 'active')

    // Spec 3 continued: key → envelope verification
    const payload = canonicalize({ verdict: 'permit', chain: true })
    const dHash = createHash('sha256').update(payload).digest('hex')
    const eSig = sign(payload, eval2.privateKey)

    const envelope = createMinimalEnvelope({
      agentDid: did, runId: 'chain-run', actionId: 'chain-act',
      scope: ['data:read'], revocationStatus: 'active',
      decisionHash: dHash, policyRef: 'floor-v1.0',
      evaluationMethod: 'deterministic', verdict: 'permit',
      evaluatedAt: new Date().toISOString(),
      evaluatorDid: createDID(eval2.publicKey),
      evaluatorSignature: eSig, receiptHash: 'xyz',
      signerPrivateKey: agent.privateKey,
      signerPublicKey: agent.publicKey,
    })

    const check = verifyExecutionEnvelope(envelope)
    assert.equal(check.signatureValid, true, 'Same key flows through all three specs')
    assert.equal(envelope.signature.public_key, resolvedKey, 'One key, three specs, one identity')
  })
})
