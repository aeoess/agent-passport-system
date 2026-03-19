// Encrypted Messaging Audit Bridge Tests (Module 29)
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createMessageAuditLog, createAuditRecord, verifyAuditRecord,
  appendToAuditLog, queryBySender, queryCrossChainMessages,
  totalBytesBySender,
} from '../src/core/messaging-audit.js'
import type { EncryptedAgoraMessage } from '../src/types/encrypted-messaging.js'

// Helper: create a fake encrypted message (we only need metadata + ciphertext)
function fakeEncryptedMessage(overrides?: Partial<{
  senderAgentId: string, recipientAgentId: string, topic: string,
  ciphertext: string, taintHashes: string[], sequenceNumber: number,
  paddedSize: number, delegationId: string,
}>): EncryptedAgoraMessage {
  const senderKp = generateKeyPair()
  const recipientKp = generateKeyPair()
  return {
    message: {
      id: `msg-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: new Date().toISOString(),
      author: {
        agentId: overrides?.senderAgentId ?? 'sender-001',
        publicKey: senderKp.publicKey,
        encryptionPublicKey: 'enc_' + senderKp.publicKey.slice(0, 16),
      },
      recipient: {
        agentId: overrides?.recipientAgentId ?? 'recipient-001',
        publicKey: recipientKp.publicKey,
      },
      topic: overrides?.topic ?? 'general',
      type: 'encrypted' as const,
      delegationId: overrides?.delegationId ?? 'del-test-001',
      ephemeralPublicKey: 'ephemeral_' + Math.random().toString(36).slice(2, 18),
      nonce: Buffer.from(Array(24).fill(0).map(() => Math.floor(Math.random() * 256))).toString('base64'),
      taintHashes: overrides?.taintHashes ?? [],
      sequenceNumber: overrides?.sequenceNumber ?? 1,
      paddedSize: overrides?.paddedSize ?? 256,
      ciphertext: overrides?.ciphertext ?? 'encrypted_payload_' + Math.random().toString(36).slice(2, 32),
    },
    outerSignature: 'outer_sig_placeholder',
  }
}

describe('Audit Record — Creation', () => {
  it('creates audit record from encrypted message', () => {
    const gwKp = generateKeyPair()
    const msg = fakeEncryptedMessage()
    const record = createAuditRecord(msg, gwKp.privateKey, gwKp.publicKey)
    assert.ok(record.auditId.startsWith('ma_'))
    assert.ok(record.ciphertextHash)
    assert.equal(record.ciphertextHash.length, 64) // SHA-256 hex
    assert.equal(record.senderAgentId, 'sender-001')
    assert.equal(record.recipientAgentId, 'recipient-001')
    assert.equal(record.gatewayPublicKey, gwKp.publicKey)
    assert.ok(record.gatewaySignature)
  })

  it('preserves taint hashes from encrypted message', () => {
    const gwKp = generateKeyPair()
    const msg = fakeEncryptedMessage({ taintHashes: ['abc123', 'def456'] })
    const record = createAuditRecord(msg, gwKp.privateKey, gwKp.publicKey)
    assert.deepEqual(record.taintHashes, ['abc123', 'def456'])
  })

  it('audit record never contains plaintext', () => {
    const gwKp = generateKeyPair()
    const msg = fakeEncryptedMessage({ ciphertext: 'SECRET_ENCRYPTED_DATA' })
    const record = createAuditRecord(msg, gwKp.privateKey, gwKp.publicKey)
    const serialized = JSON.stringify(record)
    assert.ok(!serialized.includes('SECRET_ENCRYPTED_DATA'), 'Audit record must not contain ciphertext')
    assert.ok(record.ciphertextHash.length === 64, 'Should contain hash, not content')
  })
})

describe('Audit Record — Verification', () => {
  it('verifies valid audit record', () => {
    const gwKp = generateKeyPair()
    const msg = fakeEncryptedMessage()
    const record = createAuditRecord(msg, gwKp.privateKey, gwKp.publicKey)
    const result = verifyAuditRecord(record)
    assert.equal(result.valid, true)
    assert.equal(result.signatureValid, true)
  })

  it('rejects tampered audit record', () => {
    const gwKp = generateKeyPair()
    const msg = fakeEncryptedMessage()
    const record = createAuditRecord(msg, gwKp.privateKey, gwKp.publicKey)
    const tampered = { ...record, senderAgentId: 'imposter-001' }
    const result = verifyAuditRecord(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.signatureValid, false)
  })

  it('verifies ciphertext hash matches original message', () => {
    const gwKp = generateKeyPair()
    const msg = fakeEncryptedMessage()
    const record = createAuditRecord(msg, gwKp.privateKey, gwKp.publicKey)
    const result = verifyAuditRecord(record, msg)
    assert.equal(result.valid, true)
    assert.equal(result.hashMatches, true)
  })

  it('detects ciphertext hash mismatch (message was swapped)', () => {
    const gwKp = generateKeyPair()
    const msg1 = fakeEncryptedMessage({ ciphertext: 'message_one' })
    const msg2 = fakeEncryptedMessage({ ciphertext: 'message_two' })
    const record = createAuditRecord(msg1, gwKp.privateKey, gwKp.publicKey)
    // Verify against DIFFERENT message
    const result = verifyAuditRecord(record, msg2)
    assert.equal(result.valid, false)
    assert.equal(result.hashMatches, false)
    assert.equal(result.signatureValid, true)  // sig is still valid, just wrong message
  })
})

describe('Audit Log — Operations', () => {
  it('creates log and appends records', () => {
    const gwKp = generateKeyPair()
    let log = createMessageAuditLog(gwKp.publicKey)
    const msg = fakeEncryptedMessage()
    const record = createAuditRecord(msg, gwKp.privateKey, gwKp.publicKey)
    log = appendToAuditLog(log, record)
    assert.equal(log.records.length, 1)
  })

  it('rejects record from different gateway', () => {
    const gwKp1 = generateKeyPair()
    const gwKp2 = generateKeyPair()
    const log = createMessageAuditLog(gwKp1.publicKey)
    const msg = fakeEncryptedMessage()
    const record = createAuditRecord(msg, gwKp2.privateKey, gwKp2.publicKey)
    assert.throws(() => appendToAuditLog(log, record), /gateway key does not match/)
  })
})

describe('Audit Log — Queries', () => {
  it('queries by sender', () => {
    const gwKp = generateKeyPair()
    let log = createMessageAuditLog(gwKp.publicKey)
    const msg1 = fakeEncryptedMessage({ senderAgentId: 'alice' })
    const msg2 = fakeEncryptedMessage({ senderAgentId: 'bob' })
    const msg3 = fakeEncryptedMessage({ senderAgentId: 'alice' })
    log = appendToAuditLog(log, createAuditRecord(msg1, gwKp.privateKey, gwKp.publicKey))
    log = appendToAuditLog(log, createAuditRecord(msg2, gwKp.privateKey, gwKp.publicKey))
    log = appendToAuditLog(log, createAuditRecord(msg3, gwKp.privateKey, gwKp.publicKey))
    assert.equal(queryBySender(log, 'alice').length, 2)
    assert.equal(queryBySender(log, 'bob').length, 1)
  })

  it('queries cross-chain messages (those with taint hashes)', () => {
    const gwKp = generateKeyPair()
    let log = createMessageAuditLog(gwKp.publicKey)
    const clean = fakeEncryptedMessage({ taintHashes: [] })
    const tainted = fakeEncryptedMessage({ taintHashes: ['hash1'] })
    log = appendToAuditLog(log, createAuditRecord(clean, gwKp.privateKey, gwKp.publicKey))
    log = appendToAuditLog(log, createAuditRecord(tainted, gwKp.privateKey, gwKp.publicKey))
    assert.equal(queryCrossChainMessages(log).length, 1)
  })

  it('calculates total bytes by sender', () => {
    const gwKp = generateKeyPair()
    let log = createMessageAuditLog(gwKp.publicKey)
    const m1 = fakeEncryptedMessage({ senderAgentId: 'alice', paddedSize: 256 })
    const m2 = fakeEncryptedMessage({ senderAgentId: 'alice', paddedSize: 512 })
    log = appendToAuditLog(log, createAuditRecord(m1, gwKp.privateKey, gwKp.publicKey))
    log = appendToAuditLog(log, createAuditRecord(m2, gwKp.privateKey, gwKp.publicKey))
    assert.equal(totalBytesBySender(log, 'alice'), 768)
  })
})
