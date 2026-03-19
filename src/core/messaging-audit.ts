// ══════════════════════════════════════════════════════════════════
// Encrypted Messaging Audit Bridge — Module 29
// ══════════════════════════════════════════════════════════════════
// Problem: E2E encrypted messages (Module 19) bypass the gateway.
// The gateway can't see content, but needs to know:
//   - A message was sent (for rate limiting, compliance)
//   - Who sent to whom (for delegation scope checks)
//   - Taint labels (for cross-chain enforcement)
//   - Size (for spend/quota tracking)
//
// Solution: Audit records contain metadata + hash of ciphertext,
// never plaintext. The gateway can verify the audit record matches
// the encrypted message without decrypting it.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { randomUUID } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type { EncryptedAgoraMessage } from '../types/encrypted-messaging.js'

// ── Types ──

export interface MessageAuditRecord {
  auditId: string
  /** SHA-256 hash of the full ciphertext — verifiable without decrypting */
  ciphertextHash: string
  /** Sender identity (public, not secret) */
  senderAgentId: string
  senderPublicKey: string
  /** Recipient identity */
  recipientAgentId: string
  recipientPublicKey: string
  /** Delegation authorizing this communication */
  delegationId: string
  /** Taint hashes from the encrypted message (already cleartext in Module 19) */
  taintHashes: string[]
  /** Padded ciphertext size in bytes */
  messageSize: number
  /** Sequence number (monotonic within conversation) */
  sequenceNumber: number
  /** Topic (cleartext metadata in Module 19) */
  topic: string
  /** When the audit record was created */
  timestamp: string
  /** Ed25519 signature by the gateway over this record */
  gatewaySignature: string
  /** Gateway public key */
  gatewayPublicKey: string
}

export interface AuditVerification {
  valid: boolean
  /** Whether the ciphertext hash matches the encrypted message */
  hashMatches: boolean
  /** Whether the gateway signature is valid */
  signatureValid: boolean
  /** Reason if invalid */
  reason?: string
}

export interface MessageAuditLog {
  records: MessageAuditRecord[]
  gatewayPublicKey: string
  createdAt: string
}

// ── Create Audit Log ──

export function createMessageAuditLog(gatewayPublicKey: string): MessageAuditLog {
  return {
    records: [],
    gatewayPublicKey,
    createdAt: new Date().toISOString(),
  }
}

// ── Hash Ciphertext ──

function hashCiphertext(ciphertext: string): string {
  return createHash('sha256').update(ciphertext).digest('hex')
}

// ── Create Audit Record ──

/**
 * Create an audit record from an encrypted message.
 * Extracts ONLY metadata + hash — never touches plaintext.
 * The gateway signs the record as proof it observed the message.
 */
export function createAuditRecord(
  message: EncryptedAgoraMessage,
  gatewayPrivateKey: string,
  gatewayPublicKey: string,
): MessageAuditRecord {
  const ciphertextHash = hashCiphertext(message.message.ciphertext)
  const timestamp = new Date().toISOString()
  const auditId = `ma_${randomUUID().slice(0, 8)}`

  const record: Omit<MessageAuditRecord, 'gatewaySignature'> = {
    auditId,
    ciphertextHash,
    senderAgentId: message.message.author.agentId,
    senderPublicKey: message.message.author.publicKey,
    recipientAgentId: message.message.recipient.agentId,
    recipientPublicKey: message.message.recipient.publicKey,
    delegationId: message.message.delegationId,
    taintHashes: message.message.taintHashes ?? [],
    messageSize: message.message.paddedSize,
    sequenceNumber: message.message.sequenceNumber,
    topic: message.message.topic,
    timestamp,
    gatewayPublicKey,
  }

  const payload = canonicalize(record)
  const gatewaySignature = sign(payload, gatewayPrivateKey)

  return { ...record, gatewaySignature } as MessageAuditRecord
}

// ── Verify Audit Record ──

/**
 * Verify an audit record:
 * 1. Gateway signature is valid
 * 2. Optionally: ciphertext hash matches original message
 */
export function verifyAuditRecord(
  record: MessageAuditRecord,
  originalMessage?: EncryptedAgoraMessage,
): AuditVerification {
  // Verify gateway signature
  const { gatewaySignature, ...unsigned } = record
  const payload = canonicalize(unsigned)
  const signatureValid = verify(payload, gatewaySignature, record.gatewayPublicKey)

  if (!signatureValid) {
    return { valid: false, hashMatches: false, signatureValid: false, reason: 'Gateway signature invalid' }
  }

  // If original message provided, verify hash match
  if (originalMessage) {
    const expectedHash = hashCiphertext(originalMessage.message.ciphertext)
    const hashMatches = expectedHash === record.ciphertextHash
    if (!hashMatches) {
      return { valid: false, hashMatches: false, signatureValid: true, reason: 'Ciphertext hash mismatch' }
    }
    return { valid: true, hashMatches: true, signatureValid: true }
  }

  return { valid: true, hashMatches: true, signatureValid: true }
}

// ── Log Operations ──

export function appendToAuditLog(log: MessageAuditLog, record: MessageAuditRecord): MessageAuditLog {
  if (record.gatewayPublicKey !== log.gatewayPublicKey) {
    throw new Error('Audit record gateway key does not match log gateway key')
  }
  return { ...log, records: [...log.records, record] }
}

/**
 * Query audit log by sender — how many messages did this agent send?
 */
export function queryBySender(log: MessageAuditLog, senderAgentId: string): MessageAuditRecord[] {
  return log.records.filter(r => r.senderAgentId === senderAgentId)
}

/**
 * Query audit log for cross-chain messages (those with taint hashes).
 */
export function queryCrossChainMessages(log: MessageAuditLog): MessageAuditRecord[] {
  return log.records.filter(r => r.taintHashes.length > 0)
}

/**
 * Total bytes sent by a specific agent — for quota enforcement.
 */
export function totalBytesBySender(log: MessageAuditLog, senderAgentId: string): number {
  return log.records
    .filter(r => r.senderAgentId === senderAgentId)
    .reduce((sum, r) => sum + r.messageSize, 0)
}
