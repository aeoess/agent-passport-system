// ══════════════════════════════════════════════════════════════════
// E2E Encrypted Messaging — Implementation
// ══════════════════════════════════════════════════════════════════
// Consensus spec: GPT + Gemini + Claude hostile review.
// libsodium-wrappers for X25519 + XSalsa20-Poly1305.
// Ephemeral-static ECDH per message. Double signature.
// ══════════════════════════════════════════════════════════════════

import sodium from 'libsodium-wrappers'
import { createHash, randomBytes } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  EncryptionKeyAnnouncement, EncryptionKeypair,
  EncryptedAgoraMessage, DecryptedPayload
} from '../types/encrypted-messaging.js'

/** Ensure libsodium is initialized before any crypto operation */
let sodiumReady = false
async function ensureSodium(): Promise<void> {
  if (!sodiumReady) {
    await sodium.ready
    sodiumReady = true
  }
}

// ── Key Generation ──

/**
 * Generate a dedicated X25519 encryption keypair.
 * Separate from Ed25519 identity key (consensus: key separation).
 */
export async function generateEncryptionKeypair(): Promise<EncryptionKeypair> {
  await ensureSodium()
  const kp = sodium.crypto_box_keypair()
  return {
    publicKey: sodium.to_base64(kp.publicKey),
    privateKey: sodium.to_base64(kp.privateKey)
  }
}

/**
 * Create a Key Announcement: agent signs its X25519 public key
 * with its Ed25519 identity key and publishes it.
 */
export function createKeyAnnouncement(
  agentId: string,
  encryptionPublicKey: string,
  identityPublicKey: string,
  identityPrivateKey: string
): EncryptionKeyAnnouncement {
  const payload = canonicalize({ agentId, encryptionPublicKey })
  const signature = sign(payload, identityPrivateKey)
  return {
    agentId,
    encryptionPublicKey,
    identityPublicKey,
    signature,
    createdAt: new Date().toISOString()
  }
}


/**
 * Verify a Key Announcement: Ed25519 signature over (agentId + encryptionPublicKey).
 */
export function verifyKeyAnnouncement(announcement: EncryptionKeyAnnouncement): boolean {
  const payload = canonicalize({
    agentId: announcement.agentId,
    encryptionPublicKey: announcement.encryptionPublicKey
  })
  return verify(payload, announcement.signature, announcement.identityPublicKey)
}

// ── Padding ──

const BLOCK_SIZES = [256, 1024, 4096, 16384, 65536, 262144]

/**
 * Pad data to nearest power-of-2 block size.
 * Mitigates message-size side channel.
 */
export function padToBlock(data: Uint8Array): Uint8Array {
  const targetSize = BLOCK_SIZES.find(s => s >= data.length) ?? data.length
  if (targetSize === data.length) return data
  const padded = new Uint8Array(targetSize)
  padded.set(data)
  // First 4 bytes after data store the real length (little-endian)
  const view = new DataView(padded.buffer)
  // Store length marker at the very end of the padded block
  view.setUint32(targetSize - 4, data.length, true)
  return padded
}

/**
 * Remove padding. Reads the real length from the last 4 bytes.
 */
export function unpad(padded: Uint8Array): Uint8Array {
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength)
  const realLength = view.getUint32(padded.length - 4, true)
  if (realLength > padded.length - 4 || realLength === 0) {
    // Not padded or invalid — return as-is
    return padded
  }
  return padded.slice(0, realLength)
}

// ── Core Encrypt/Decrypt ──

/**
 * Encrypt a message using ephemeral-static ECDH.
 * Sender generates fresh ephemeral X25519 keypair per message.
 * Shared secret = X25519(ephemeral_private, recipient_static_public).
 */
export async function encryptPayload(
  plaintext: string,
  recipientEncryptionPublicKey: string
): Promise<{ ciphertext: string; nonce: string; ephemeralPublicKey: string }> {
  await ensureSodium()

  // Generate ephemeral keypair (sender forward secrecy)
  const ephemeral = sodium.crypto_box_keypair()

  const recipientPub = sodium.from_base64(recipientEncryptionPublicKey)
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)

  // Pad plaintext before encryption
  const plaintextBytes = sodium.from_string(plaintext)
  const paddedPlaintext = padToBlock(plaintextBytes)

  // Encrypt: XSalsa20-Poly1305 with ephemeral-static DH
  const ciphertextBytes = sodium.crypto_box_easy(
    paddedPlaintext,
    nonce,
    recipientPub,
    ephemeral.privateKey
  )

  return {
    ciphertext: sodium.to_base64(ciphertextBytes),
    nonce: sodium.to_base64(nonce),
    ephemeralPublicKey: sodium.to_base64(ephemeral.publicKey)
  }
}

/**
 * Decrypt a message using recipient's static private key + sender's ephemeral public key.
 */
export async function decryptPayload(
  ciphertext: string,
  nonce: string,
  ephemeralPublicKey: string,
  recipientEncryptionPrivateKey: string
): Promise<string> {
  await ensureSodium()

  const ciphertextBytes = sodium.from_base64(ciphertext)
  const nonceBytes = sodium.from_base64(nonce)
  const ephemeralPub = sodium.from_base64(ephemeralPublicKey)
  const recipientPriv = sodium.from_base64(recipientEncryptionPrivateKey)

  const paddedPlaintext = sodium.crypto_box_open_easy(
    ciphertextBytes,
    nonceBytes,
    ephemeralPub,
    recipientPriv
  )

  const unpadded = unpad(paddedPlaintext)
  return sodium.to_string(unpadded)
}

// ── High-Level: Create Encrypted Agora Message ──

/**
 * Create a fully encrypted Agora message with double signature.
 * Inner signature: Ed25519 over plaintext + recipient + nonce (prevents stripping)
 * Outer signature: Ed25519 over ciphertext envelope (public verifiability)
 */
export async function createEncryptedAgoraMessage(opts: {
  subject: string
  content: string
  senderAgentId: string
  senderIdentityPublicKey: string
  senderIdentityPrivateKey: string
  senderEncryptionPublicKey: string
  recipientAgentId: string
  recipientIdentityPublicKey: string
  recipientEncryptionPublicKey: string
  topic: string
  delegationId: string
  taintPrincipalIds?: string[]
  permitId?: string
  sequenceNumber: number
  metadata?: Record<string, unknown>
}): Promise<EncryptedAgoraMessage> {
  await ensureSodium()

  // Step 1: Hash taint principal IDs (cleartext but opaque)
  const taintHashes = (opts.taintPrincipalIds ?? []).map(
    id => createHash('sha256').update(id).digest('hex')
  )

  // Step 2: Create inner signature over plaintext + recipient + nonce
  // (This will be encrypted inside the payload)
  const tempNonce = randomBytes(24).toString('base64')
  const innerPayload = canonicalize({
    subject: opts.subject,
    content: opts.content,
    recipientAgentId: opts.recipientAgentId,
    nonce: tempNonce,
    ...(opts.metadata ? { metadata: opts.metadata } : {})
  })
  const innerSignature = sign(innerPayload, opts.senderIdentityPrivateKey)

  // Step 3: Build the plaintext bundle (content + inner signature)
  const decryptedPayload: DecryptedPayload = {
    subject: opts.subject,
    content: opts.content,
    recipientAgentId: opts.recipientAgentId,
    nonce: tempNonce,
    innerSignature,
    ...(opts.metadata ? { metadata: opts.metadata } : {})
  }

  // Step 4: Encrypt the entire plaintext bundle
  const plaintextStr = canonicalize(decryptedPayload)
  const encrypted = await encryptPayload(plaintextStr, opts.recipientEncryptionPublicKey)

  // Step 5: Build the cleartext envelope
  const message = {
    id: `emsg-${randomBytes(8).toString('hex')}`,
    timestamp: new Date().toISOString(),
    author: {
      agentId: opts.senderAgentId,
      publicKey: opts.senderIdentityPublicKey,
      encryptionPublicKey: opts.senderEncryptionPublicKey
    },
    recipient: {
      agentId: opts.recipientAgentId,
      publicKey: opts.recipientIdentityPublicKey
    },
    topic: opts.topic,
    type: 'encrypted' as const,
    delegationId: opts.delegationId,
    ephemeralPublicKey: encrypted.ephemeralPublicKey,
    nonce: encrypted.nonce,
    taintHashes,
    permitId: opts.permitId,
    sequenceNumber: opts.sequenceNumber,
    paddedSize: sodium.from_base64(encrypted.ciphertext).length,
    ciphertext: encrypted.ciphertext
  }

  // Step 6: Outer signature over the entire envelope (public verifiability)
  const outerPayload = canonicalize(message)
  const outerSignature = sign(outerPayload, opts.senderIdentityPrivateKey)

  return { message, outerSignature }
}

// ── High-Level: Decrypt + Verify Agora Message ──

/**
 * Decrypt an encrypted Agora message and verify both signatures.
 * 1. Verify outer signature (public verifiability — no decryption needed)
 * 2. Decrypt payload
 * 3. Verify inner signature (sender authored this for this recipient)
 * 4. Check recipient matches (prevents surreptitious forwarding)
 */
export async function decryptAgoraMessage(
  msg: EncryptedAgoraMessage,
  recipientEncryptionPrivateKey: string,
  recipientAgentId: string
): Promise<{ payload: DecryptedPayload; valid: boolean; errors: string[] }> {
  await ensureSodium()
  const errors: string[] = []

  // Step 1: Verify outer signature (Ed25519 over ciphertext envelope)
  const outerPayload = canonicalize(msg.message)
  const outerValid = verify(outerPayload, msg.outerSignature, msg.message.author.publicKey)
  if (!outerValid) errors.push('Outer signature invalid')

  // Step 2: Decrypt
  let payloadStr: string
  try {
    payloadStr = await decryptPayload(
      msg.message.ciphertext,
      msg.message.nonce,
      msg.message.ephemeralPublicKey,
      recipientEncryptionPrivateKey
    )
  } catch (e) {
    return {
      payload: { subject: '', content: '', recipientAgentId: '', nonce: '', innerSignature: '' },
      valid: false,
      errors: [...errors, `Decryption failed: ${(e as Error).message}`]
    }
  }

  // Step 3: Parse decrypted payload
  let payload: DecryptedPayload
  try {
    payload = JSON.parse(payloadStr)
  } catch {
    return {
      payload: { subject: '', content: '', recipientAgentId: '', nonce: '', innerSignature: '' },
      valid: false,
      errors: [...errors, 'Decrypted payload is not valid JSON']
    }
  }

  // Step 4: Verify inner signature (Ed25519 over plaintext + recipient + nonce)
  const innerPayload = canonicalize({
    subject: payload.subject,
    content: payload.content,
    recipientAgentId: payload.recipientAgentId,
    nonce: payload.nonce,
    ...(payload.metadata ? { metadata: payload.metadata } : {})
  })
  const innerValid = verify(innerPayload, payload.innerSignature, msg.message.author.publicKey)
  if (!innerValid) errors.push('Inner signature invalid')

  // Step 5: Check recipient (prevents surreptitious forwarding)
  if (payload.recipientAgentId !== recipientAgentId) {
    errors.push(`Message intended for ${payload.recipientAgentId}, not ${recipientAgentId}`)
  }

  return {
    payload,
    valid: errors.length === 0,
    errors
  }
}

// ── Outer Signature Verification (gateway use — no decryption needed) ──

/**
 * Verify only the outer signature on an encrypted message.
 * The gateway calls this to confirm sender identity without decrypting.
 */
export function verifyOuterSignature(msg: EncryptedAgoraMessage): boolean {
  const outerPayload = canonicalize(msg.message)
  return verify(outerPayload, msg.outerSignature, msg.message.author.publicKey)
}
