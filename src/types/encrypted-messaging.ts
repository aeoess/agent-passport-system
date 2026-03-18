// ══════════════════════════════════════════════════════════════════
// E2E Encrypted Messaging — Types
// ══════════════════════════════════════════════════════════════════
// Consensus spec from GPT + Gemini + Claude hostile review.
//
// Design: Separate X25519 encryption keys (not converted from Ed25519).
// Ephemeral-static ECDH per message (sender forward secrecy).
// Double signature: inner (plaintext) + outer (ciphertext).
// Taint hashes in cleartext AAD for Module 18 enforcement.
// Padding to power-of-2 blocks.
// libsodium-wrappers (JS), PyNaCl (Python).
// ══════════════════════════════════════════════════════════════════

// ── Key Announcement ──
// Agent generates X25519 keypair, signs the public key with Ed25519,
// and publishes it on the Agora. This binds encryption key to identity
// without cross-contaminating secret key material.

export interface EncryptionKeyAnnouncement {
  agentId: string
  /** X25519 public key for encryption (base64) */
  encryptionPublicKey: string
  /** Ed25519 public key for identity (base64) */
  identityPublicKey: string
  /** Ed25519 signature over canonical(agentId + encryptionPublicKey) */
  signature: string
  createdAt: string
}

// ── Encrypted Agora Message ──

export interface EncryptedAgoraMessage {
  message: {
    id: string
    timestamp: string
    author: {
      agentId: string
      publicKey: string              // Ed25519 identity key
      encryptionPublicKey: string    // X25519 static key
    }
    recipient: {
      agentId: string
      publicKey: string              // Ed25519
    }
    topic: string
    type: 'encrypted'
    /** Delegation authorizing this communication */
    delegationId: string
    /** Sender's one-time X25519 public key (ephemeral-static ECDH) */
    ephemeralPublicKey: string
    /** 24-byte random nonce (base64) */
    nonce: string
    /** sha256 hashes of taint principal IDs (cleartext for Module 18 enforcement) */
    taintHashes: string[]
    /** Cross-chain permit ID if cross-context flow */
    permitId?: string
    /** Monotonic within a conversation */
    sequenceNumber: number
    /** Padded ciphertext size in bytes */
    paddedSize: number
    /** Encrypted payload (base64) — contains plaintext + inner signature */
    ciphertext: string
  }
  /** Ed25519 signature over canonical(message) — outer signature for public verifiability */
  outerSignature: string
}

// ── Decrypted Payload ──
// What the recipient sees after decrypting.

export interface DecryptedPayload {
  subject: string
  content: string
  /** Explicit recipient ID (prevents surreptitious forwarding) */
  recipientAgentId: string
  /** Nonce from the envelope (bound into inner signature) */
  nonce: string
  /** Inner Ed25519 signature over canonical(subject + content + recipientAgentId + nonce) */
  innerSignature: string
  metadata?: Record<string, unknown>
}

// ── Encryption Keypair ──

export interface EncryptionKeypair {
  /** X25519 public key (base64) */
  publicKey: string
  /** X25519 private key (base64) */
  privateKey: string
}

// ── Message Validation Result ──

export interface MessageValidation {
  /** Outer signature valid (Ed25519 over ciphertext envelope) */
  outerSignatureValid: boolean
  /** Inner signature valid (Ed25519 over plaintext + recipient + nonce) */
  innerSignatureValid: boolean
  /** Delegation still active at receive time */
  delegationValid: boolean
  /** Recipient matches the intended recipient */
  recipientMatch: boolean
  /** Message not expired */
  notExpired: boolean
  /** Overall: all checks pass */
  valid: boolean
  error?: string
}
