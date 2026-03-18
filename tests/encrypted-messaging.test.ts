import { describe, it, expect } from 'vitest'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  generateEncryptionKeypair,
  createKeyAnnouncement, verifyKeyAnnouncement,
  padToBlock, unpad,
  createEncryptedAgoraMessage, decryptAgoraMessage,
  verifyOuterSignature
} from '../src/index.js'

// Two agents: Alice (sender) and Bob (recipient)
const aliceIdentity = generateKeyPair()
const bobIdentity = generateKeyPair()
const eveIdentity = generateKeyPair()

let aliceEnc: { publicKey: string; privateKey: string }
let bobEnc: { publicKey: string; privateKey: string }

describe('E2E Encrypted Messaging', () => {

  // Generate encryption keypairs before tests (async)
  it('should generate encryption keypairs', async () => {
    aliceEnc = await generateEncryptionKeypair()
    bobEnc = await generateEncryptionKeypair()
    expect(aliceEnc.publicKey).toBeTruthy()
    expect(bobEnc.publicKey).toBeTruthy()
    expect(aliceEnc.publicKey).not.toBe(bobEnc.publicKey)
  })

  // ── Key Announcement ──

  describe('Key Announcements', () => {
    it('should create and verify a key announcement', () => {
      const announcement = createKeyAnnouncement(
        'alice-agent',
        'fake-enc-pubkey-for-test',
        aliceIdentity.publicKey,
        aliceIdentity.privateKey
      )
      expect(announcement.agentId).toBe('alice-agent')
      expect(announcement.encryptionPublicKey).toBe('fake-enc-pubkey-for-test')
      expect(verifyKeyAnnouncement(announcement)).toBe(true)
    })

    it('should reject announcement signed by wrong key', () => {
      const announcement = createKeyAnnouncement(
        'alice-agent',
        'fake-enc-pubkey',
        aliceIdentity.publicKey,
        aliceIdentity.privateKey
      )
      // Tamper: claim it's bob's identity
      const tampered = { ...announcement, identityPublicKey: bobIdentity.publicKey }
      expect(verifyKeyAnnouncement(tampered)).toBe(false)
    })
  })

  // ── Padding ──

  describe('Padding', () => {
    it('should pad to power-of-2 block sizes', () => {
      const small = new Uint8Array(50)
      const padded = padToBlock(small)
      expect(padded.length).toBe(256)  // Nearest block
    })

    it('should roundtrip pad → unpad', () => {
      const original = new TextEncoder().encode('Hello, encrypted world!')
      const padded = padToBlock(original)
      expect(padded.length).toBeGreaterThan(original.length)
      const unpadded = unpad(padded)
      expect(new TextDecoder().decode(unpadded)).toBe('Hello, encrypted world!')
    })
  })

  // ── Encrypt → Decrypt Roundtrip ──

  describe('Encrypt/Decrypt', () => {
    it('should encrypt and decrypt a full Agora message', async () => {
      const msg = await createEncryptedAgoraMessage({
        subject: 'Secret meeting notes',
        content: 'The quarterly numbers look great.',
        senderAgentId: 'alice-agent',
        senderIdentityPublicKey: aliceIdentity.publicKey,
        senderIdentityPrivateKey: aliceIdentity.privateKey,
        senderEncryptionPublicKey: aliceEnc.publicKey,
        recipientAgentId: 'bob-agent',
        recipientIdentityPublicKey: bobIdentity.publicKey,
        recipientEncryptionPublicKey: bobEnc.publicKey,
        topic: 'finance',
        delegationId: 'del-001',
        taintPrincipalIds: ['principal-alice'],
        sequenceNumber: 1
      })

      expect(msg.message.type).toBe('encrypted')
      expect(msg.message.ciphertext).toBeTruthy()
      expect(msg.outerSignature).toBeTruthy()

      // Decrypt
      const result = await decryptAgoraMessage(msg, bobEnc.privateKey, 'bob-agent')

      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
      expect(result.payload.subject).toBe('Secret meeting notes')
      expect(result.payload.content).toBe('The quarterly numbers look great.')
      expect(result.payload.recipientAgentId).toBe('bob-agent')
    })

    it('should verify outer signature without decrypting', async () => {
      const msg = await createEncryptedAgoraMessage({
        subject: 'Test',
        content: 'Test content',
        senderAgentId: 'alice-agent',
        senderIdentityPublicKey: aliceIdentity.publicKey,
        senderIdentityPrivateKey: aliceIdentity.privateKey,
        senderEncryptionPublicKey: aliceEnc.publicKey,
        recipientAgentId: 'bob-agent',
        recipientIdentityPublicKey: bobIdentity.publicKey,
        recipientEncryptionPublicKey: bobEnc.publicKey,
        topic: 'general',
        delegationId: 'del-001',
        sequenceNumber: 1
      })

      // Gateway verifies sender without decrypting
      expect(verifyOuterSignature(msg)).toBe(true)
    })

    // ══════════════════════════════════════
    // ATTACK SCENARIOS
    // ══════════════════════════════════════

    it('ATTACK: wrong recipient key → decryption fails', async () => {
      const msg = await createEncryptedAgoraMessage({
        subject: 'Secret',
        content: 'Confidential data',
        senderAgentId: 'alice-agent',
        senderIdentityPublicKey: aliceIdentity.publicKey,
        senderIdentityPrivateKey: aliceIdentity.privateKey,
        senderEncryptionPublicKey: aliceEnc.publicKey,
        recipientAgentId: 'bob-agent',
        recipientIdentityPublicKey: bobIdentity.publicKey,
        recipientEncryptionPublicKey: bobEnc.publicKey,
        topic: 'secret',
        delegationId: 'del-001',
        sequenceNumber: 1
      })

      // Eve tries to decrypt with her key
      const eveEnc = await generateEncryptionKeypair()
      const result = await decryptAgoraMessage(msg, eveEnc.privateKey, 'eve-agent')
      expect(result.valid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
    })

    it('ATTACK: surreptitious forwarding → recipient mismatch detected', async () => {
      // Alice sends to Bob
      const msg = await createEncryptedAgoraMessage({
        subject: 'For Bob only',
        content: 'Private info for Bob',
        senderAgentId: 'alice-agent',
        senderIdentityPublicKey: aliceIdentity.publicKey,
        senderIdentityPrivateKey: aliceIdentity.privateKey,
        senderEncryptionPublicKey: aliceEnc.publicKey,
        recipientAgentId: 'bob-agent',
        recipientIdentityPublicKey: bobIdentity.publicKey,
        recipientEncryptionPublicKey: bobEnc.publicKey,
        topic: 'private',
        delegationId: 'del-001',
        sequenceNumber: 1
      })

      // Bob decrypts successfully
      const bobResult = await decryptAgoraMessage(msg, bobEnc.privateKey, 'bob-agent')
      expect(bobResult.valid).toBe(true)

      // Inner payload says "for bob-agent". If Charlie somehow gets the decrypted payload,
      // the recipientAgentId check catches the mismatch.
      // Simulate: Charlie claims to be the recipient but inner says "bob-agent"
      const charlieResult = await decryptAgoraMessage(msg, bobEnc.privateKey, 'charlie-agent')
      expect(charlieResult.valid).toBe(false)
      expect(charlieResult.errors.some(e => e.includes('charlie-agent'))).toBe(true)
    })

    it('ATTACK: tampered ciphertext → decryption fails (AEAD)', async () => {
      const msg = await createEncryptedAgoraMessage({
        subject: 'Integrity test',
        content: 'Original content',
        senderAgentId: 'alice-agent',
        senderIdentityPublicKey: aliceIdentity.publicKey,
        senderIdentityPrivateKey: aliceIdentity.privateKey,
        senderEncryptionPublicKey: aliceEnc.publicKey,
        recipientAgentId: 'bob-agent',
        recipientIdentityPublicKey: bobIdentity.publicKey,
        recipientEncryptionPublicKey: bobEnc.publicKey,
        topic: 'integrity',
        delegationId: 'del-001',
        sequenceNumber: 1
      })

      // Tamper with ciphertext
      const tampered = {
        ...msg,
        message: { ...msg.message, ciphertext: msg.message.ciphertext.slice(0, -4) + 'AAAA' }
      }
      const result = await decryptAgoraMessage(tampered, bobEnc.privateKey, 'bob-agent')
      expect(result.valid).toBe(false)
      expect(result.errors.some(e => e.includes('Decryption failed') || e.includes('Outer signature invalid'))).toBe(true)
    })

    it('ATTACK: outer signature stripped and re-signed by Eve → inner sig catches it', async () => {
      const msg = await createEncryptedAgoraMessage({
        subject: 'Identity test',
        content: 'Alice wrote this',
        senderAgentId: 'alice-agent',
        senderIdentityPublicKey: aliceIdentity.publicKey,
        senderIdentityPrivateKey: aliceIdentity.privateKey,
        senderEncryptionPublicKey: aliceEnc.publicKey,
        recipientAgentId: 'bob-agent',
        recipientIdentityPublicKey: bobIdentity.publicKey,
        recipientEncryptionPublicKey: bobEnc.publicKey,
        topic: 'auth',
        delegationId: 'del-001',
        sequenceNumber: 1
      })

      // Eve strips Alice's outer signature and claims authorship
      // She re-signs the ciphertext with her own key
      const { canonicalize: canon } = await import('../src/core/canonical.js')
      const { sign: signFn } = await import('../src/crypto/keys.js')

      const eveMsg = {
        ...msg,
        message: {
          ...msg.message,
          author: {
            ...msg.message.author,
            agentId: 'eve-agent',
            publicKey: eveIdentity.publicKey
          }
        },
        outerSignature: signFn(canon(msg.message), eveIdentity.privateKey)
      }

      // Bob decrypts — the ciphertext is still valid (same ephemeral key)
      // But the inner signature was signed by Alice, not Eve
      // When Bob verifies inner sig against Eve's publicKey, it fails
      const result = await decryptAgoraMessage(eveMsg, bobEnc.privateKey, 'bob-agent')
      // Inner signature check uses msg.message.author.publicKey (Eve's)
      // but the actual inner sig was made by Alice → mismatch
      expect(result.errors.some(e => e.includes('Inner signature invalid'))).toBe(true)
    })

    it('should include taint hashes in cleartext envelope', async () => {
      const msg = await createEncryptedAgoraMessage({
        subject: 'Tainted data',
        content: 'Cross-chain info',
        senderAgentId: 'alice-agent',
        senderIdentityPublicKey: aliceIdentity.publicKey,
        senderIdentityPrivateKey: aliceIdentity.privateKey,
        senderEncryptionPublicKey: aliceEnc.publicKey,
        recipientAgentId: 'bob-agent',
        recipientIdentityPublicKey: bobIdentity.publicKey,
        recipientEncryptionPublicKey: bobEnc.publicKey,
        topic: 'cross-chain',
        delegationId: 'del-001',
        taintPrincipalIds: ['principal-alice', 'principal-bob'],
        sequenceNumber: 1
      })

      // Taint hashes are in cleartext (gateway can enforce Module 18)
      expect(msg.message.taintHashes).toHaveLength(2)
      // They're hashed, not raw principal IDs
      expect(msg.message.taintHashes[0]).not.toBe('principal-alice')
      expect(msg.message.taintHashes[0]).toHaveLength(64) // sha256 hex
    })

    it('should use different ephemeral key per message (forward secrecy)', async () => {
      const msg1 = await createEncryptedAgoraMessage({
        subject: 'Message 1',
        content: 'First',
        senderAgentId: 'alice-agent',
        senderIdentityPublicKey: aliceIdentity.publicKey,
        senderIdentityPrivateKey: aliceIdentity.privateKey,
        senderEncryptionPublicKey: aliceEnc.publicKey,
        recipientAgentId: 'bob-agent',
        recipientIdentityPublicKey: bobIdentity.publicKey,
        recipientEncryptionPublicKey: bobEnc.publicKey,
        topic: 'fs-test',
        delegationId: 'del-001',
        sequenceNumber: 1
      })

      const msg2 = await createEncryptedAgoraMessage({
        subject: 'Message 2',
        content: 'Second',
        senderAgentId: 'alice-agent',
        senderIdentityPublicKey: aliceIdentity.publicKey,
        senderIdentityPrivateKey: aliceIdentity.privateKey,
        senderEncryptionPublicKey: aliceEnc.publicKey,
        recipientAgentId: 'bob-agent',
        recipientIdentityPublicKey: bobIdentity.publicKey,
        recipientEncryptionPublicKey: bobEnc.publicKey,
        topic: 'fs-test',
        delegationId: 'del-001',
        sequenceNumber: 2
      })

      // Different ephemeral key per message
      expect(msg1.message.ephemeralPublicKey).not.toBe(msg2.message.ephemeralPublicKey)
      // Different nonce per message
      expect(msg1.message.nonce).not.toBe(msg2.message.nonce)

      // Both still decrypt correctly
      const r1 = await decryptAgoraMessage(msg1, bobEnc.privateKey, 'bob-agent')
      const r2 = await decryptAgoraMessage(msg2, bobEnc.privateKey, 'bob-agent')
      expect(r1.valid).toBe(true)
      expect(r2.valid).toBe(true)
      expect(r1.payload.content).toBe('First')
      expect(r2.payload.content).toBe('Second')
    })
  })

})
