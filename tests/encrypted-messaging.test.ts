import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
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
    assert.ok(aliceEnc.publicKey)
    assert.ok(bobEnc.publicKey)
    assert.notEqual(aliceEnc.publicKey, bobEnc.publicKey)
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
      assert.equal(announcement.agentId, 'alice-agent')
      assert.equal(announcement.encryptionPublicKey, 'fake-enc-pubkey-for-test')
      assert.equal(verifyKeyAnnouncement(announcement), true)
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
      assert.equal(verifyKeyAnnouncement(tampered), false)
    })
  })

  // ── Padding ──

  describe('Padding', () => {
    it('should pad to power-of-2 block sizes', () => {
      const small = new Uint8Array(50)
      const padded = padToBlock(small)
      assert.equal(padded.length, 256)  // Nearest block
    })

    it('should roundtrip pad → unpad', () => {
      const original = new TextEncoder().encode('Hello, encrypted world!')
      const padded = padToBlock(original)
      assert.ok(padded.length > original.length)
      const unpadded = unpad(padded)
      assert.equal(new TextDecoder().decode(unpadded), 'Hello, encrypted world!')
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

      assert.equal(msg.message.type, 'encrypted')
      assert.ok(msg.message.ciphertext)
      assert.ok(msg.outerSignature)

      // Decrypt
      const result = await decryptAgoraMessage(msg, bobEnc.privateKey, 'bob-agent')

      assert.equal(result.valid, true)
      assert.equal(result.errors.length, 0)
      assert.equal(result.payload.subject, 'Secret meeting notes')
      assert.equal(result.payload.content, 'The quarterly numbers look great.')
      assert.equal(result.payload.recipientAgentId, 'bob-agent')
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
      assert.equal(verifyOuterSignature(msg), true)
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
      assert.equal(result.valid, false)
      assert.ok(result.errors.length > 0)
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
      assert.equal(bobResult.valid, true)

      // Inner payload says "for bob-agent". If Charlie somehow gets the decrypted payload,
      // the recipientAgentId check catches the mismatch.
      // Simulate: Charlie claims to be the recipient but inner says "bob-agent"
      const charlieResult = await decryptAgoraMessage(msg, bobEnc.privateKey, 'charlie-agent')
      assert.equal(charlieResult.valid, false)
      assert.equal(charlieResult.errors.some(e => e.includes('charlie-agent')), true)
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
      assert.equal(result.valid, false)
      assert.equal(result.errors.some(e => e.includes('Decryption failed') || e.includes('Outer signature invalid')), true)
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
      assert.equal(result.errors.some(e => e.includes('Inner signature invalid')), true)
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
      assert.equal(msg.message.taintHashes.length, 2)
      // They're hashed, not raw principal IDs
      assert.notEqual(msg.message.taintHashes[0], 'principal-alice')
      assert.equal(msg.message.taintHashes[0].length, 64) // sha256 hex
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
      assert.notEqual(msg1.message.ephemeralPublicKey, msg2.message.ephemeralPublicKey)
      // Different nonce per message
      assert.notEqual(msg1.message.nonce, msg2.message.nonce)

      // Both still decrypt correctly
      const r1 = await decryptAgoraMessage(msg1, bobEnc.privateKey, 'bob-agent')
      const r2 = await decryptAgoraMessage(msg2, bobEnc.privateKey, 'bob-agent')
      assert.equal(r1.valid, true)
      assert.equal(r2.valid, true)
      assert.equal(r1.payload.content, 'First')
      assert.equal(r2.payload.content, 'Second')
    })
  })

})
