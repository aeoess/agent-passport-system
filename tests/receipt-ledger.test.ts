// Receipt Ledger Tests (Module 23)
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import { createHash } from 'node:crypto'
import {
  createReceiptLedger, addReceipt, commitBatch,
  proveInclusion, verifyInclusion,
  verifyBatch, verifyBatchChain,
} from '../src/core/receipt-ledger.js'

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex')
}

describe('Receipt Ledger — Basic Operations', () => {
  it('creates ledger, adds receipts, commits batch', () => {
    const kp = generateKeyPair()
    const ledger = createReceiptLedger()
    addReceipt(ledger, sha256('receipt-1'))
    addReceipt(ledger, sha256('receipt-2'))
    addReceipt(ledger, sha256('receipt-3'))
    assert.equal(ledger.pendingReceipts.length, 3)
    const batch = commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    assert.ok(batch.batchId.startsWith('batch_'))
    assert.equal(batch.receiptCount, 3)
    assert.equal(batch.epoch, 0)
    assert.equal(batch.previousBatchId, null)
    assert.ok(batch.merkleRoot)
    assert.ok(batch.signature)
    assert.equal(ledger.pendingReceipts.length, 0)
    assert.equal(ledger.batches.length, 1)
  })

  it('rejects empty batch commit', () => {
    const kp = generateKeyPair()
    const ledger = createReceiptLedger()
    assert.throws(() => {
      commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    }, /Cannot commit empty batch/)
  })
})

describe('Receipt Ledger — Inclusion Proofs', () => {
  it('proves and verifies inclusion of a specific receipt', () => {
    const kp = generateKeyPair()
    const ledger = createReceiptLedger()
    const h1 = sha256('receipt-1'), h2 = sha256('receipt-2'), h3 = sha256('receipt-3')
    addReceipt(ledger, h1); addReceipt(ledger, h2); addReceipt(ledger, h3)
    const batch = commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    const proof = proveInclusion(batch, h2)
    assert.equal(proof.verified, true)
    assert.equal(proof.receiptHash, h2)
    assert.equal(verifyInclusion(proof), true)
  })

  it('inclusion proof fails for receipt NOT in batch', () => {
    const kp = generateKeyPair()
    const ledger = createReceiptLedger()
    addReceipt(ledger, sha256('r1')); addReceipt(ledger, sha256('r2'))
    const batch = commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    const proof = proveInclusion(batch, sha256('not-here'))
    assert.equal(proof.verified, false)
    assert.equal(proof.leafIndex, -1)
    assert.equal(verifyInclusion(proof), false)
  })
})

describe('Receipt Ledger — Batch Verification', () => {
  it('verifies batch signature', () => {
    const kp = generateKeyPair()
    const ledger = createReceiptLedger()
    addReceipt(ledger, sha256('r1')); addReceipt(ledger, sha256('r2'))
    const batch = commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    const result = verifyBatch(batch, null)
    assert.equal(result.valid, true)
    assert.equal(result.signatureValid, true)
    assert.equal(result.rootValid, true)
    assert.equal(result.chainValid, true)
  })

  it('detects tampered batch signature', () => {
    const kp = generateKeyPair()
    const ledger = createReceiptLedger()
    addReceipt(ledger, sha256('r1'))
    const batch = commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    const tampered = { ...batch, signature: 'deadbeef'.repeat(16) }
    const result = verifyBatch(tampered, null)
    assert.equal(result.valid, false)
    assert.equal(result.signatureValid, false)
  })

  it('detects tampered Merkle root', () => {
    const kp = generateKeyPair()
    const ledger = createReceiptLedger()
    addReceipt(ledger, sha256('r1')); addReceipt(ledger, sha256('r2'))
    const batch = commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    const tampered = { ...batch, merkleRoot: sha256('fake-root') }
    const result = verifyBatch(tampered)
    assert.equal(result.rootValid, false)
  })
})

describe('Receipt Ledger — Batch Chain', () => {
  it('chains multiple batches with incrementing epochs', () => {
    const kp = generateKeyPair()
    const ledger = createReceiptLedger()
    addReceipt(ledger, sha256('b0-r1')); addReceipt(ledger, sha256('b0-r2'))
    const b0 = commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    addReceipt(ledger, sha256('b1-r1'))
    const b1 = commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    addReceipt(ledger, sha256('b2-r1')); addReceipt(ledger, sha256('b2-r2')); addReceipt(ledger, sha256('b2-r3'))
    const b2 = commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    assert.equal(b0.epoch, 0); assert.equal(b1.epoch, 1); assert.equal(b2.epoch, 2)
    assert.equal(b1.previousBatchId, b0.batchId)
    assert.equal(b2.previousBatchId, b1.batchId)
    assert.equal(ledger.batches.length, 3)
  })

  it('verifies full batch chain', () => {
    const kp = generateKeyPair()
    const ledger = createReceiptLedger()
    addReceipt(ledger, sha256('b0-r1'))
    commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    addReceipt(ledger, sha256('b1-r1')); addReceipt(ledger, sha256('b1-r2'))
    commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    addReceipt(ledger, sha256('b2-r1'))
    commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    const result = verifyBatchChain(ledger.batches)
    assert.equal(result.valid, true)
    assert.equal(result.batchCount, 3)
    assert.equal(result.totalReceipts, 4)
  })

  it('detects broken chain — wrong previousBatchId', () => {
    const kp = generateKeyPair()
    const ledger = createReceiptLedger()
    addReceipt(ledger, sha256('b0-r1'))
    commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    addReceipt(ledger, sha256('b1-r1'))
    commitBatch({ ledger, committerPrivateKey: kp.privateKey, committerPublicKey: kp.publicKey })
    const tampered = [...ledger.batches]
    tampered[1] = { ...tampered[1], previousBatchId: 'batch_fake12345' }
    const result = verifyBatchChain(tampered)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => e.includes('Previous batch ID mismatch')))
  })

  it('verifies empty batch chain as valid', () => {
    const result = verifyBatchChain([])
    assert.equal(result.valid, true)
    assert.equal(result.batchCount, 0)
  })
})
