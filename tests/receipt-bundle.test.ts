// ══════════════════════════════════════════════════════════════════
// Receipt Bundle — Export/Import/Verify Tests
// ══════════════════════════════════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { createReceiptBundle, verifyReceiptBundle, importReceiptBundle, hashReceipt } from '../src/storage/receipt-bundle.js'
import { VolatileBackend } from '../src/storage/volatile-backend.js'
import { generateKeyPair } from '../src/crypto/keys.js'
import type { ActionReceipt } from '../src/types/passport.js'

function makeReceipt(id: string, agentId: string, tool: string, prevHash?: string): ActionReceipt {
  return {
    receiptId: id, version: '1.1', timestamp: new Date().toISOString(),
    agentId, delegationId: 'del_test',
    action: { type: `gateway:${tool}`, target: '{}', scopeUsed: tool },
    result: { status: 'success', summary: 'ok' },
    delegationChain: ['pk_principal'], signature: 'sig_' + id,
    previousReceiptHash: prevHash
  } as ActionReceipt
}

// Build a chain of receipts with proper hash links
function makeChain(count: number): ActionReceipt[] {
  const chain: ActionReceipt[] = []
  for (let i = 0; i < count; i++) {
    const prev = i > 0 ? hashReceipt(chain[i - 1]) : undefined
    chain.push(makeReceipt(`rcpt-${i}`, 'agent-1', 'data:read', prev))
  }
  return chain
}

describe('Receipt Bundle', () => {
  const gwKeys = generateKeyPair()

  it('creates a signed bundle from receipts', () => {
    const receipts = makeChain(5)
    const bundle = createReceiptBundle({
      gatewayId: 'gw-test', gatewayPrivateKey: gwKeys.privateKey,
      receipts, filter: { agentId: 'agent-1' }
    })
    assert.equal(bundle.version, '1.0')
    assert.equal(bundle.gatewayId, 'gw-test')
    assert.equal(bundle.count, 5)
    assert.equal(bundle.receipts.length, 5)
    assert.ok(bundle.signature)
    assert.ok(bundle.chainStartHash)
    assert.ok(bundle.chainEndHash)
    assert.ok(bundle.chainValid)
    assert.ok(bundle.exportedAt)
  })

  it('verifies a valid bundle', () => {
    const receipts = makeChain(10)
    const bundle = createReceiptBundle({
      gatewayId: 'gw-verify', gatewayPrivateKey: gwKeys.privateKey,
      receipts, filter: {}
    })
    const result = verifyReceiptBundle(bundle, gwKeys.publicKey)
    assert.ok(result.valid, 'Bundle is valid')
    assert.ok(result.bundleSignatureValid, 'Signature valid')
    assert.ok(result.chainIntegrityValid, 'Chain valid')
    assert.equal(result.receiptCount, 10)
    assert.equal(result.tombstonedCount, 0)
    assert.equal(result.errors.length, 0)
  })

  it('rejects bundle signed with wrong key', () => {
    const receipts = makeChain(3)
    const bundle = createReceiptBundle({
      gatewayId: 'gw-wrong', gatewayPrivateKey: gwKeys.privateKey,
      receipts, filter: {}
    })
    const otherKeys = generateKeyPair()
    const result = verifyReceiptBundle(bundle, otherKeys.publicKey)
    assert.equal(result.bundleSignatureValid, false, 'Wrong key rejected')
    assert.equal(result.valid, false)
  })

  it('detects tampered receipt count', () => {
    const receipts = makeChain(5)
    const bundle = createReceiptBundle({
      gatewayId: 'gw-tamper', gatewayPrivateKey: gwKeys.privateKey,
      receipts, filter: {}
    })
    // Tamper: remove a receipt
    bundle.receipts = bundle.receipts.slice(0, 3)
    const result = verifyReceiptBundle(bundle, gwKeys.publicKey)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => e.includes('count mismatch')))
  })

  it('counts tombstoned receipts in verification', () => {
    const receipts = makeChain(5)
    receipts[2].tombstoned = true
    receipts[2].tombstoneReason = 'gdpr'
    receipts[4].tombstoned = true
    receipts[4].tombstoneReason = 'gdpr'
    const bundle = createReceiptBundle({
      gatewayId: 'gw-tomb', gatewayPrivateKey: gwKeys.privateKey,
      receipts, filter: {}
    })
    const result = verifyReceiptBundle(bundle, gwKeys.publicKey)
    assert.equal(result.tombstonedCount, 2)
  })

  it('imports a verified bundle into storage', async () => {
    const receipts = makeChain(8)
    const bundle = createReceiptBundle({
      gatewayId: 'gw-import', gatewayPrivateKey: gwKeys.privateKey,
      receipts, filter: { agentId: 'agent-1' }
    })

    const storage = new VolatileBackend()
    await storage.initialize()

    const result = await importReceiptBundle(bundle, gwKeys.publicKey, storage)
    assert.equal(result.imported, 8, '8 receipts imported')
    assert.equal(result.skipped, 0, '0 skipped')
    assert.equal(result.errors.length, 0, 'No errors')

    // Verify receipts are in storage
    const count = await storage.getReceiptCount('agent-1')
    assert.equal(count, 8)

    // Verify individual receipt retrievable
    const r = await storage.getReceipt('rcpt-0')
    assert.ok(r)
    assert.equal(r.agentId, 'agent-1')
  })

  it('rejects import of invalid bundle', async () => {
    const receipts = makeChain(3)
    const bundle = createReceiptBundle({
      gatewayId: 'gw-reject', gatewayPrivateKey: gwKeys.privateKey,
      receipts, filter: {}
    })

    const storage = new VolatileBackend()
    await storage.initialize()

    // Try importing with wrong key
    const otherKeys = generateKeyPair()
    const result = await importReceiptBundle(bundle, otherKeys.publicKey, storage)
    assert.equal(result.imported, 0, 'Nothing imported')
    assert.ok(result.errors.length > 0, 'Errors reported')

    // Storage should be empty
    assert.equal(await storage.getReceiptCount(), 0)
  })

  it('handles empty bundle', () => {
    const bundle = createReceiptBundle({
      gatewayId: 'gw-empty', gatewayPrivateKey: gwKeys.privateKey,
      receipts: [], filter: {}
    })
    assert.equal(bundle.count, 0)
    assert.equal(bundle.receipts.length, 0)
    assert.ok(bundle.chainValid)

    const result = verifyReceiptBundle(bundle, gwKeys.publicKey)
    assert.ok(result.valid)
    assert.equal(result.receiptCount, 0)
  })

  it('hashReceipt is deterministic', () => {
    const r = makeReceipt('det-test', 'a1', 'data:read')
    const h1 = hashReceipt(r)
    const h2 = hashReceipt(r)
    assert.equal(h1, h2, 'Same receipt produces same hash')
    const r2 = makeReceipt('det-test-2', 'a1', 'data:read')
    const h3 = hashReceipt(r2)
    assert.notEqual(h1, h3, 'Different receipts produce different hashes')
  })

  it('full round-trip: export → serialize → deserialize → verify → import', async () => {
    const receipts = makeChain(5)
    const bundle = createReceiptBundle({
      gatewayId: 'gw-roundtrip', gatewayPrivateKey: gwKeys.privateKey,
      receipts, filter: { agentId: 'agent-1' }
    })

    // Serialize to JSON (as if writing to disk or sending over network)
    const json = JSON.stringify(bundle)
    assert.ok(json.length > 0)

    // Deserialize
    const restored: typeof bundle = JSON.parse(json)

    // Verify the deserialized bundle
    const verification = verifyReceiptBundle(restored, gwKeys.publicKey)
    assert.ok(verification.valid, 'Deserialized bundle still valid')

    // Import into fresh storage
    const storage = new VolatileBackend()
    await storage.initialize()
    const importResult = await importReceiptBundle(restored, gwKeys.publicKey, storage)
    assert.equal(importResult.imported, 5)
  })
})
