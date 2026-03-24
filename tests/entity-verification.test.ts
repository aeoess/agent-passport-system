/**
 * Entity Verification v1.0 Tests
 * Adopted behaviors: fail-closed, cache-with-staleness, explicit did_resolution_status
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDID, isValidDID, clearStores,
  verifyEntityChain,
  cacheDIDResolution, getCachedDIDResolution, clearDIDCache,
  computeSenderId,
} from '../src/index.js'
import type { PublicProofSurface } from '../src/index.js'

const keys = generateKeyPair()

// Mock entity lookup (simulates Corpo API)
async function mockLookup(entityId: string): Promise<PublicProofSurface | null> {
  if (entityId === 'active-entity') {
    return {
      entity_id: 'active-entity', name: 'AEOESS DAO LLC',
      status: 'active', entity_type: 'wyoming_dao_llc',
      authority_ceiling: ['hold_assets', 'delegate_authority', 'sign_contracts'],
      verified_at: '2026-03-24T00:00:00Z',
    }
  }
  if (entityId === 'suspended-entity') {
    return {
      entity_id: 'suspended-entity', name: 'Bad Actor LLC',
      status: 'suspended', entity_type: 'delaware_llc',
      authority_ceiling: [], verified_at: '2026-03-24T00:00:00Z',
    }
  }
  return null
}

async function failingLookup(_: string): Promise<PublicProofSurface | null> {
  throw new Error('Network timeout')
}

describe('Entity Verification — Full Chain', () => {
  it('verifies active entity with live DID resolution', async () => {
    clearStores()
    clearDIDCache()
    const did = createDID(keys.publicKey)
    const result = await verifyEntityChain(did, mockLookup, { entityId: 'active-entity' })
    assert.equal(result.verified, true)
    assert.equal(result.didResolutionStatus, 'live')
    assert.equal(result.resolvedPublicKey, keys.publicKey)
    assert.equal(result.entity!.status, 'active')
    assert.equal(result.entity!.entity_type, 'wyoming_dao_llc')
    assert.ok(result.senderId)
    assert.equal(result.senderId!.length, 32)
    assert.equal(result.errors.length, 0)
  })

  it('fail-closed: invalid DID blocks verification', async () => {
    const result = await verifyEntityChain('not-a-did', mockLookup, { entityId: 'active-entity' })
    assert.equal(result.verified, false)
    assert.equal(result.didResolutionStatus, 'failed')
    assert.equal(result.resolvedPublicKey, null)
    assert.ok(result.errors.length > 0)
    assert.ok(result.errors.some(e => e.includes('fail-closed') || e.includes('Invalid DID')))
  })

  it('fail-closed: unknown entity blocks verification', async () => {
    clearStores()
    const did = createDID(keys.publicKey)
    const result = await verifyEntityChain(did, mockLookup, { entityId: 'nonexistent' })
    assert.equal(result.verified, false)
    assert.equal(result.didResolutionStatus, 'live')
    assert.equal(result.resolvedPublicKey, keys.publicKey)
    assert.equal(result.entity, null)
    assert.ok(result.errors.some(e => e.includes('not found')))
  })

  it('rejects suspended entity', async () => {
    clearStores()
    const did = createDID(keys.publicKey)
    const result = await verifyEntityChain(did, mockLookup, { entityId: 'suspended-entity' })
    assert.equal(result.verified, false)
    assert.equal(result.entity!.status, 'suspended')
    assert.ok(result.errors.some(e => e.includes('suspended')))
  })

  it('fail-closed: entity lookup failure blocks verification', async () => {
    clearStores()
    const did = createDID(keys.publicKey)
    const result = await verifyEntityChain(did, failingLookup, { entityId: 'active-entity' })
    assert.equal(result.verified, false)
    assert.ok(result.errors.some(e => e.includes('Network timeout') || e.includes('failed')))
  })
})

describe('Entity Verification — DID Resolution Cache', () => {
  it('caches a DID resolution', () => {
    clearDIDCache()
    const did = createDID(keys.publicKey)
    const entry = cacheDIDResolution(did, keys.publicKey, 3600000)
    assert.equal(entry.did, did)
    assert.equal(entry.publicKey, keys.publicKey)
    assert.equal(entry.status, 'live')
    assert.ok(entry.resolvedAt)
    assert.ok(entry.expiresAt)
  })

  it('retrieves cached resolution with status=cached', () => {
    clearDIDCache()
    const did = createDID(keys.publicKey)
    cacheDIDResolution(did, keys.publicKey, 3600000)
    const cached = getCachedDIDResolution(did)
    assert.ok(cached)
    assert.equal(cached!.publicKey, keys.publicKey)
    assert.equal(cached!.status, 'cached')
  })

  it('returns null for expired cache entry', () => {
    clearDIDCache()
    const did = createDID(keys.publicKey)
    cacheDIDResolution(did, keys.publicKey, 1) // 1ms TTL
    // Wait just a tiny bit
    const start = Date.now()
    while (Date.now() - start < 5) { /* busy wait */ }
    const cached = getCachedDIDResolution(did)
    assert.equal(cached, null)
  })

  it('returns null for uncached DID', () => {
    clearDIDCache()
    const cached = getCachedDIDResolution('did:aps:zNotCached')
    assert.equal(cached, null)
  })
})

describe('Entity Verification — Sender ID', () => {
  it('computes sender ID per QSP-1 §4: Trunc16(SHA-256(pubkey))', () => {
    const senderId = computeSenderId(keys.publicKey)
    assert.equal(senderId.length, 32) // 16 bytes = 32 hex chars
  })

  it('same key always produces same sender ID', () => {
    const id1 = computeSenderId(keys.publicKey)
    const id2 = computeSenderId(keys.publicKey)
    assert.equal(id1, id2)
  })

  it('different keys produce different sender IDs', () => {
    const other = generateKeyPair()
    const id1 = computeSenderId(keys.publicKey)
    const id2 = computeSenderId(other.publicKey)
    assert.notEqual(id1, id2)
  })

  it('sender ID from verifyEntityChain matches direct computation', async () => {
    clearStores()
    clearDIDCache()
    const did = createDID(keys.publicKey)
    const result = await verifyEntityChain(did, mockLookup, { entityId: 'active-entity' })
    const directId = computeSenderId(keys.publicKey)
    assert.equal(result.senderId, directId)
  })
})
