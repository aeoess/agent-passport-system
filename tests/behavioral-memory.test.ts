// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createBehavioralMemoryObject, verifyBehavioralMemoryObject,
  isBMOExpired, exportBehavioralMemory, importBehavioralMemory,
  createBMOReceipt, verifyBMOReceipt,
} from '../src/index.js'

const issuer = generateKeyPair()
const principal = generateKeyPair()

function makeBMO(overrides?: Record<string, unknown>) {
  return createBehavioralMemoryObject({
    principal_id: principal.publicKey,
    issuer_id: issuer.publicKey,
    issuer_private_key: issuer.privateKey,
    pattern: {
      category: 'communication',
      description: 'Prefers concise responses under 100 words',
      confidence: 0.87,
      observation_count: 42,
      observation_window: { start: '2026-04-01T00:00:00Z', end: '2026-04-07T00:00:00Z' },
    },
    derivation_source: 'del_abc123',
    retention_ttl: 86400, // 1 day
    relational_entities: false,
    portable: true,
    ...overrides,
  })
}

describe('Behavioral Memory Objects', () => {
  it('creates a BMO with valid signature', () => {
    const bmo = makeBMO()
    assert.ok(bmo.id.startsWith('bmo_'))
    assert.equal(bmo.format_version, '1.0')
    assert.ok(verifyBehavioralMemoryObject(bmo, issuer.publicKey))
  })

  it('rejects tampered BMO', () => {
    const bmo = makeBMO()
    const tampered = { ...bmo, pattern: { ...bmo.pattern, confidence: 0.99 } }
    assert.ok(!verifyBehavioralMemoryObject(tampered, issuer.publicKey))
  })

  it('detects expired BMO', () => {
    const bmo = makeBMO({ retention_ttl: -1 }) // already expired
    assert.ok(isBMOExpired(bmo))
  })

  it('detects non-expired BMO', () => {
    const bmo = makeBMO({ retention_ttl: 86400 })
    assert.ok(!isBMOExpired(bmo))
  })

  it('exports and imports BMO bundle with signature verification', () => {
    const bmo1 = makeBMO()
    const bmo2 = makeBMO({ retention_ttl: 3600 })
    const bundle = exportBehavioralMemory([bmo1, bmo2], issuer.publicKey, issuer.privateKey)
    assert.ok(bundle.bundle_id.startsWith('bundle_'))
    assert.equal(bundle.bmos.length, 2)

    const imported = importBehavioralMemory(bundle, issuer.publicKey)
    assert.ok(imported.valid)
    assert.equal(imported.bmos.length, 2)
  })

  it('import rejects tampered bundle', () => {
    const bundle = exportBehavioralMemory([makeBMO()], issuer.publicKey, issuer.privateKey)
    const tampered = { ...bundle, exported_at: '2099-01-01T00:00:00Z' }
    const imported = importBehavioralMemory(tampered, issuer.publicKey)
    assert.ok(!imported.valid)
    assert.ok(imported.errors.some(e => e.includes('signature invalid')))
  })

  it('import filters expired BMOs', () => {
    const expired = makeBMO({ retention_ttl: -1 })
    const valid = makeBMO({ retention_ttl: 86400 })
    const bundle = exportBehavioralMemory([expired, valid], issuer.publicKey, issuer.privateKey)
    const imported = importBehavioralMemory(bundle, issuer.publicKey)
    assert.equal(imported.bmos.length, 1)
    assert.ok(imported.errors.some(e => e.includes('expired')))
  })

  it('relational_entities flag is preserved', () => {
    const bmo = makeBMO({ relational_entities: true })
    assert.equal(bmo.relational_entities, true)
  })

  it('portable flag is preserved', () => {
    const bmo = makeBMO({ portable: false })
    assert.equal(bmo.portable, false)
  })
})

describe('BMO Receipts', () => {
  const eventTypes = ['create', 'update', 'export', 'import', 'delete', 'expire'] as const

  for (const eventType of eventTypes) {
    it(`creates and verifies ${eventType} receipt`, () => {
      const bmo = makeBMO()
      const receipt = createBMOReceipt({
        bmo_id: bmo.id,
        event_type: eventType,
        actor_id: issuer.publicKey,
        private_key: issuer.privateKey,
      })
      assert.ok(receipt.receipt_id.startsWith('bmo_rcpt_'))
      assert.equal(receipt.event_type, eventType)
      assert.equal(receipt.bmo_id, bmo.id)
      assert.ok(verifyBMOReceipt(receipt, issuer.publicKey))
    })
  }

  it('rejects tampered receipt', () => {
    const receipt = createBMOReceipt({
      bmo_id: 'bmo_test', event_type: 'create',
      actor_id: issuer.publicKey, private_key: issuer.privateKey,
    })
    const tampered = { ...receipt, event_type: 'delete' as const }
    assert.ok(!verifyBMOReceipt(tampered, issuer.publicKey))
  })
})
