// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Attribution Consent — tests

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createAttributionReceipt,
  signAttributionConsent,
  verifyAttributionConsent,
  checkArtifactCitations,
  generateKeyPair,
  createHybridTimestamp,
} from '../../src/index.js'
import type {
  AttributionReceipt,
  CitingArtifact,
} from '../../src/index.js'
import type { HybridTimestamp } from '../../src/types/time.js'

function stampAt(wallMs: number, logicalTime = 1, gatewayId = 'test-gw'): HybridTimestamp {
  return {
    logicalTime,
    wallClockEarliest: wallMs - 50,
    wallClockLatest: wallMs + 50,
    gatewayId,
  }
}

function fixture(overrides: Partial<{
  citationContent: string
  bindingContext: string
  createdAt: HybridTimestamp
  expiresAt: HybridTimestamp
}> = {}) {
  const citer = generateKeyPair()
  const cited = generateKeyPair()
  const now = Date.now()
  const params = {
    citer: 'did:aps:citer-agent',
    citer_public_key: citer.publicKey,
    citer_private_key: citer.privateKey,
    cited_principal: 'did:aps:cited-principal',
    cited_principal_public_key: cited.publicKey,
    citation_content: overrides.citationContent ?? 'Douglas supports scoped-committer model',
    binding_context: overrides.bindingContext ?? 'charter:governance-v3',
    created_at: overrides.createdAt ?? stampAt(now),
    expires_at: overrides.expiresAt ?? stampAt(now + 60_000, 2),
  }
  const receipt = createAttributionReceipt(params)
  return { citer, cited, receipt, params }
}

describe('createAttributionReceipt', () => {
  it('produces a receipt with a stable sha256 id and citer_signature', () => {
    const { receipt } = fixture()
    assert.equal(receipt.version, '1.0')
    assert.match(receipt.id, /^[0-9a-f]{64}$/)
    assert.ok(receipt.citer_signature.length > 0)
    assert.equal(receipt.cited_principal_signature, undefined)
  })

  it('same inputs produce the same id (content-addressed)', () => {
    const now = stampAt(1_700_000_000_000)
    const later = stampAt(1_700_000_060_000, 2)
    const k1 = generateKeyPair()
    const k2 = generateKeyPair()
    const base = {
      citer: 'did:aps:a',
      citer_public_key: k1.publicKey,
      citer_private_key: k1.privateKey,
      cited_principal: 'did:aps:b',
      cited_principal_public_key: k2.publicKey,
      citation_content: 'same',
      binding_context: 'ctx',
      created_at: now,
      expires_at: later,
    }
    const r1 = createAttributionReceipt(base)
    const r2 = createAttributionReceipt(base)
    assert.equal(r1.id, r2.id)
  })

  it('rejects empty citation_content', () => {
    const k = generateKeyPair()
    assert.throws(() => createAttributionReceipt({
      citer: 'did:a', citer_public_key: k.publicKey, citer_private_key: k.privateKey,
      cited_principal: 'did:b', cited_principal_public_key: k.publicKey,
      citation_content: '', binding_context: 'ctx',
      created_at: stampAt(1), expires_at: stampAt(2, 2),
    }), /citation_content/)
  })
})

describe('verifyAttributionConsent — before cited signature', () => {
  it('fails with "no consent signature" on unsigned receipt', () => {
    const { receipt } = fixture()
    const result = verifyAttributionConsent(receipt)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'no consent signature')
  })
})

describe('signAttributionConsent', () => {
  it('adds cited_principal_signature; verify passes', () => {
    const { receipt, cited } = fixture()
    const signed = signAttributionConsent(receipt, cited.privateKey)
    assert.ok(signed.cited_principal_signature)
    const v = verifyAttributionConsent(signed)
    assert.equal(v.valid, true, v.reason)
  })

  it('throws when signed with wrong key', () => {
    const { receipt } = fixture()
    const other = generateKeyPair()
    assert.throws(() => signAttributionConsent(receipt, other.privateKey), /does not verify/)
  })

  it('does not mutate the original receipt', () => {
    const { receipt, cited } = fixture()
    signAttributionConsent(receipt, cited.privateKey)
    assert.equal(receipt.cited_principal_signature, undefined)
  })
})

describe('verifyAttributionConsent — tamper detection', () => {
  it('fails when citation_content is tampered post-sign', () => {
    const { receipt, cited } = fixture()
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const tampered: AttributionReceipt = { ...signed, citation_content: 'something broader' }
    const v = verifyAttributionConsent(tampered)
    assert.equal(v.valid, false)
    // id check fires before signature check
    assert.match(v.reason!, /tampered|invalid/)
  })

  it('fails when id is tampered but content kept', () => {
    const { receipt, cited } = fixture()
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const tampered: AttributionReceipt = { ...signed, id: 'f'.repeat(64) }
    const v = verifyAttributionConsent(tampered)
    assert.equal(v.valid, false)
    assert.match(v.reason!, /tampered/)
  })

  it('fails when citer_signature is swapped', () => {
    const { receipt, cited } = fixture()
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const bogus = signed.citer_signature.replace(/^./, (c) => c === '0' ? '1' : '0')
    const v = verifyAttributionConsent({ ...signed, citer_signature: bogus })
    assert.equal(v.valid, false)
  })
})

describe('verifyAttributionConsent — TTL window', () => {
  it('passes inside window', () => {
    const now = Date.now()
    const { receipt, cited } = fixture({
      createdAt: stampAt(now - 1000),
      expiresAt: stampAt(now + 60_000, 2),
    })
    const signed = signAttributionConsent(receipt, cited.privateKey)
    assert.equal(verifyAttributionConsent(signed).valid, true)
  })

  it('fails when evaluated past expiry', () => {
    const t0 = 1_700_000_000_000
    const { receipt, cited } = fixture({
      createdAt: stampAt(t0),
      expiresAt: stampAt(t0 + 1_000, 2),
    })
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const future = stampAt(t0 + 10 * 60_000, 3, 'attribution-verifier')
    const v = verifyAttributionConsent(signed, future)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'expired')
  })

  it('fails when evaluated before not-before', () => {
    const t0 = 1_700_000_000_000
    const { receipt, cited } = fixture({
      createdAt: stampAt(t0 + 10 * 60_000),
      expiresAt: stampAt(t0 + 20 * 60_000, 2),
    })
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const early = stampAt(t0, 3, 'attribution-verifier')
    const v = verifyAttributionConsent(signed, early)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'not yet valid')
  })

  it('fails when expires_at precedes created_at', () => {
    const t0 = 1_700_000_000_000
    const { receipt, cited } = fixture({
      createdAt: stampAt(t0 + 10_000, 2),
      expiresAt: stampAt(t0, 1),
    })
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const v = verifyAttributionConsent(signed, stampAt(t0 + 5_000, 3, 'attribution-verifier'))
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'expires_at precedes created_at')
  })
})

describe('checkArtifactCitations', () => {
  it('passes when there are no citations', () => {
    const artifact: CitingArtifact = { kind: 'charter' }
    const result = checkArtifactCitations(artifact, [])
    assert.equal(result.valid, true)
  })

  it('fails when a citation has no matching receipt', () => {
    const artifact: CitingArtifact = {
      citations: [{
        receipt_id: 'deadbeef',
        cited_principal: 'did:aps:x',
        citation_content: 'something',
      }],
    }
    const v = checkArtifactCitations(artifact, [])
    assert.equal(v.valid, false)
    assert.match(v.reason!, /no receipt/)
  })

  it('fails when receipt exists but citation_content differs', () => {
    const { receipt, cited } = fixture()
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const artifact: CitingArtifact = {
      citations: [{
        receipt_id: signed.id,
        cited_principal: signed.cited_principal,
        citation_content: 'a different claim',
      }],
    }
    const v = checkArtifactCitations(artifact, [signed])
    assert.equal(v.valid, false)
    assert.match(v.reason!, /content mismatch/)
  })

  it('fails when cited_principal differs between citation and receipt', () => {
    const { receipt, cited } = fixture()
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const artifact: CitingArtifact = {
      citations: [{
        receipt_id: signed.id,
        cited_principal: 'did:aps:other',
        citation_content: signed.citation_content,
      }],
    }
    const v = checkArtifactCitations(artifact, [signed])
    assert.equal(v.valid, false)
    assert.match(v.reason!, /principal mismatch/)
  })

  it('fails on replay: same receipt referenced twice in one artifact', () => {
    const { receipt, cited } = fixture()
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const artifact: CitingArtifact = {
      citations: [
        { receipt_id: signed.id, cited_principal: signed.cited_principal, citation_content: signed.citation_content },
        { receipt_id: signed.id, cited_principal: signed.cited_principal, citation_content: signed.citation_content },
      ],
    }
    const v = checkArtifactCitations(artifact, [signed])
    assert.equal(v.valid, false)
    assert.match(v.reason!, /replay/)
  })

  it('passes for a well-formed artifact with a valid receipt', () => {
    const { receipt, cited } = fixture()
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const artifact: CitingArtifact = {
      citations: [{
        receipt_id: signed.id,
        cited_principal: signed.cited_principal,
        citation_content: signed.citation_content,
      }],
    }
    const v = checkArtifactCitations(artifact, [signed])
    assert.equal(v.valid, true)
  })

  it('rejects when receipt binding_context does not match opts.binding_context', () => {
    const { receipt, cited } = fixture({ bindingContext: 'charter:governance-v3' })
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const artifact: CitingArtifact = {
      citations: [{
        receipt_id: signed.id,
        cited_principal: signed.cited_principal,
        citation_content: signed.citation_content,
      }],
    }
    const v = checkArtifactCitations(artifact, [signed], { binding_context: 'settlement:xyz' })
    assert.equal(v.valid, false)
    assert.match(v.reason!, /binding context/)
  })

  it('rejects when underlying receipt is unsigned (no consent)', () => {
    const { receipt } = fixture()
    const artifact: CitingArtifact = {
      citations: [{
        receipt_id: receipt.id,
        cited_principal: receipt.cited_principal,
        citation_content: receipt.citation_content,
      }],
    }
    const v = checkArtifactCitations(artifact, [receipt])
    assert.equal(v.valid, false)
    assert.match(v.reason!, /no consent signature/)
  })

  it('rejects expired receipts via the gate even when other fields match', () => {
    const t0 = 1_700_000_000_000
    const { receipt, cited } = fixture({
      createdAt: stampAt(t0),
      expiresAt: stampAt(t0 + 1_000, 2),
    })
    const signed = signAttributionConsent(receipt, cited.privateKey)
    const artifact: CitingArtifact = {
      citations: [{
        receipt_id: signed.id,
        cited_principal: signed.cited_principal,
        citation_content: signed.citation_content,
      }],
    }
    const future = stampAt(t0 + 10 * 60_000, 3, 'attribution-verifier')
    const v = checkArtifactCitations(artifact, [signed], { now: future })
    assert.equal(v.valid, false)
    assert.match(v.reason!, /expired/)
  })
})

describe('cross-signature integrity', () => {
  it('citer and cited signatures cover the same canonical core', () => {
    const { receipt, cited, citer } = fixture()
    const signed = signAttributionConsent(receipt, cited.privateKey)
    // Both signatures must verify against their respective public keys
    // against the identical core payload; verifyAttributionConsent() wires
    // that end-to-end. Cross-check here by running verify for each side.
    const v = verifyAttributionConsent(signed)
    assert.equal(v.valid, true)
    // If we swap the citer public key to the cited's, citer sig must fail.
    const swapped: AttributionReceipt = { ...signed, citer_public_key: cited.publicKey }
    const v2 = verifyAttributionConsent(swapped)
    assert.equal(v2.valid, false)
    // And swapping cited public key to citer's breaks the consent side.
    const swapped2: AttributionReceipt = { ...signed, cited_principal_public_key: citer.publicKey }
    const v3 = verifyAttributionConsent(swapped2)
    assert.equal(v3.valid, false)
  })
})

describe('smoke: hybrid timestamp integration', () => {
  it('accepts timestamps produced by createHybridTimestamp', () => {
    const citer = generateKeyPair()
    const cited = generateKeyPair()
    const created = createHybridTimestamp('gw-a')
    const expires: HybridTimestamp = {
      ...createHybridTimestamp('gw-a'),
      wallClockEarliest: created.wallClockEarliest + 60_000,
      wallClockLatest: created.wallClockLatest + 60_000,
    }
    const r = createAttributionReceipt({
      citer: 'did:a', citer_public_key: citer.publicKey, citer_private_key: citer.privateKey,
      cited_principal: 'did:b', cited_principal_public_key: cited.publicKey,
      citation_content: 'c', binding_context: 'ctx',
      created_at: created, expires_at: expires,
    })
    const signed = signAttributionConsent(r, cited.privateKey)
    assert.equal(verifyAttributionConsent(signed).valid, true)
  })
})
