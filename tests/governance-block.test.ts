// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  generateGovernanceBlock,
  verifyGovernanceBlock,
  renderGovernanceHTML,
  renderGovernanceMeta,
  parseGovernanceBlockFromHTML,
  embedGovernance,
  isUsagePermitted,
  DEFAULT_REVOCATION_POLICY,
  isGovernanceBlockExpired,
  createVerifiedGovernanceCredential,
  verifyGovernanceCredential,
} from '../src/index.js'
import type { GovernanceTerms } from '../src/index.js'

const keys = generateKeyPair()
const ARTICLE = 'AI agents are transforming the economy. This article explores how governance infrastructure ensures accountability when agents act on behalf of humans and organizations.'

const TERMS: GovernanceTerms = {
  inference: 'permitted',
  training: 'compensation_required',
  redistribution: 'prohibited',
  derivative: 'attribution_required',
  caching: 'permitted',
  version: '1.0',
}

describe('Governance Block — Generate + Verify', () => {
  it('generates a valid signed governance block', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    assert.equal(block['@context'], 'https://aeoess.com/governance/v1')
    assert.equal(block['@type'], 'GovernanceBlock')
    assert.ok(block.source_did.startsWith('did:aps:z'))
    assert.ok(block.content_hash.startsWith('sha256:'))
    assert.ok(block.signature)
    assert.equal(block.terms.training, 'compensation_required')
    assert.equal(block.revocation_policy.cached_copy, 'delete')
  })

  it('verifies a valid block against original content', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const result = verifyGovernanceBlock(block, ARTICLE, keys.publicKey)
    assert.equal(result.valid, true)
    assert.equal(result.signatureValid, true)
    assert.equal(result.contentHashValid, true)
    assert.equal(result.didConsistent, true)
    assert.equal(result.errors.length, 0)
  })

  it('detects tampered content', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const result = verifyGovernanceBlock(block, ARTICLE + ' INJECTED TEXT', keys.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.contentHashValid, false)
    assert.ok(result.errors[0].includes('Content hash mismatch'))
  })

  it('detects wrong public key', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const other = generateKeyPair()
    const result = verifyGovernanceBlock(block, ARTICLE, other.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.signatureValid, false)
    assert.equal(result.didConsistent, false)
  })

  it('detects tampered signature', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const tampered = { ...block, signature: block.signature.replace(/a/g, 'b') }
    const result = verifyGovernanceBlock(tampered, ARTICLE, keys.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.signatureValid, false)
  })

  it('uses custom revocation policy when provided', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
      revocationPolicy: { cached_copy: 'retain_with_notice', rag_chunk: 'no_obligation', embedding: 'no_obligation', fine_tune: 'no_obligation', synthetic: 'no_obligation' },
    })
    assert.equal(block.revocation_policy.cached_copy, 'retain_with_notice')
  })
})

describe('Governance Block — HTML Embedding', () => {
  it('renders as script tag', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const html = renderGovernanceHTML(block)
    assert.ok(html.startsWith('<script type="application/aps-governance+json">'))
    assert.ok(html.endsWith('</script>'))
    assert.ok(html.includes('"source_did"'))
    assert.ok(html.includes('"content_hash"'))
  })

  it('renders as meta tag', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const meta = renderGovernanceMeta(block)
    assert.ok(meta.startsWith('<meta name="aps-governance"'))
    assert.ok(meta.includes('content="'))
  })

  it('roundtrips through script tag: generate → render → parse → verify', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const html = renderGovernanceHTML(block)
    const parsed = parseGovernanceBlockFromHTML(`<html><head>${html}</head><body>${ARTICLE}</body></html>`)
    assert.ok(parsed)
    const result = verifyGovernanceBlock(parsed!, ARTICLE, keys.publicKey)
    assert.equal(result.valid, true)
  })

  it('roundtrips through meta tag: generate → render → parse → verify', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const meta = renderGovernanceMeta(block)
    const parsed = parseGovernanceBlockFromHTML(`<html><head>${meta}</head><body></body></html>`)
    assert.ok(parsed)
    const result = verifyGovernanceBlock(parsed!, ARTICLE, keys.publicKey)
    assert.equal(result.valid, true)
  })

  it('returns null for HTML without governance block', () => {
    const parsed = parseGovernanceBlockFromHTML('<html><body>No governance here</body></html>')
    assert.equal(parsed, null)
  })

  it('embedGovernance returns block + html + meta', () => {
    const result = embedGovernance({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    assert.ok(result.block.signature)
    assert.ok(result.html.includes('aps-governance+json'))
    assert.ok(result.meta.includes('aps-governance'))
  })
})

describe('Governance Block — Usage Checks', () => {
  const block = generateGovernanceBlock({
    content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
  })

  it('inference is permitted', () => {
    const r = isUsagePermitted(block, 'inference')
    assert.equal(r.permitted, true)
    assert.equal(r.condition, 'permitted')
  })


  it('training requires compensation', () => {
    const r = isUsagePermitted(block, 'training')
    assert.equal(r.permitted, false)
    assert.equal(r.condition, 'compensation_required')
  })

  it('redistribution is prohibited', () => {
    const r = isUsagePermitted(block, 'redistribution')
    assert.equal(r.permitted, false)
    assert.equal(r.condition, 'prohibited')
  })

  it('derivative requires attribution', () => {
    const r = isUsagePermitted(block, 'derivative')
    assert.equal(r.permitted, true)
    assert.equal(r.condition, 'attribution_required')
  })

  it('unspecified usage defaults to permitted', () => {
    const minBlock = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
    })
    const r = isUsagePermitted(minBlock, 'training')
    assert.equal(r.permitted, true)
    assert.equal(r.condition, 'not_specified')
  })
})

describe('Governance Block — Adversarial', () => {
  it('detects content injection after signing', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    // Attacker appends invisible content to page
    const result = verifyGovernanceBlock(block, ARTICLE + '\n<!-- injected ad -->', keys.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.contentHashValid, false)
  })

  it('detects terms tampering in transit', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const tampered = { ...block, terms: { ...block.terms, training: 'permitted' as const } }
    const result = verifyGovernanceBlock(tampered, ARTICLE, keys.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.signatureValid, false)
  })

  it('detects revocation policy tampering', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const tampered = { ...block, revocation_policy: { ...block.revocation_policy, cached_copy: 'no_obligation' as const } }
    const result = verifyGovernanceBlock(tampered, ARTICLE, keys.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.signatureValid, false)
  })

  it('detects DID spoofing (different publisher claims authorship)', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey, terms: TERMS,
    })
    const attacker = generateKeyPair()
    // Attacker tries to verify with their own key — DID won't match
    const result = verifyGovernanceBlock(block, ARTICLE, attacker.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.didConsistent, false)
  })

  it('same content with different terms produces different signatures', () => {
    const block1 = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { training: 'permitted' },
    })
    const block2 = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { training: 'prohibited' },
    })
    assert.notEqual(block1.signature, block2.signature)
    assert.equal(block1.content_hash, block2.content_hash)
  })
})


// ══════════════════════════════════════════════════════════════════
// AV-3: Governance Block Expiry (MoltyCel qntm#7)
// ══════════════════════════════════════════════════════════════════

describe('AV-3: Governance Block Expiry', () => {
  const keys = generateKeyPair()
  const ARTICLE = 'Test content for expiry checks'

  it('block without expires_at is not expired', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
    })
    assert.equal(isGovernanceBlockExpired(block), false)
  })

  it('block with future expires_at is not expired', () => {
    const future = new Date(Date.now() + 86400000).toISOString()
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
      expiresAt: future,
    })
    assert.equal(block.expires_at, future)
    assert.equal(isGovernanceBlockExpired(block), false)
  })

  it('block with past expires_at is expired', () => {
    const past = new Date(Date.now() - 86400000).toISOString()
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
      expiresAt: past,
    })
    assert.equal(isGovernanceBlockExpired(block), true)
  })

  it('expires_at is included in signature', () => {
    const block1 = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
    })
    const block2 = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    })
    // Different signatures because expires_at is in the signed payload
    assert.notEqual(block1.signature, block2.signature)
  })
})

// ══════════════════════════════════════════════════════════════════
// AV-1: Verified Governance Credential (MoltyCel qntm#7)
// ══════════════════════════════════════════════════════════════════

describe('AV-1: Verified Governance Credential', () => {
  const keys = generateKeyPair()
  const ARTICLE = 'Test content for credential verification'

  it('creates valid credential from governance block', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted', training: 'prohibited' },
    })
    const credential = createVerifiedGovernanceCredential({
      block, privateKey: keys.privateKey,
      publisherDid: block.source_did,
    })
    assert.deepEqual(credential.type, ['VerifiableCredential', 'GovernanceCredential'])
    assert.equal(credential.issuer, block.source_did)
    assert.ok(credential.credentialSubject.governanceBlockHash.startsWith('sha256:'))
    assert.equal(credential.proof.type, 'Ed25519Signature2020')
  })

  it('verifies credential against original block', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
    })
    const credential = createVerifiedGovernanceCredential({
      block, privateKey: keys.privateKey,
      publisherDid: block.source_did,
    })
    const result = verifyGovernanceCredential(credential, block, keys.publicKey)
    assert.equal(result.valid, true)
    assert.equal(result.errors.length, 0)
  })

  it('detects tampered block (AV-1 spoofing)', () => {
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
    })
    const credential = createVerifiedGovernanceCredential({
      block, privateKey: keys.privateKey,
      publisherDid: block.source_did,
    })
    // Tamper with the block after credential issuance
    const tampered = { ...block, terms: { ...block.terms, training: 'permitted' as any } }
    const result = verifyGovernanceCredential(credential, tampered, keys.publicKey)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => e.includes('hash mismatch')))
  })

  it('detects expired credential (AV-3 replay)', () => {
    const past = new Date(Date.now() - 86400000).toISOString()
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
      expiresAt: past,
    })
    const credential = createVerifiedGovernanceCredential({
      block, privateKey: keys.privateKey,
      publisherDid: block.source_did,
    })
    const result = verifyGovernanceCredential(credential, block, keys.publicKey)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => e.includes('expired')))
  })

  it('detects wrong signer (attacker creates credential for victim block)', () => {
    const attacker = generateKeyPair()
    const block = generateGovernanceBlock({
      content: ARTICLE, publicKey: keys.publicKey, privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
    })
    // Attacker tries to create a credential for the real block
    const credential = createVerifiedGovernanceCredential({
      block, privateKey: attacker.privateKey,
      publisherDid: block.source_did,
    })
    // Verify with the real publisher's key — signature won't match
    const result = verifyGovernanceCredential(credential, block, keys.publicKey)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => e.includes('signature')))
  })
})
