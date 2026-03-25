// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, embedGovernance, generateGovernanceBlock,
  governanceHeaders, generateApsTxt,
  checkHTMLGovernance, checkHeaderGovernance,
  createAccessReceipt, verifyAccessReceipt,
  governanceLoop360,
} from '../src/index.js'
import type { GovernanceTerms } from '../src/index.js'

const publisher = generateKeyPair()
const agent = generateKeyPair()
const ARTICLE = 'Breaking: AI agents now require governance infrastructure for autonomous economic activity.'
const TERMS: GovernanceTerms = {
  inference: 'permitted',
  training: 'compensation_required',
  redistribution: 'prohibited',
  caching: 'permitted',
}

describe('Governance 360 — Full Loop', () => {
  // Publisher embeds governance in HTML
  const { block, html } = embedGovernance({
    content: ARTICLE, publicKey: publisher.publicKey, privateKey: publisher.privateKey, terms: TERMS,
  })
  const fullPage = `<html><head>${html}</head><body><article>${ARTICLE}</article></body></html>`

  it('360: publisher embeds → agent extracts → verifies → checks terms → creates receipt', () => {
    const result = governanceLoop360({
      html: fullPage,
      contentBody: ARTICLE,
      publisherPublicKey: publisher.publicKey,
      agentPublicKey: agent.publicKey,
      agentPrivateKey: agent.privateKey,
      intendedUsage: 'inference',
      sourceUrl: 'https://theagenttimes.com/article/ai-governance',
    })

    // Governance found and verified
    assert.equal(result.governance.found, true)
    assert.equal(result.governance.verified, true)
    assert.equal(result.governance.source, 'html_script')

    // Usage permitted (inference = permitted)
    assert.equal(result.permitted, true)

    // Receipt created
    assert.ok(result.receipt)
    assert.ok(result.receipt!.receiptId.startsWith('gar_'))
    assert.equal(result.receipt!.publisher_did, block.source_did)
    assert.equal(result.receipt!.content_hash, block.content_hash)
    assert.equal(result.receipt!.intended_usage, 'inference')
    assert.equal(result.receipt!.governance_verified, true)
    assert.equal(result.receipt!.source_url, 'https://theagenttimes.com/article/ai-governance')

    // Receipt is verifiable
    assert.equal(verifyAccessReceipt(result.receipt!, agent.publicKey), true)

    // Summary is readable
    assert.ok(result.summary.includes('VERIFIED'))
    assert.ok(result.summary.includes('PERMITTED'))
  })

  it('360: training usage is restricted with compensation_required', () => {
    const result = governanceLoop360({
      html: fullPage, contentBody: ARTICLE,
      publisherPublicKey: publisher.publicKey,
      agentPublicKey: agent.publicKey, agentPrivateKey: agent.privateKey,
      intendedUsage: 'training',
      sourceUrl: 'https://theagenttimes.com/article/ai-governance',
    })
    assert.equal(result.permitted, false)
    assert.equal(result.governance.usageCheck?.condition, 'compensation_required')
    // Receipt still created — evidence of access even when restricted
    assert.ok(result.receipt)
    assert.ok(result.summary.includes('RESTRICTED'))
  })

  it('360: ungoverned content returns permitted with no receipt', () => {
    const plainPage = '<html><body>No governance here.</body></html>'
    const result = governanceLoop360({
      html: plainPage, contentBody: 'No governance here.',
      publisherPublicKey: publisher.publicKey,
      agentPublicKey: agent.publicKey, agentPrivateKey: agent.privateKey,
      intendedUsage: 'training',
      sourceUrl: 'https://example.com/plain',
    })
    assert.equal(result.governance.found, false)
    assert.equal(result.permitted, true) // ungoverned = no restrictions
    assert.equal(result.receipt, null)
    assert.ok(result.summary.includes('ungoverned'))
  })

  it('360: falls back to HTTP headers when no HTML block', () => {
    const headers = governanceHeaders(block)
    const lowerHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(headers)) lowerHeaders[k.toLowerCase()] = v

    const result = governanceLoop360({
      html: '<html><body>Article without embedded block</body></html>',
      contentBody: ARTICLE,
      publisherPublicKey: publisher.publicKey,
      agentPublicKey: agent.publicKey, agentPrivateKey: agent.privateKey,
      intendedUsage: 'inference',
      sourceUrl: 'https://theagenttimes.com/api/article/123',
      responseHeaders: lowerHeaders,
    })
    assert.equal(result.governance.found, true)
    assert.equal(result.governance.source, 'http_header')
    assert.ok(result.receipt)
  })

  it('360: detects tampered content — governance invalid', () => {
    const result = governanceLoop360({
      html: fullPage,
      contentBody: ARTICLE + ' TAMPERED BY MIDDLEMAN',
      publisherPublicKey: publisher.publicKey,
      agentPublicKey: agent.publicKey, agentPrivateKey: agent.privateKey,
      intendedUsage: 'inference',
      sourceUrl: 'https://theagenttimes.com/article/tampered',
    })
    assert.equal(result.governance.found, true)
    assert.equal(result.governance.verified, false)
    // Receipt records that governance was NOT verified
    assert.ok(result.receipt)
    assert.equal(result.receipt!.governance_verified, false)
  })
})

describe('Access Receipt', () => {
  const block = generateGovernanceBlock({
    content: ARTICLE, publicKey: publisher.publicKey, privateKey: publisher.privateKey, terms: TERMS,
  })

  it('creates and verifies access receipt', () => {
    const receipt = createAccessReceipt({
      agentPublicKey: agent.publicKey, agentPrivateKey: agent.privateKey,
      block, sourceUrl: 'https://example.com/article', intendedUsage: 'inference',
      governanceVerified: true,
    })
    assert.ok(receipt.receiptId.startsWith('gar_'))
    assert.equal(receipt.publisher_did, block.source_did)
    assert.equal(receipt.content_hash, block.content_hash)
    assert.equal(receipt.intended_usage, 'inference')
    assert.equal(receipt.terms_at_access.training, 'compensation_required')
    assert.equal(receipt.revocation_policy_at_access.cached_copy, 'delete')
    assert.equal(verifyAccessReceipt(receipt, agent.publicKey), true)
  })

  it('rejects receipt with wrong key', () => {
    const receipt = createAccessReceipt({
      agentPublicKey: agent.publicKey, agentPrivateKey: agent.privateKey,
      block, sourceUrl: 'https://example.com', intendedUsage: 'training',
      governanceVerified: true,
    })
    const other = generateKeyPair()
    assert.equal(verifyAccessReceipt(receipt, other.publicKey), false)
  })

  it('receipt preserves terms snapshot at access time', () => {
    const receipt = createAccessReceipt({
      agentPublicKey: agent.publicKey, agentPrivateKey: agent.privateKey,
      block, sourceUrl: 'https://example.com', intendedUsage: 'training',
      governanceVerified: true,
    })
    // Even if publisher later changes terms, the receipt records what was in effect
    assert.equal(receipt.terms_at_access.inference, 'permitted')
    assert.equal(receipt.terms_at_access.training, 'compensation_required')
    assert.equal(receipt.revocation_policy_at_access.rag_chunk, 'delete')
    assert.equal(receipt.revocation_policy_at_access.fine_tune, 'no_future_use')
  })
})

describe('checkHTMLGovernance', () => {
  it('finds and checks governance in HTML', () => {
    const { html } = embedGovernance({
      content: ARTICLE, publicKey: publisher.publicKey, privateKey: publisher.privateKey, terms: TERMS,
    })
    const result = checkHTMLGovernance(
      `<html><head>${html}</head><body></body></html>`,
      ARTICLE, publisher.publicKey, 'inference',
    )
    assert.equal(result.found, true)
    assert.equal(result.verified, true)
    assert.equal(result.usageCheck?.permitted, true)
  })
})
