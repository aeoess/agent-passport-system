// ══════════════════════════════════════════════════════════════════
// Governance Consumer — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: checkHTMLGovernance, checkHeaderGovernance,
// createAccessReceipt, verifyAccessReceipt, governanceLoop360.
// The only untested core module — filling the gap.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  generateGovernanceBlock,
  renderGovernanceHTML,
  embedGovernance,
} from '../src/core/governance-block.js'
import {
  checkHTMLGovernance,
  checkHeaderGovernance,
  createAccessReceipt,
  verifyAccessReceipt,
  governanceLoop360,
} from '../src/core/governance-consumer.js'

// ── Test data factory ──

function createTestGovernance() {
  const publisherKeys = generateKeyPair()
  const agentKeys = generateKeyPair()
  const contentBody = 'This is an article about AI governance. It discusses how agents should be accountable.'

  const terms = {
    version: '1.0' as const,
    inference: 'permitted' as const,
    training: 'prohibited' as const,
    redistribution: 'attribution_required' as const,
    derivative: 'permitted' as const,
    caching: 'time_limited' as const,
  }

  const block = generateGovernanceBlock({
    content: contentBody,
    publicKey: publisherKeys.publicKey,
    privateKey: publisherKeys.privateKey,
    terms,
  })

  const html = `<html><head></head><body>
    <script type="application/aps-governance+json">${JSON.stringify(block)}</script>
    <p>${contentBody}</p>
  </body></html>`

  return { publisherKeys, agentKeys, contentBody, terms, block, html }
}

// ══════════════════════════════════════════════════════════════════
// Test Suite: checkHTMLGovernance
// ══════════════════════════════════════════════════════════════════

describe('Governance Consumer — HTML Check', () => {
  it('finds and verifies governance block in HTML', () => {
    const { html, contentBody, publisherKeys } = createTestGovernance()
    const result = checkHTMLGovernance(html, contentBody, publisherKeys.publicKey, 'inference')

    assert.strictEqual(result.found, true)
    assert.strictEqual(result.source, 'html_script')
    assert.ok(result.block, 'block must be present')
    assert.strictEqual(result.verified, true)
    assert.strictEqual(result.errors.length, 0)
  })

  it('checks usage permission correctly — inference permitted', () => {
    const { html, contentBody, publisherKeys } = createTestGovernance()
    const result = checkHTMLGovernance(html, contentBody, publisherKeys.publicKey, 'inference')

    assert.ok(result.usageCheck)
    assert.strictEqual(result.usageCheck.permitted, true)
  })

  it('checks usage permission correctly — training prohibited', () => {
    const { html, contentBody, publisherKeys } = createTestGovernance()
    const result = checkHTMLGovernance(html, contentBody, publisherKeys.publicKey, 'training')

    assert.ok(result.usageCheck)
    assert.strictEqual(result.usageCheck.permitted, false)
  })

  it('returns found=false when no governance block in HTML', () => {
    const result = checkHTMLGovernance('<html><body>No governance here</body></html>', 'content', 'fakepubkey', 'inference')
    assert.strictEqual(result.found, false)
    assert.strictEqual(result.source, 'none')
    assert.strictEqual(result.block, null)
  })

  it('detects invalid signature with wrong publisher key', () => {
    const { html, contentBody } = createTestGovernance()
    const wrongKeys = generateKeyPair()
    const result = checkHTMLGovernance(html, contentBody, wrongKeys.publicKey, 'inference')

    assert.strictEqual(result.found, true)
    assert.strictEqual(result.verified, false)
    assert.ok(result.errors.length > 0, 'should have verification errors')
  })

  it('detects content hash mismatch with tampered content', () => {
    const { html, publisherKeys } = createTestGovernance()
    const result = checkHTMLGovernance(html, 'This content has been tampered with', publisherKeys.publicKey, 'inference')

    assert.strictEqual(result.found, true)
    assert.strictEqual(result.verified, false)
  })
})

// ══════════════════════════════════════════════════════════════════
// Test Suite: Access Receipts
// ══════════════════════════════════════════════════════════════════

describe('Governance Consumer — Access Receipts', () => {
  it('creates a signed access receipt', () => {
    const { agentKeys, block } = createTestGovernance()
    const receipt = createAccessReceipt({
      agentPublicKey: agentKeys.publicKey,
      agentPrivateKey: agentKeys.privateKey,
      block,
      sourceUrl: 'https://theagenttimes.com/article/test',
      intendedUsage: 'inference',
      governanceVerified: true,
    })

    assert.ok(receipt.receiptId.startsWith('gar_'), 'receipt ID should start with gar_')
    assert.ok(receipt.agent_did.startsWith('did:aps:'), 'agent DID should be set')
    assert.strictEqual(receipt.publisher_did, block.source_did)
    assert.strictEqual(receipt.content_hash, block.content_hash)
    assert.strictEqual(receipt.source_url, 'https://theagenttimes.com/article/test')
    assert.strictEqual(receipt.intended_usage, 'inference')
    assert.strictEqual(receipt.governance_verified, true)
    assert.ok(receipt.signature.length > 0, 'must be signed')
    assert.ok(receipt.accessed_at, 'must have timestamp')
  })

  it('verifies a valid access receipt', () => {
    const { agentKeys, block } = createTestGovernance()
    const receipt = createAccessReceipt({
      agentPublicKey: agentKeys.publicKey,
      agentPrivateKey: agentKeys.privateKey,
      block,
      sourceUrl: 'https://example.com/page',
      intendedUsage: 'inference',
      governanceVerified: true,
    })

    const valid = verifyAccessReceipt(receipt, agentKeys.publicKey)
    assert.strictEqual(valid, true)
  })

  it('rejects tampered access receipt', () => {
    const { agentKeys, block } = createTestGovernance()
    const receipt = createAccessReceipt({
      agentPublicKey: agentKeys.publicKey,
      agentPrivateKey: agentKeys.privateKey,
      block,
      sourceUrl: 'https://example.com/page',
      intendedUsage: 'inference',
      governanceVerified: true,
    })

    // Tamper with the receipt
    receipt.intended_usage = 'training'
    const valid = verifyAccessReceipt(receipt, agentKeys.publicKey)
    assert.strictEqual(valid, false, 'tampered receipt should fail verification')
  })

  it('rejects receipt verified with wrong key', () => {
    const { agentKeys, block } = createTestGovernance()
    const receipt = createAccessReceipt({
      agentPublicKey: agentKeys.publicKey,
      agentPrivateKey: agentKeys.privateKey,
      block,
      sourceUrl: 'https://example.com/page',
      intendedUsage: 'inference',
      governanceVerified: true,
    })

    const wrongKeys = generateKeyPair()
    const valid = verifyAccessReceipt(receipt, wrongKeys.publicKey)
    assert.strictEqual(valid, false, 'wrong key should fail')
  })

  it('captures terms and revocation policy at access time', () => {
    const { agentKeys, block, terms } = createTestGovernance()
    const receipt = createAccessReceipt({
      agentPublicKey: agentKeys.publicKey,
      agentPrivateKey: agentKeys.privateKey,
      block,
      sourceUrl: 'https://example.com/page',
      intendedUsage: 'inference',
      governanceVerified: true,
    })

    assert.deepStrictEqual(receipt.terms_at_access, terms)
    assert.ok(receipt.revocation_policy_at_access, 'must capture revocation policy')
  })
})

// ══════════════════════════════════════════════════════════════════
// Test Suite: Full 360 Governance Loop
// ══════════════════════════════════════════════════════════════════

describe('Governance Consumer — 360 Loop', () => {
  it('completes the full loop: extract → verify → check → receipt', () => {
    const { html, contentBody, publisherKeys, agentKeys } = createTestGovernance()
    const result = governanceLoop360({
      html,
      contentBody,
      publisherPublicKey: publisherKeys.publicKey,
      agentPublicKey: agentKeys.publicKey,
      agentPrivateKey: agentKeys.privateKey,
      intendedUsage: 'inference',
      sourceUrl: 'https://theagenttimes.com/article/test',
    })

    assert.strictEqual(result.permitted, true, 'inference should be permitted')
    assert.ok(result.receipt, 'receipt must be generated')
    assert.ok(result.receipt.receiptId.startsWith('gar_'))
    assert.strictEqual(result.governance.verified, true)
    assert.ok(result.summary.includes('VERIFIED'))
    assert.ok(result.summary.includes('PERMITTED'))
  })

  it('detects restricted usage in 360 loop', () => {
    const { html, contentBody, publisherKeys, agentKeys } = createTestGovernance()
    const result = governanceLoop360({
      html,
      contentBody,
      publisherPublicKey: publisherKeys.publicKey,
      agentPublicKey: agentKeys.publicKey,
      agentPrivateKey: agentKeys.privateKey,
      intendedUsage: 'training',
      sourceUrl: 'https://theagenttimes.com/article/test',
    })

    assert.strictEqual(result.permitted, false, 'training should be restricted')
    assert.ok(result.receipt, 'receipt still generated even for restricted usage')
    assert.ok(result.summary.includes('RESTRICTED'))
  })

  it('handles ungoverned content gracefully', () => {
    const agentKeys = generateKeyPair()
    const publisherKeys = generateKeyPair()
    const result = governanceLoop360({
      html: '<html><body>No governance here</body></html>',
      contentBody: 'No governance here',
      publisherPublicKey: publisherKeys.publicKey,
      agentPublicKey: agentKeys.publicKey,
      agentPrivateKey: agentKeys.privateKey,
      intendedUsage: 'inference',
      sourceUrl: 'https://example.com/plain',
    })

    assert.strictEqual(result.permitted, true, 'ungoverned content should be permitted')
    assert.strictEqual(result.receipt, null, 'no receipt for ungoverned content')
    assert.ok(result.summary.includes('ungoverned'))
  })

  it('receipt from 360 loop verifies correctly', () => {
    const { html, contentBody, publisherKeys, agentKeys } = createTestGovernance()
    const result = governanceLoop360({
      html,
      contentBody,
      publisherPublicKey: publisherKeys.publicKey,
      agentPublicKey: agentKeys.publicKey,
      agentPrivateKey: agentKeys.privateKey,
      intendedUsage: 'inference',
      sourceUrl: 'https://theagenttimes.com/article/test',
    })

    assert.ok(result.receipt)
    const valid = verifyAccessReceipt(result.receipt, agentKeys.publicKey)
    assert.strictEqual(valid, true, 'receipt from 360 loop must verify')
  })
})
