// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  generateApsTxt, verifyApsTxt, serializeApsTxt, parseApsTxt,
  resolveTermsForPath, governanceHeaders, parseGovernanceHeaders,
  generateGovernanceBlock,
  createChainedGovernanceBlock, verifyChainedBlock,
} from '../src/index.js'
import type { GovernanceTerms } from '../src/index.js'

const keys = generateKeyPair()
const TERMS: GovernanceTerms = {
  inference: 'permitted',
  training: 'compensation_required',
  redistribution: 'prohibited',
}

describe('aps.txt — Site-Wide Governance', () => {
  it('generates valid signed aps.txt', () => {
    const doc = generateApsTxt({
      domain: 'theagenttimes.com', publisherName: 'The Agent Times',
      publicKey: keys.publicKey, privateKey: keys.privateKey,
      defaultTerms: TERMS,
      mcpEndpoint: 'https://mcp.theagenttimes.com/sse',
      revocationEndpoint: 'https://theagenttimes.com/api/revocations',
    })
    assert.equal(doc['@type'], 'ApsTxt')
    assert.equal(doc.domain, 'theagenttimes.com')
    assert.ok(doc.publisher_did.startsWith('did:aps:z'))
    assert.equal(doc.default_terms.training, 'compensation_required')
    assert.equal(doc.mcp_endpoint, 'https://mcp.theagenttimes.com/sse')
    assert.ok(doc.signature)
  })

  it('verifies valid aps.txt', () => {
    const doc = generateApsTxt({
      domain: 'example.com', publisherName: 'Test',
      publicKey: keys.publicKey, privateKey: keys.privateKey, defaultTerms: TERMS,
    })
    const result = verifyApsTxt(doc, keys.publicKey)
    assert.equal(result.valid, true)
  })

  it('detects tampered aps.txt', () => {
    const doc = generateApsTxt({
      domain: 'example.com', publisherName: 'Test',
      publicKey: keys.publicKey, privateKey: keys.privateKey, defaultTerms: TERMS,
    })
    doc.domain = 'evil.com'
    const result = verifyApsTxt(doc, keys.publicKey)
    assert.equal(result.valid, false)
  })

  it('roundtrips through serialize/parse', () => {
    const doc = generateApsTxt({
      domain: 'example.com', publisherName: 'Test',
      publicKey: keys.publicKey, privateKey: keys.privateKey, defaultTerms: TERMS,
    })
    const serialized = serializeApsTxt(doc)
    const parsed = parseApsTxt(serialized)
    assert.ok(parsed)
    assert.equal(parsed!.domain, 'example.com')
    const result = verifyApsTxt(parsed!, keys.publicKey)
    assert.equal(result.valid, true)
  })

  it('resolves path-specific terms with overrides', () => {
    const doc = generateApsTxt({
      domain: 'example.com', publisherName: 'Test',
      publicKey: keys.publicKey, privateKey: keys.privateKey,
      defaultTerms: TERMS,
      pathOverrides: [
        { pattern: '/api/*', terms: { training: 'prohibited', inference: 'prohibited' } },
        { pattern: '/blog/*', terms: { training: 'permitted' } },
      ],
    })
    const apiTerms = resolveTermsForPath(doc, '/api/data')
    assert.equal(apiTerms.training, 'prohibited')
    assert.equal(apiTerms.inference, 'prohibited')

    const blogTerms = resolveTermsForPath(doc, '/blog/my-article')
    assert.equal(blogTerms.training, 'permitted')
    assert.equal(blogTerms.redistribution, 'prohibited') // inherited from default

    const homeTerms = resolveTermsForPath(doc, '/about')
    assert.equal(homeTerms.training, 'compensation_required') // default
  })

  it('rejects invalid JSON in parseApsTxt', () => {
    assert.equal(parseApsTxt('not json'), null)
    assert.equal(parseApsTxt('{"@type":"NotApsTxt"}'), null)
  })
})

describe('Governance HTTP Headers', () => {
  const block = generateGovernanceBlock({
    content: 'Test article content', publicKey: keys.publicKey, privateKey: keys.privateKey,
    terms: TERMS,
  })

  it('generates X-APS-Governance header with full block', () => {
    const headers = governanceHeaders(block)
    assert.ok(headers['X-APS-Governance'])
    assert.ok(headers['X-APS-DID'].startsWith('did:aps:z'))
    assert.ok(headers['X-APS-Content-Hash'].startsWith('sha256:'))
    assert.equal(headers['X-APS-Terms-Training'], 'compensation_required')
    assert.equal(headers['X-APS-Terms-Inference'], 'permitted')
  })

  it('roundtrips through headers: generate → set → parse → verify', () => {
    const headers = governanceHeaders(block)
    // Simulate HTTP: lowercase header names
    const lowerHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(headers)) lowerHeaders[k.toLowerCase()] = v

    const parsed = parseGovernanceHeaders(lowerHeaders)
    assert.ok(parsed)
    assert.equal(parsed!.source_did, block.source_did)
    assert.equal(parsed!.content_hash, block.content_hash)
  })

  it('returns null for missing header', () => {
    assert.equal(parseGovernanceHeaders({ 'content-type': 'text/html' }), null)
  })
})

describe('Chained Governance Blocks', () => {
  const publisher = generateKeyPair()
  const agent = generateKeyPair()
  const originalContent = 'Original article about AI governance in healthcare.'
  const originalBlock = generateGovernanceBlock({
    content: originalContent, publicKey: publisher.publicKey, privateKey: publisher.privateKey,
    terms: TERMS,
  })

  it('creates chained block referencing parent', () => {
    const summary = 'AI governance article summary: covers healthcare agent regulation.'
    const chained = createChainedGovernanceBlock({
      content: summary, publicKey: agent.publicKey, privateKey: agent.privateKey,
      terms: { inference: 'permitted', training: 'prohibited' },
      parentBlock: originalBlock, derivationType: 'summary',
    })
    assert.ok(chained.parent_block_hash.startsWith('sha256:'))
    assert.equal(chained.derivation_type, 'summary')
    assert.equal(chained.source_did, originalBlock.source_did) // original publisher DID preserved
    assert.ok(chained.derivative_agent_did.startsWith('did:aps:z'))
    assert.notEqual(chained.derivative_agent_did, chained.source_did) // different agent
  })

  it('verifies valid chained block with parent', () => {
    const summary = 'AI governance article summary: covers healthcare agent regulation.'
    const chained = createChainedGovernanceBlock({
      content: summary, publicKey: agent.publicKey, privateKey: agent.privateKey,
      terms: { inference: 'permitted', training: 'prohibited' },
      parentBlock: originalBlock, derivationType: 'summary',
    })
    const result = verifyChainedBlock(chained, summary, agent.publicKey, originalBlock)
    assert.equal(result.valid, true)
    assert.equal(result.chainValid, true)
    assert.equal(result.errors.length, 0)
  })

  it('detects broken chain (wrong parent)', () => {
    const summary = 'Summary of something else entirely.'
    const fakeParent = generateGovernanceBlock({
      content: 'Completely different article', publicKey: publisher.publicKey, privateKey: publisher.privateKey,
      terms: TERMS,
    })
    const chained = createChainedGovernanceBlock({
      content: summary, publicKey: agent.publicKey, privateKey: agent.privateKey,
      terms: { inference: 'permitted' },
      parentBlock: fakeParent, derivationType: 'summary',
    })
    // Verify against the REAL original block — chain should break
    const result = verifyChainedBlock(chained, summary, agent.publicKey, originalBlock)
    assert.equal(result.chainValid, false)
    assert.ok(result.errors.some(e => e.includes('Parent block hash mismatch')))
  })

  it('detects tampered derivative content', () => {
    const summary = 'Original summary.'
    const chained = createChainedGovernanceBlock({
      content: summary, publicKey: agent.publicKey, privateKey: agent.privateKey,
      terms: { inference: 'permitted' },
      parentBlock: originalBlock, derivationType: 'rag_chunk',
    })
    const result = verifyChainedBlock(chained, summary + ' INJECTED', agent.publicKey, originalBlock)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => e.includes('Content hash mismatch')))
  })

  it('inherits revocation policy from parent when not overridden', () => {
    const summary = 'Derived content.'
    const chained = createChainedGovernanceBlock({
      content: summary, publicKey: agent.publicKey, privateKey: agent.privateKey,
      terms: { inference: 'permitted' },
      parentBlock: originalBlock, derivationType: 'embedding',
    })
    assert.equal(chained.revocation_policy.cached_copy, originalBlock.revocation_policy.cached_copy)
    assert.equal(chained.revocation_policy.fine_tune, originalBlock.revocation_policy.fine_tune)
  })

  it('verifies without parent (chain unchecked)', () => {
    const summary = 'Standalone verification.'
    const chained = createChainedGovernanceBlock({
      content: summary, publicKey: agent.publicKey, privateKey: agent.privateKey,
      terms: { inference: 'permitted' },
      parentBlock: originalBlock, derivationType: 'summary',
    })
    const result = verifyChainedBlock(chained, summary, agent.publicKey)
    assert.equal(result.valid, true)
    assert.equal(result.chainValid, true) // no parent to check against, so chain is "valid"
  })
})
