import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  parseAgentJson,
  resolveIntentPrice,
  resolveIntentBounty,
  commercePreflightFromManifest,
  generateCommerceReceiptFromManifest,
} from '../src/interop/agent-json-bridge.js'
import type { AgentJsonManifest } from '../src/interop/agent-json-bridge.js'
import type { CommerceDelegation } from '../src/types/commerce.js'
import { generateKeyPair, verify } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'

// ═══════════════════════════════════════
// Test Fixtures
// ═══════════════════════════════════════

const TIER1_MANIFEST = {
  version: '1.0',
  origin: 'example.com',
  payout_address: '0x0000000000000000000000000000000000000000',
}

const TIER2_MANIFEST: AgentJsonManifest = {
  version: '1.0',
  origin: 'shop.example.com',
  payout_address: '0xabc123',
  display_name: 'Example Shop',
  description: 'Online marketplace for electronics.',
  intents: [
    {
      name: 'search_products',
      description: 'Search the product catalog by keyword.',
      parameters: {
        query: { type: 'string', required: true, description: 'Search query' },
      },
    },
    {
      name: 'complete_purchase',
      description: 'Complete a purchase for items in cart.',
      parameters: {
        cart_id: { type: 'string', required: true, description: 'Cart ID' },
      },
      price: { amount: 50, currency: 'USDC', model: 'per_call' },
      bounty: { type: 'cpa', rate: 5.0, currency: 'USDC' },
    },
  ],
  bounty: { type: 'cpa', rate: 1.0, currency: 'USDC' },
}

const TIER3_MANIFEST: AgentJsonManifest = {
  version: '1.3',
  origin: 'api.example.com',
  payout_address: '0xdef456',
  display_name: 'Example Intelligence API',
  description: 'AI-powered document analysis.',
  identity: {
    did: 'did:web:api.example.com',
    public_key: 'base64url-encoded-public-key',
  },
  intents: [
    {
      name: 'analyze_document',
      description: 'AI-powered document analysis.',
      endpoint: '/api/v1/analyze',
      method: 'POST',
      parameters: {
        document_url: { type: 'string', required: true, description: 'URL of the document' },
      },
      returns: {
        type: 'object',
        description: 'Analysis result',
        properties: {
          summary: { type: 'string', description: 'Document summary' },
        },
      },
      price: { amount: 50, currency: 'USDC', model: 'per_call' },
    },
  ],
}

function makeDelegation(overrides: Partial<CommerceDelegation> = {}): CommerceDelegation {
  return {
    agentId: 'agent-001',
    delegationId: 'del-001',
    scope: ['commerce:checkout', 'commerce:browse'],
    spendLimit: 1000,
    spentAmount: 0,
    currency: 'USDC',
    approvedMerchants: undefined,
    requireHumanApproval: false,
    humanApprovalThreshold: 500,
    ...overrides,
  }
}

// ═══════════════════════════════════════
// Tests: Parse & Validate
// ═══════════════════════════════════════

describe('agent.json Bridge — Parse & Validate', () => {
  it('parses a valid Tier 1 manifest (minimal)', () => {
    const m = parseAgentJson(TIER1_MANIFEST)
    assert.equal(m.version, '1.0')
    assert.equal(m.origin, 'example.com')
    assert.equal(m.payout_address, '0x0000000000000000000000000000000000000000')
    assert.equal(m.intents, undefined)
  })

  it('parses a valid Tier 2 manifest with intents', () => {
    const m = parseAgentJson(TIER2_MANIFEST)
    assert.equal(m.display_name, 'Example Shop')
    assert.equal(m.intents!.length, 2)
    assert.equal(m.intents![0].name, 'search_products')
    assert.equal(m.intents![1].price!.amount, 50)
  })

  it('parses a valid Tier 3 manifest with identity', () => {
    const m = parseAgentJson(TIER3_MANIFEST)
    assert.equal(m.version, '1.3')
    assert.equal(m.identity!.did, 'did:web:api.example.com')
    assert.equal(m.intents![0].endpoint, '/api/v1/analyze')
  })

  it('parses from JSON string', () => {
    const json = JSON.stringify(TIER1_MANIFEST)
    const m = parseAgentJson(json)
    assert.equal(m.origin, 'example.com')
  })

  it('rejects missing version', () => {
    assert.throws(() => parseAgentJson({ origin: 'x', payout_address: '0x' }), /missing required field "version"/)
  })

  it('rejects missing origin', () => {
    assert.throws(() => parseAgentJson({ version: '1.0', payout_address: '0x' }), /missing required field "origin"/)
  })

  it('rejects missing payout_address', () => {
    assert.throws(() => parseAgentJson({ version: '1.0', origin: 'x' }), /missing required field "payout_address"/)
  })

  it('rejects unsupported version', () => {
    assert.throws(() => parseAgentJson({ version: '2.0', origin: 'x', payout_address: '0x' }), /unsupported version/)
  })

  it('rejects invalid JSON string', () => {
    assert.throws(() => parseAgentJson('not json'), /not valid JSON/)
  })

  it('rejects intent without name', () => {
    assert.throws(() => parseAgentJson({
      version: '1.0', origin: 'x', payout_address: '0x',
      intents: [{ description: 'test' }],
    }), /intent missing required field "name"/)
  })
})

// ═══════════════════════════════════════
// Tests: Price & Bounty Resolution
// ═══════════════════════════════════════

describe('agent.json Bridge — Price & Bounty Resolution', () => {
  it('resolves intent-level price', () => {
    const p = resolveIntentPrice(TIER2_MANIFEST, 'complete_purchase')
    assert.ok(p)
    assert.equal(p.amount, 50)
    assert.equal(p.currency, 'USDC')
    assert.equal(p.model, 'per_call')
  })

  it('returns null for unpriced intent', () => {
    const p = resolveIntentPrice(TIER2_MANIFEST, 'search_products')
    assert.equal(p, null)
  })

  it('returns null for unknown intent', () => {
    const p = resolveIntentPrice(TIER2_MANIFEST, 'nonexistent')
    assert.equal(p, null)
  })

  it('resolves intent-level bounty over manifest-level', () => {
    const b = resolveIntentBounty(TIER2_MANIFEST, 'complete_purchase')
    assert.ok(b)
    assert.equal(b.rate, 5.0)  // intent-level overrides manifest-level 1.0
  })

  it('falls back to manifest-level bounty', () => {
    const b = resolveIntentBounty(TIER2_MANIFEST, 'search_products')
    assert.ok(b)
    assert.equal(b.rate, 1.0)  // manifest-level default
  })

  it('returns null when no bounty at any level', () => {
    const b = resolveIntentBounty(TIER3_MANIFEST, 'analyze_document')
    assert.equal(b, null)
  })
})

// ═══════════════════════════════════════
// Tests: Commerce Preflight (4-gate)
// ═══════════════════════════════════════

describe('agent.json Bridge — Commerce Preflight', () => {
  it('passes when delegation covers scope + budget', () => {
    const result = commercePreflightFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'complete_purchase',
      delegation: makeDelegation(),
    })
    assert.equal(result.permitted, true)
    assert.equal(result.checks.every(c => c.passed), true)
  })

  it('fails when scope not in delegation', () => {
    const result = commercePreflightFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'complete_purchase',
      delegation: makeDelegation({ scope: ['data:read'] }),
    })
    assert.equal(result.permitted, false)
    const scopeCheck = result.checks.find(c => c.check === 'delegation_scope')
    assert.ok(scopeCheck)
    assert.equal(scopeCheck.passed, false)
  })

  it('fails when price exceeds remaining spend limit', () => {
    const result = commercePreflightFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'complete_purchase',
      delegation: makeDelegation({ spendLimit: 100, spentAmount: 80 }),
    })
    assert.equal(result.permitted, false)
    const spendCheck = result.checks.find(c => c.check === 'spend_limit')
    assert.ok(spendCheck)
    assert.equal(spendCheck.passed, false)
  })

  it('fails when merchant not in whitelist', () => {
    const result = commercePreflightFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'complete_purchase',
      delegation: makeDelegation({ approvedMerchants: ['other-store.com'] }),
    })
    assert.equal(result.permitted, false)
    const merchantCheck = result.checks.find(c => c.check === 'merchant_whitelist')
    assert.ok(merchantCheck)
    assert.equal(merchantCheck.passed, false)
  })

  it('requires human approval when price exceeds threshold', () => {
    const result = commercePreflightFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'complete_purchase',
      delegation: makeDelegation({ humanApprovalThreshold: 10 }),
    })
    assert.equal(result.permitted, false)
    const approvalCheck = result.checks.find(c => c.check === 'human_approval')
    assert.ok(approvalCheck)
    assert.equal(approvalCheck.passed, false)
    assert.ok(result.warnings.length > 0)
  })

  it('returns error for unknown intent', () => {
    const result = commercePreflightFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'nonexistent_intent',
      delegation: makeDelegation(),
    })
    assert.equal(result.permitted, false)
    assert.ok(result.blockedReason?.includes('not declared'))
  })

  it('passes free intent with no spend check needed', () => {
    const result = commercePreflightFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'search_products',
      delegation: makeDelegation(),
    })
    assert.equal(result.permitted, true)
    const spendCheck = result.checks.find(c => c.check === 'spend_limit')
    assert.ok(spendCheck?.detail.includes('free'))
  })

  it('passes when no merchant whitelist configured', () => {
    const result = commercePreflightFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'complete_purchase',
      delegation: makeDelegation({ approvedMerchants: undefined }),
    })
    const merchantCheck = result.checks.find(c => c.check === 'merchant_whitelist')
    assert.ok(merchantCheck?.passed)
    assert.ok(merchantCheck?.detail.includes('all merchants'))
  })
})

// ═══════════════════════════════════════
// Tests: Receipt Generation
// ═══════════════════════════════════════

describe('agent.json Bridge — Commerce Receipt', () => {
  it('generates signed receipt with full attribution chain', () => {
    const keys = generateKeyPair()
    const receipt = generateCommerceReceiptFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'complete_purchase',
      delegation: makeDelegation(),
      beneficiary: 'human-principal-001',
      privateKey: keys.privateKey,
    })

    assert.ok(receipt.receiptId.startsWith('ajr_'))
    assert.equal(receipt.agentId, 'agent-001')
    assert.equal(receipt.delegationId, 'del-001')
    assert.equal(receipt.beneficiary, 'human-principal-001')
    assert.equal(receipt.service.origin, 'shop.example.com')
    assert.equal(receipt.intent.name, 'complete_purchase')
    assert.equal(receipt.spend.amount, 50)
    assert.equal(receipt.spend.currency, 'USDC')
    assert.equal(receipt.spend.pricingModel, 'per_call')
    assert.ok(receipt.signature)
  })

  it('receipt signature is cryptographically verifiable', () => {
    const keys = generateKeyPair()
    const receipt = generateCommerceReceiptFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'complete_purchase',
      delegation: makeDelegation(),
      beneficiary: 'human-principal-001',
      privateKey: keys.privateKey,
    })

    const { signature, ...unsigned } = receipt
    const valid = verify(canonicalize(unsigned), signature, keys.publicKey)
    assert.equal(valid, true)
  })

  it('receipt includes service DID from Tier 3 manifest', () => {
    const keys = generateKeyPair()
    const receipt = generateCommerceReceiptFromManifest({
      manifest: TIER3_MANIFEST,
      intentName: 'analyze_document',
      delegation: makeDelegation(),
      beneficiary: 'human-principal-001',
      privateKey: keys.privateKey,
    })

    assert.equal(receipt.service.did, 'did:web:api.example.com')
    assert.equal(receipt.service.publicKey, 'base64url-encoded-public-key')
  })

  it('receipt includes bounty earned when available', () => {
    const keys = generateKeyPair()
    const receipt = generateCommerceReceiptFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'complete_purchase',
      delegation: makeDelegation(),
      beneficiary: 'human-principal-001',
      privateKey: keys.privateKey,
    })

    assert.ok(receipt.bountyEarned)
    assert.equal(receipt.bountyEarned!.amount, 5.0)
    assert.equal(receipt.bountyEarned!.currency, 'USDC')
  })

  it('receipt has no bounty when manifest has none', () => {
    const keys = generateKeyPair()
    const receipt = generateCommerceReceiptFromManifest({
      manifest: TIER3_MANIFEST,
      intentName: 'analyze_document',
      delegation: makeDelegation(),
      beneficiary: 'human-principal-001',
      privateKey: keys.privateKey,
    })

    assert.equal(receipt.bountyEarned, undefined)
  })

  it('throws when generating receipt for unknown intent', () => {
    const keys = generateKeyPair()
    assert.throws(() => generateCommerceReceiptFromManifest({
      manifest: TIER2_MANIFEST,
      intentName: 'nonexistent',
      delegation: makeDelegation(),
      beneficiary: 'human',
      privateKey: keys.privateKey,
    }), /not found in manifest/)
  })
})

// ═══════════════════════════════════════
// Tests: End-to-End Flow
// ═══════════════════════════════════════

describe('agent.json Bridge — End-to-End', () => {
  it('parse manifest → preflight → generate receipt', () => {
    const keys = generateKeyPair()
    const delegation = makeDelegation({ approvedMerchants: ['shop.example.com'] })

    // Step 1: Parse
    const manifest = parseAgentJson(TIER2_MANIFEST)
    assert.equal(manifest.origin, 'shop.example.com')

    // Step 2: Preflight
    const preflight = commercePreflightFromManifest({
      manifest,
      intentName: 'complete_purchase',
      delegation,
    })
    assert.equal(preflight.permitted, true)

    // Step 3: Generate receipt (only after preflight passes)
    const receipt = generateCommerceReceiptFromManifest({
      manifest,
      intentName: 'complete_purchase',
      delegation,
      beneficiary: 'human-principal-001',
      privateKey: keys.privateKey,
    })

    // Verify full chain
    assert.equal(receipt.beneficiary, 'human-principal-001')
    assert.equal(receipt.service.origin, 'shop.example.com')
    assert.equal(receipt.service.displayName, 'Example Shop')
    assert.equal(receipt.intent.name, 'complete_purchase')
    assert.equal(receipt.spend.amount, 50)
    assert.equal(receipt.bountyEarned!.amount, 5.0)

    // Verify signature
    const { signature, ...unsigned } = receipt
    const valid = verify(canonicalize(unsigned), signature, keys.publicKey)
    assert.equal(valid, true)
  })
})
