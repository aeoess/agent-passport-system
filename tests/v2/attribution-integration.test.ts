// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// AttributionConsent integration — charter / settlement / completion_receipt

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createAttributionReceipt, signAttributionConsent,
  createCharter, verifyCharter,
  createCompletionReceipt, verifyCompletionReceipt,
  generateKeyPair, publicKeyFromPrivate,
} from '../../src/index.js'
import type {
  AttributionReceipt, ArtifactCitation,
} from '../../src/index.js'
// verifySettlement + SettlementRecord moved to @aeoess/gateway.
// Gateway-side integration tests cover the AttributionConsent gating.
import type { HybridTimestamp } from '../../src/types/time.js'

function stampAt(wallMs: number, logicalTime = 1, gatewayId = 'test-gw'): HybridTimestamp {
  return {
    logicalTime,
    wallClockEarliest: wallMs - 50,
    wallClockLatest: wallMs + 50,
    gatewayId,
  }
}

function validReceipt(opts: { bindingContext: string; expiredAt?: number }): {
  receipt: AttributionReceipt
  citation: ArtifactCitation
} {
  const citer = generateKeyPair()
  const cited = generateKeyPair()
  const now = Date.now()
  const expiresWall = opts.expiredAt ?? (now + 5 * 60_000)
  const unsigned = createAttributionReceipt({
    citer: 'did:aps:citer',
    citer_public_key: citer.publicKey,
    citer_private_key: citer.privateKey,
    cited_principal: 'did:aps:cited',
    cited_principal_public_key: cited.publicKey,
    citation_content: `claim-for-${opts.bindingContext}`,
    binding_context: opts.bindingContext,
    created_at: stampAt(now),
    expires_at: stampAt(expiresWall, 2),
  })
  const receipt = signAttributionConsent(unsigned, cited.privateKey)
  const citation: ArtifactCitation = {
    receipt_id: receipt.id,
    cited_principal: receipt.cited_principal,
    citation_content: receipt.citation_content,
  }
  return { receipt, citation }
}

// ══════════════════════════════════════════════════════════════════
// Charter
// ══════════════════════════════════════════════════════════════════

function makeCharter(citations?: ArtifactCitation[]) {
  const founder = generateKeyPair()
  const mkThreshold = () => ({
    policyId: 'policy_test',
    requirements: [{
      role: 'board', requiredSignatures: 1, eligibleKeys: [founder.publicKey],
    }],
    collectionTimeoutSeconds: 3600,
    onTimeout: 'reject' as const,
    reevaluateOnRevocation: true,
  })
  return createCharter({
    name: 'Test Institution',
    offices: [{
      officeId: 'ops',
      name: 'Operations',
      holderMode: 'single',
      holderSet: [{
        publicKey: founder.publicKey,
        appointedAt: new Date().toISOString(),
        appointedBy: 'charter_founding',
        isInterim: false,
      }],
      delegationPolicy: { allowedScopes: ['*'], maxSpendPerAction: 1000, maxDelegationDepth: 3 },
      successionOrder: [],
      status: 'active',
      effectiveAt: new Date().toISOString(),
    } as any],
    amendmentPolicy: mkThreshold() as any,
    dissolutionPolicy: {
      requiresThreshold: mkThreshold(),
      gracePeriodSeconds: 86400,
      activeEscrowHandling: 'settle_first',
    } as any,
    delegationSurvival: {
      onOfficeChange: 'require_reconfirmation',
      onCharterAmendment: 'survive_if_compatible',
    } as any,
    founderPrivateKey: founder.privateKey,
    founderPublicKey: founder.publicKey,
    founderRole: 'board',
    citations,
  })
}

describe('verifyCharter — AttributionConsent integration', () => {
  it('charter without citations: verify passes unchanged', () => {
    const charter = makeCharter()
    const v = verifyCharter(charter)
    assert.equal(v.valid, true, v.errors.join(', '))
  })

  it('charter with citations but no receipts arg: fails clearly', () => {
    const { citation } = validReceipt({ bindingContext: 'charter:x' })
    const charter = makeCharter([citation])
    const v = verifyCharter(charter)
    assert.equal(v.valid, false)
    assert.ok(v.errors.some(e => /citations present but no receipts supplied/.test(e)))
  })

  it('charter with citations + matching receipts: passes', () => {
    const { receipt, citation } = validReceipt({ bindingContext: 'charter:x' })
    const charter = makeCharter([citation])
    const v = verifyCharter(charter, [receipt])
    assert.equal(v.valid, true, v.errors.join(', '))
  })

  it('charter with citations + wrong receipts (different citer content): fails', () => {
    const { citation } = validReceipt({ bindingContext: 'charter:x' })
    const { receipt: otherReceipt } = validReceipt({ bindingContext: 'charter:y' })
    const charter = makeCharter([citation])
    const v = verifyCharter(charter, [otherReceipt])
    assert.equal(v.valid, false)
    assert.ok(v.errors.some(e => /AttributionConsent/.test(e)))
  })

  it('charter with citations + expired receipt: fails with expired', () => {
    const past = Date.now() - 10 * 60_000
    const citer = generateKeyPair()
    const cited = generateKeyPair()
    const unsigned = createAttributionReceipt({
      citer: 'did:aps:citer',
      citer_public_key: citer.publicKey,
      citer_private_key: citer.privateKey,
      cited_principal: 'did:aps:cited',
      cited_principal_public_key: cited.publicKey,
      citation_content: 'stale-claim',
      binding_context: 'charter:old',
      created_at: stampAt(past - 60_000),
      expires_at: stampAt(past, 2),
    })
    const receipt = signAttributionConsent(unsigned, cited.privateKey)
    const citation: ArtifactCitation = {
      receipt_id: receipt.id,
      cited_principal: receipt.cited_principal,
      citation_content: receipt.citation_content,
    }
    const charter = makeCharter([citation])
    const v = verifyCharter(charter, [receipt])
    assert.equal(v.valid, false)
    assert.ok(v.errors.some(e => /expired/.test(e)))
  })
})

// ══════════════════════════════════════════════════════════════════
// Settlement — verifySettlement tests moved to @aeoess/gateway
// (tests/sdk-migrated/core/data-settlement.test.ts). The
// AttributionConsent primitive the gating relies on is still tested above.
// ══════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════
// Completion Receipt
// ══════════════════════════════════════════════════════════════════

function makeCompletion(citations?: ArtifactCitation[]) {
  const key = generateKeyPair()
  const receipt = createCompletionReceipt({
    permitReceiptHash: 'p'.repeat(64),
    executionResult: 'success',
    resultSummary: 'ok',
    executedAt: new Date().toISOString(),
    durationMs: 1,
    privateKey: key.privateKey,
    citations,
  })
  return { receipt, publicKey: key.publicKey }
}

describe('verifyCompletionReceipt — AttributionConsent integration', () => {
  it('completion without citations: verify passes unchanged', () => {
    const { receipt, publicKey } = makeCompletion()
    const v = verifyCompletionReceipt(receipt, publicKey)
    assert.equal(v.valid, true, v.errors.join(', '))
  })

  it('completion with citations but no receipts arg: fails clearly', () => {
    const { citation } = validReceipt({ bindingContext: 'completion:c1' })
    const { receipt, publicKey } = makeCompletion([citation])
    const v = verifyCompletionReceipt(receipt, publicKey)
    assert.equal(v.valid, false)
    assert.ok(v.errors.some(e => /citations present but no receipts supplied/.test(e)))
  })

  it('completion with citations + matching receipts: passes', () => {
    const { receipt: attrReceipt, citation } = validReceipt({ bindingContext: 'completion:c1' })
    const { receipt, publicKey } = makeCompletion([citation])
    const v = verifyCompletionReceipt(receipt, publicKey, [attrReceipt])
    assert.equal(v.valid, true, v.errors.join(', '))
  })

  it('completion with citations + wrong receipts: fails', () => {
    const { citation } = validReceipt({ bindingContext: 'completion:c1' })
    const { receipt: other } = validReceipt({ bindingContext: 'completion:other' })
    const { receipt, publicKey } = makeCompletion([citation])
    const v = verifyCompletionReceipt(receipt, publicKey, [other])
    assert.equal(v.valid, false)
    assert.ok(v.errors.some(e => /AttributionConsent/.test(e)))
  })
})

// ══════════════════════════════════════════════════════════════════
// Multi-citation integration
// ══════════════════════════════════════════════════════════════════

describe('integration: multi-citation artifact surfaces failing receipt', () => {
  it('2 citations, 1 valid + 1 invalid (expired) → verify fails, surfaces receipt id', () => {
    const past = Date.now() - 10 * 60_000
    const { receipt: goodReceipt, citation: goodCitation } = validReceipt({ bindingContext: 'charter:multi' })

    const citer = generateKeyPair()
    const cited = generateKeyPair()
    const badUnsigned = createAttributionReceipt({
      citer: 'did:aps:citer',
      citer_public_key: citer.publicKey,
      citer_private_key: citer.privateKey,
      cited_principal: 'did:aps:cited',
      cited_principal_public_key: cited.publicKey,
      citation_content: 'stale',
      binding_context: 'charter:multi',
      created_at: stampAt(past - 60_000),
      expires_at: stampAt(past, 2),
    })
    const badReceipt = signAttributionConsent(badUnsigned, cited.privateKey)
    const badCitation: ArtifactCitation = {
      receipt_id: badReceipt.id,
      cited_principal: badReceipt.cited_principal,
      citation_content: badReceipt.citation_content,
    }

    const charter = makeCharter([goodCitation, badCitation])
    const v = verifyCharter(charter, [goodReceipt, badReceipt])
    assert.equal(v.valid, false)
    const consentErr = v.errors.find(e => /AttributionConsent/.test(e))
    assert.ok(consentErr, 'expected AttributionConsent error')
    // The failing receipt id must be named in the surfaced reason.
    assert.ok(consentErr!.includes(badReceipt.id), `error should reference failing receipt ${badReceipt.id}, got: ${consentErr}`)
    assert.ok(/expired/.test(consentErr!))
  })
})
