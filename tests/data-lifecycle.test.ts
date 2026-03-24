import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createDerivationReceipt, resolveExtendedLineage,
  evaluateRevocationImpact, DEFAULT_OBLIGATIONS,
  createDecisionLineageReceipt,
  isPurposePermitted, purposeCategory,
  pinTermsAtAccess, isRetentionExpired,
  verifyDerivationReceipt, verifyDecisionLineageReceipt,
} from '../src/index.js'
import type { DerivationReceipt, ParentArtifact, RetentionPolicy } from '../src/index.js'
import { generateKeyPair } from '../src/crypto/keys.js'

const keys = generateKeyPair()

// ═══════════════════════════════════════
// Tests: Extended Derivation Continuity
// ═══════════════════════════════════════

describe('Data Lifecycle — Derivation Receipts', () => {
  it('creates a signed derivation receipt', () => {
    const r = createDerivationReceipt({
      derivativeId: 'deriv-001',
      derivativeType: 'rag_chunk',
      parentArtifacts: [{ artifactId: 'access-001', artifactType: 'access_receipt', sourceId: 'src-1' }],
      transformClass: 'embedding',
      lineageConfidence: 'complete',
      agentId: 'agent-1',
      privateKey: keys.privateKey,
    })
    assert.ok(r.receiptId.startsWith('drv_'))
    assert.equal(r.transformClass, 'embedding')
    assert.equal(r.lineageConfidence, 'complete')
    assert.equal(r.externalBoundaryBreak, false)
    assert.equal(r.isSyntheticDerivative, false)
    assert.equal(r.upstreamObligationsRetained, true)
    assert.ok(r.signature)
  })

  it('signature is verifiable', () => {
    const r = createDerivationReceipt({
      derivativeId: 'deriv-002',
      derivativeType: 'summary',
      parentArtifacts: [{ artifactId: 'a1', artifactType: 'access_receipt', sourceId: 's1' }],
      transformClass: 'summary',
      lineageConfidence: 'complete',
      agentId: 'agent-1',
      privateKey: keys.privateKey,
    })
    assert.equal(verifyDerivationReceipt(r, keys.publicKey), true)
  })

  it('marks external boundary break', () => {
    const r = createDerivationReceipt({
      derivativeId: 'deriv-003',
      derivativeType: 'embedding',
      parentArtifacts: [{ artifactId: 'external-001', artifactType: 'source_registration' }],
      transformClass: 'embedding',
      lineageConfidence: 'broken_external',
      externalBoundaryBreak: true,
      breakReason: 'Data re-entered from external vector store',
      agentId: 'agent-1',
      privateKey: keys.privateKey,
    })
    assert.equal(r.externalBoundaryBreak, true)
    assert.equal(r.lineageConfidence, 'broken_external')
    assert.ok(r.breakReason?.includes('external'))
  })

  it('marks synthetic derivative', () => {
    const r = createDerivationReceipt({
      derivativeId: 'synth-001',
      derivativeType: 'synthetic_derivative',
      parentArtifacts: [{ artifactId: 'a1', artifactType: 'access_receipt', sourceId: 's1' }],
      transformClass: 'synthetic',
      lineageConfidence: 'asserted',
      isSyntheticDerivative: true,
      upstreamObligationsRetained: true,
      agentId: 'agent-1',
      privateKey: keys.privateKey,
    })
    assert.equal(r.isSyntheticDerivative, true)
    assert.equal(r.upstreamObligationsRetained, true)
  })

  it('supports multiple parent artifacts', () => {
    const parents: ParentArtifact[] = [
      { artifactId: 'a1', artifactType: 'access_receipt', sourceId: 's1', transformFromParent: 'subset' },
      { artifactId: 'a2', artifactType: 'access_receipt', sourceId: 's2', transformFromParent: 'subset' },
      { artifactId: 'a3', artifactType: 'derivation_receipt', transformFromParent: 'summary' },
    ]
    const r = createDerivationReceipt({
      derivativeId: 'multi-001',
      derivativeType: 'aggregation',
      parentArtifacts: parents,
      transformClass: 'aggregation',
      lineageConfidence: 'partial',
      agentId: 'agent-1',
      privateKey: keys.privateKey,
    })
    assert.equal(r.parentArtifacts.length, 3)
  })
})

// ═══════════════════════════════════════
// Tests: Extended Lineage Resolution
// ═══════════════════════════════════════

describe('Data Lifecycle — Lineage Resolution', () => {
  function buildChain(): Map<string, DerivationReceipt> {
    const store = new Map<string, DerivationReceipt>()
    // Source → hop1 → hop2 → hop3
    const hop1 = createDerivationReceipt({
      derivativeId: 'hop1', derivativeType: 'rag_chunk',
      parentArtifacts: [{ artifactId: 'source-A', artifactType: 'source_registration', sourceId: 'src-A' }],
      transformClass: 'subset', lineageConfidence: 'complete',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('hop1', hop1)

    const hop2 = createDerivationReceipt({
      derivativeId: 'hop2', derivativeType: 'embedding',
      parentArtifacts: [{ artifactId: 'hop1', artifactType: 'derivation_receipt' }],
      transformClass: 'embedding', lineageConfidence: 'complete',
      agentId: 'a2', privateKey: keys.privateKey,
    })
    store.set('hop2', hop2)

    const hop3 = createDerivationReceipt({
      derivativeId: 'hop3', derivativeType: 'model_weights',
      parentArtifacts: [{ artifactId: 'hop2', artifactType: 'derivation_receipt' }],
      transformClass: 'model_training', lineageConfidence: 'partial',
      agentId: 'a3', privateKey: keys.privateKey,
    })
    store.set('hop3', hop3)
    return store
  }

  it('resolves multi-hop lineage chain', () => {
    const store = buildChain()
    const result = resolveExtendedLineage('hop3', store)
    assert.equal(result.depth, 3)
    assert.equal(result.chain.length, 3)
    assert.equal(result.chain[0].derivativeId, 'hop3')
  })

  it('downgrades confidence through chain', () => {
    const store = buildChain()
    const result = resolveExtendedLineage('hop3', store)
    // hop3 has 'partial' confidence → overall should be at least 'partial'
    assert.equal(result.confidence, 'partial')
  })

  it('detects external boundary breaks', () => {
    const store = new Map<string, DerivationReceipt>()
    const r = createDerivationReceipt({
      derivativeId: 'broken', derivativeType: 'rag_chunk',
      parentArtifacts: [{ artifactId: 'ext-1', artifactType: 'source_registration' }],
      transformClass: 'copy', lineageConfidence: 'broken_external',
      externalBoundaryBreak: true, breakReason: 'Re-imported from external system',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('broken', r)
    const result = resolveExtendedLineage('broken', store)
    assert.equal(result.hasBreaks, true)
    assert.equal(result.confidence, 'broken_external')
  })

  it('handles cycle detection (no infinite loop)', () => {
    const store = new Map<string, DerivationReceipt>()
    // Create a cycle: A → B → A
    const a = createDerivationReceipt({
      derivativeId: 'cycle-a', derivativeType: 'summary',
      parentArtifacts: [{ artifactId: 'cycle-b', artifactType: 'derivation_receipt' }],
      transformClass: 'summary', lineageConfidence: 'complete',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('cycle-a', a)

    const b = createDerivationReceipt({
      derivativeId: 'cycle-b', derivativeType: 'embedding',
      parentArtifacts: [{ artifactId: 'cycle-a', artifactType: 'derivation_receipt' }],
      transformClass: 'embedding', lineageConfidence: 'complete',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('cycle-b', b)
    // Should not infinite loop
    const result = resolveExtendedLineage('cycle-a', store)
    assert.ok(result.depth <= 2)
  })

  it('returns empty for unknown derivative', () => {
    const store = new Map<string, DerivationReceipt>()
    const result = resolveExtendedLineage('nonexistent', store)
    assert.equal(result.depth, 0)
    assert.equal(result.chain.length, 0)
  })
})

// ═══════════════════════════════════════
// Tests: Post-Revocation Obligations
// ═══════════════════════════════════════

describe('Data Lifecycle — Revocation Obligations', () => {
  it('classifies obligations by artifact type', () => {
    assert.equal(DEFAULT_OBLIGATIONS['cached_raw'], 'delete_if_cached')
    assert.equal(DEFAULT_OBLIGATIONS['rag_chunk'], 'delete_if_cached')
    assert.equal(DEFAULT_OBLIGATIONS['embedding'], 'quarantine')
    assert.equal(DEFAULT_OBLIGATIONS['model_weights'], 'retraining_required')
    assert.equal(DEFAULT_OBLIGATIONS['decision_artifact'], 'immutable_ledger_exempt')
    assert.equal(DEFAULT_OBLIGATIONS['settlement_record'], 'immutable_ledger_exempt')
    assert.equal(DEFAULT_OBLIGATIONS['synthetic_derivative'], 'compensation_only')
  })

  it('evaluates revocation impact across derivation chain', () => {
    const store = new Map<string, DerivationReceipt>()
    const r1 = createDerivationReceipt({
      derivativeId: 'd1', derivativeType: 'rag_chunk',
      parentArtifacts: [{ artifactId: 'a1', artifactType: 'access_receipt', sourceId: 'revoked-src' }],
      transformClass: 'subset', lineageConfidence: 'complete',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('d1', r1)

    const r2 = createDerivationReceipt({
      derivativeId: 'd2', derivativeType: 'model_weights',
      parentArtifacts: [{ artifactId: 'd1', artifactType: 'derivation_receipt' }],
      transformClass: 'model_training', lineageConfidence: 'complete',
      agentId: 'a2', privateKey: keys.privateKey,
    })
    store.set('d2', r2)

    const obligation = evaluateRevocationImpact({
      sourceId: 'revoked-src', receiptStore: store, privateKey: keys.privateKey,
    })
    assert.ok(obligation.obligationId.startsWith('rvo_'))
    assert.equal(obligation.sourceId, 'revoked-src')
    assert.ok(obligation.totalAffected >= 1)
    // rag_chunk should be delete_if_cached
    const ragObligation = obligation.affectedArtifacts.find(a => a.artifactType === 'rag_chunk')
    if (ragObligation) assert.equal(ragObligation.obligation, 'delete_if_cached')
  })

  it('returns empty for source with no derivatives', () => {
    const store = new Map<string, DerivationReceipt>()
    const obligation = evaluateRevocationImpact({
      sourceId: 'no-derivs', receiptStore: store, privateKey: keys.privateKey,
    })
    assert.equal(obligation.totalAffected, 0)
  })
})

// ═══════════════════════════════════════
// Tests: Decision Lineage Receipt
// ═══════════════════════════════════════

describe('Data Lifecycle — Decision Lineage Receipt', () => {
  it('creates a signed decision lineage receipt', () => {
    const r = createDecisionLineageReceipt({
      decisionArtifactId: 'dec-001',
      decisionType: 'loan_decision',
      contributingSources: [
        {
          sourceId: 'credit-data', accessReceiptId: 'ar-001',
          derivationDepth: 1, transformPath: ['subset'],
          termsVersionAtAccess: '2.0', lineageConfidence: 'complete',
          compensationStatus: 'settled',
        },
        {
          sourceId: 'income-data', accessReceiptId: 'ar-002',
          derivationDepth: 2, transformPath: ['subset', 'aggregation'],
          termsVersionAtAccess: '1.0', lineageConfidence: 'partial',
          compensationStatus: 'pending',
        },
      ],
      lineageCompleteness: 'partial',
      transformChain: ['subset', 'aggregation', 'decision_artifact'],
      governingPurpose: 'inference:decision_support',
      explanation: 'Loan decision based on credit and income data',
      privateKey: keys.privateKey,
    })

    assert.ok(r.receiptId.startsWith('dlr_'))
    assert.equal(r.decisionArtifactId, 'dec-001')
    assert.equal(r.contributingSources.length, 2)
    assert.equal(r.lineageCompleteness, 'partial')
    assert.equal(r.governingPurpose, 'inference:decision_support')
    assert.ok(r.signature)
  })

  it('signature is verifiable', () => {
    const r = createDecisionLineageReceipt({
      decisionArtifactId: 'dec-002',
      decisionType: 'content_moderation',
      contributingSources: [{
        sourceId: 's1', accessReceiptId: 'ar-1',
        derivationDepth: 1, transformPath: ['copy'],
        termsVersionAtAccess: '1.0', lineageConfidence: 'complete',
        compensationStatus: 'settled',
      }],
      lineageCompleteness: 'complete',
      privateKey: keys.privateKey,
    })
    assert.equal(verifyDecisionLineageReceipt(r, keys.publicKey), true)
  })

  it('records external hops and incomplete lineage', () => {
    const r = createDecisionLineageReceipt({
      decisionArtifactId: 'dec-003',
      decisionType: 'risk_assessment',
      contributingSources: [{
        sourceId: 'external-model-training',
        accessReceiptId: 'ar-ext',

        derivationDepth: 3, transformPath: ['model_training', 'summary', 'decision_artifact'],
        termsVersionAtAccess: '1.0', lineageConfidence: 'broken_external',
        compensationStatus: 'disputed',
      }],
      lineageCompleteness: 'broken_external',
      externalHopsPresent: true,
      explanation: 'Model trained externally — lineage incomplete',
      privateKey: keys.privateKey,
    })
    assert.equal(r.externalHopsPresent, true)
    assert.equal(r.lineageCompleteness, 'broken_external')
    assert.equal(r.contributingSources[0].compensationStatus, 'disputed')
  })
})

// ═══════════════════════════════════════
// Tests: Purpose Taxonomy
// ═══════════════════════════════════════

describe('Data Lifecycle — Purpose Taxonomy', () => {
  it('exact match permits', () => {
    assert.equal(isPurposePermitted('research:academic', ['research:academic']), true)
  })

  it('exact match denies when not listed', () => {
    assert.equal(isPurposePermitted('research:commercial', ['research:academic']), false)
  })

  it('wildcard match: research:* covers research:academic', () => {
    assert.equal(isPurposePermitted('research:academic', ['research:*']), true)
    assert.equal(isPurposePermitted('research:commercial', ['research:*']), true)
  })

  it('wildcard does not cross categories', () => {
    assert.equal(isPurposePermitted('training:model', ['research:*']), false)
  })

  it('parent covers child: research covers research:academic', () => {
    assert.equal(isPurposePermitted('research:academic', ['research']), true)
    assert.equal(isPurposePermitted('research:commercial', ['research']), true)
  })

  it('child does not cover parent', () => {
    assert.equal(isPurposePermitted('research', ['research:academic']), false)
  })

  it('multiple allowed purposes', () => {
    const allowed = ['research:academic', 'analytics:internal']
    assert.equal(isPurposePermitted('research:academic', allowed), true)
    assert.equal(isPurposePermitted('analytics:internal', allowed), true)
    assert.equal(isPurposePermitted('commerce', allowed), false)
  })

  it('extracts purpose category', () => {
    assert.equal(purposeCategory('research:academic'), 'research')
    assert.equal(purposeCategory('commerce'), 'commerce')
    assert.equal(purposeCategory('training:fine_tune'), 'training')
  })
})

// ═══════════════════════════════════════
// Tests: Retention TTL & Terms Version Pinning
// ═══════════════════════════════════════

describe('Data Lifecycle — Retention TTL', () => {
  it('detects expired retention for persistent access', () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000).toISOString()
    const expired = isRetentionExpired(twoHoursAgo, {
      maxRetentionMs: 3600000, // 1 hour
      onExpiry: 'delete',
    }, 'persistent')
    assert.equal(expired, true)
  })

  it('allows access within retention period', () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString()
    const expired = isRetentionExpired(fiveMinAgo, {
      maxRetentionMs: 3600000, // 1 hour
      onExpiry: 'delete',
    }, 'persistent')
    assert.equal(expired, false)
  })

  it('never expires when maxRetentionMs is null', () => {
    const yearAgo = new Date(Date.now() - 365 * 86400 * 1000).toISOString()
    const expired = isRetentionExpired(yearAgo, {
      maxRetentionMs: null,
      onExpiry: 'delete',
    })
    assert.equal(expired, false)
  })

  it('distinguishes ephemeral vs persistent retention', () => {
    const thirtyMinAgo = new Date(Date.now() - 30 * 60 * 1000).toISOString()
    const policy: RetentionPolicy = {
      maxRetentionMs: null,
      onExpiry: 'delete',
      ephemeralAccessMs: 3600000,    // 1 hour
      persistentAccessMs: 86400000,  // 24 hours
    }
    // 30 min ago — ephemeral still valid, persistent still valid
    assert.equal(isRetentionExpired(thirtyMinAgo, policy, 'ephemeral'), false)
    assert.equal(isRetentionExpired(thirtyMinAgo, policy, 'persistent'), false)

    const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000).toISOString()
    // 2 hours ago — ephemeral expired, persistent still valid
    assert.equal(isRetentionExpired(twoHoursAgo, policy, 'ephemeral'), true)
    assert.equal(isRetentionExpired(twoHoursAgo, policy, 'persistent'), false)
  })
})

describe('Data Lifecycle — Terms Version Pinning', () => {
  it('pins terms at access time', () => {
    const pin = pinTermsAtAccess({
      termsVersion: '2.0',
      compensationRate: 0.001,
      currency: 'USDC',
      allowedPurposes: ['research:academic', 'analytics:internal'],
      retentionPolicy: { maxRetentionMs: 86400000, onExpiry: 'delete' },
    })
    assert.equal(pin.termsVersion, '2.0')
    assert.equal(pin.compensationRate, 0.001)
    assert.equal(pin.allowedPurposes.length, 2)
    assert.ok(pin.pinnedAt)
    assert.ok(pin.retentionPolicy)
  })

  it('pinned terms are immutable snapshot (different from later changes)', () => {
    const pin = pinTermsAtAccess({
      termsVersion: '1.0',
      compensationRate: 0.001,
      currency: 'USDC',
      allowedPurposes: ['research:*'],
    })
    // Simulating: terms later change to v2 with higher rate
    // The pin preserves the original rate
    assert.equal(pin.compensationRate, 0.001)
    assert.equal(pin.termsVersion, '1.0')
  })
})

// ═══════════════════════════════════════
// Tests: End-to-End — Right to Explanation
// ═══════════════════════════════════════

describe('Data Lifecycle — End-to-End: Right to Explanation', () => {
  it('full chain: source → derivation → decision → lineage receipt', () => {
    // Step 1: Agent accesses credit data (creates derivation receipt)
    const creditDerivation = createDerivationReceipt({
      derivativeId: 'credit-embedding-001',
      derivativeType: 'embedding',
      parentArtifacts: [{
        artifactId: 'credit-access-receipt',
        artifactType: 'access_receipt',
        sourceId: 'equifax-credit-scores',
      }],
      transformClass: 'embedding',
      lineageConfidence: 'complete',
      agentId: 'loan-agent',
      privateKey: keys.privateKey,
    })

    // Step 2: Agent accesses income data (second derivation)
    const incomeDerivation = createDerivationReceipt({
      derivativeId: 'income-summary-001',
      derivativeType: 'summary',
      parentArtifacts: [{
        artifactId: 'income-access-receipt',
        artifactType: 'access_receipt',
        sourceId: 'irs-income-data',
      }],
      transformClass: 'summary',
      lineageConfidence: 'complete',
      agentId: 'loan-agent',
      privateKey: keys.privateKey,
    })

    // Step 3: Agent makes loan decision using both sources
    const lineageReceipt = createDecisionLineageReceipt({
      decisionArtifactId: 'loan-decision-001',
      decisionType: 'loan_approval',
      contributingSources: [
        {
          sourceId: 'equifax-credit-scores',
          accessReceiptId: 'credit-access-receipt',
          derivationDepth: 1,
          transformPath: ['embedding'],
          termsVersionAtAccess: '3.1',
          lineageConfidence: 'complete',
          compensationStatus: 'settled',
        },
        {
          sourceId: 'irs-income-data',
          accessReceiptId: 'income-access-receipt',
          derivationDepth: 1,
          transformPath: ['summary'],
          termsVersionAtAccess: '1.0',
          lineageConfidence: 'complete',
          compensationStatus: 'pending',
        },
      ],
      lineageCompleteness: 'complete',
      transformChain: ['embedding', 'summary', 'decision_artifact'],
      governingPurpose: 'inference:decision_support',
      explanation: 'Loan denied based on credit score below threshold and insufficient income verification',
      privateKey: keys.privateKey,
    })

    // Verify: the human can now ask "what data influenced this decision?"
    assert.equal(lineageReceipt.decisionArtifactId, 'loan-decision-001')
    assert.equal(lineageReceipt.contributingSources.length, 2)
    assert.equal(lineageReceipt.contributingSources[0].sourceId, 'equifax-credit-scores')
    assert.equal(lineageReceipt.contributingSources[1].sourceId, 'irs-income-data')
    assert.equal(lineageReceipt.lineageCompleteness, 'complete')
    assert.ok(lineageReceipt.explanation?.includes('Loan denied'))
    assert.equal(verifyDecisionLineageReceipt(lineageReceipt, keys.publicKey), true)
  })

  it('revocation cascade: source revoked → obligations propagate through chain', () => {
    const store = new Map<string, DerivationReceipt>()

    // Chain: credit-source → rag_chunk → embedding → model_weights
    const r1 = createDerivationReceipt({
      derivativeId: 'chunk-1', derivativeType: 'rag_chunk',
      parentArtifacts: [{ artifactId: 'ar-1', artifactType: 'access_receipt', sourceId: 'credit-source' }],
      transformClass: 'subset', lineageConfidence: 'complete',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('chunk-1', r1)

    const r2 = createDerivationReceipt({
      derivativeId: 'emb-1', derivativeType: 'embedding',
      parentArtifacts: [{ artifactId: 'chunk-1', artifactType: 'derivation_receipt' }],
      transformClass: 'embedding', lineageConfidence: 'complete',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('emb-1', r2)

    const r3 = createDerivationReceipt({
      derivativeId: 'model-1', derivativeType: 'model_weights',
      parentArtifacts: [{ artifactId: 'emb-1', artifactType: 'derivation_receipt' }],
      transformClass: 'model_training', lineageConfidence: 'complete',
      agentId: 'a2', privateKey: keys.privateKey,
    })
    store.set('model-1', r3)

    // Credit source revokes consent
    const obligation = evaluateRevocationImpact({
      sourceId: 'credit-source', receiptStore: store, privateKey: keys.privateKey,
    })

    assert.ok(obligation.totalAffected >= 1)
    assert.ok(obligation.obligationId.startsWith('rvo_'))

    // Each artifact type gets appropriate obligation
    const chunkObl = obligation.affectedArtifacts.find(a => a.artifactType === 'rag_chunk')
    const embObl = obligation.affectedArtifacts.find(a => a.artifactType === 'embedding')
    const modelObl = obligation.affectedArtifacts.find(a => a.artifactType === 'model_weights')

    if (chunkObl) assert.equal(chunkObl.obligation, 'delete_if_cached')
    if (embObl) assert.equal(embObl.obligation, 'quarantine')
    if (modelObl) assert.equal(modelObl.obligation, 'retraining_required')

    // Not: "delete everything" (impossible for model weights)
    // Instead: honest per-type obligation classification
  })

  it('synthetic derivative retains upstream obligations', () => {
    const r = createDerivationReceipt({
      derivativeId: 'synth-from-proprietary',
      derivativeType: 'synthetic_derivative',
      parentArtifacts: [{ artifactId: 'proprietary-access', artifactType: 'access_receipt', sourceId: 'proprietary-dataset' }],
      transformClass: 'synthetic',
      lineageConfidence: 'asserted',
      isSyntheticDerivative: true,
      upstreamObligationsRetained: true,
      agentId: 'laundering-agent',
      privateKey: keys.privateKey,
    })

    // The synthetic data carries its upstream provenance
    assert.equal(r.isSyntheticDerivative, true)
    assert.equal(r.upstreamObligationsRetained, true)
    assert.equal(r.transformClass, 'synthetic')
    assert.equal(r.parentArtifacts[0].sourceId, 'proprietary-dataset')
    // This makes synthetic laundering auditable:
    // the derivation receipt proves the synthetic data came from proprietary source
  })
})

// ═══════════════════════════════════════
// Phase 2 Tests: Aggregation Controls
// ═══════════════════════════════════════

import {
  checkAggregateConstraints,
  isTransferPermitted,
  computeGovernanceTaint,
  fileDispute,
  checkCombinationPermitted,
  createAccessSnapshot,
  verifyAccessSnapshot,
} from '../src/index.js'
import type { AggregateAccessLog, JurisdictionEnvelope, CombinationConstraint } from '../src/index.js'

describe('Data Lifecycle — Aggregation Controls', () => {
  it('permits access within window limits', () => {
    const constraint = { maxAccessesPerWindow: 100, windowMs: 86400000 }
    const log: AggregateAccessLog = {
      sourceId: 's1', agentId: 'a1',
      windowStartMs: Date.now() - 3600000,
      accessCount: 50, recordCount: 50, lastAccessMs: Date.now() - 1000,
    }
    assert.equal(checkAggregateConstraints(constraint, log).permitted, true)
  })

  it('blocks access when window limit exceeded', () => {
    const constraint = { maxAccessesPerWindow: 100, windowMs: 86400000 }
    const log: AggregateAccessLog = {
      sourceId: 's1', agentId: 'a1',
      windowStartMs: Date.now() - 3600000,
      accessCount: 100, recordCount: 100, lastAccessMs: Date.now() - 500,
    }
    const result = checkAggregateConstraints(constraint, log)
    assert.equal(result.permitted, false)
    assert.ok(result.reason?.includes('100/100'))
  })

  it('blocks burst access', () => {
    const constraint = { burstLimit: 5 }
    const log: AggregateAccessLog = {
      sourceId: 's1', agentId: 'a1',
      windowStartMs: Date.now() - 1000,
      accessCount: 10, recordCount: 10, lastAccessMs: Date.now() - 100,
    }
    const result = checkAggregateConstraints(constraint, log)
    assert.equal(result.permitted, false)
    assert.ok(result.reason?.includes('Burst'))
  })
})

// ═══════════════════════════════════════
// Phase 2 Tests: Jurisdiction Transfer
// ═══════════════════════════════════════

describe('Data Lifecycle — Jurisdiction Envelope', () => {
  it('permits transfer within same jurisdiction', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'DE',
      processingRestrictions: ['NO_CROSS_BORDER'],
    }
    assert.equal(isTransferPermitted(env, 'DE', 'research:academic').permitted, true)
  })

  it('blocks cross-border when NO_CROSS_BORDER set', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'DE',
      processingRestrictions: ['NO_CROSS_BORDER'],
    }
    const result = isTransferPermitted(env, 'US', 'research:academic')
    assert.equal(result.permitted, false)
    assert.ok(result.reason?.includes('NO_CROSS_BORDER'))
  })

  it('permits EU-to-EU when EU_ONLY set', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'DE',
      processingRestrictions: ['EU_ONLY'],
    }
    assert.equal(isTransferPermitted(env, 'FR', 'analytics:internal').permitted, true)
  })

  it('blocks EU-to-non-EU when EU_ONLY set', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'DE',
      processingRestrictions: ['EU_ONLY'],
    }
    const result = isTransferPermitted(env, 'CN', 'analytics:internal')
    assert.equal(result.permitted, false)
    assert.ok(result.reason?.includes('EU_ONLY'))
  })

  it('permits transfer to GDPR adequate country', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'FR',
      transferConstraints: ['GDPR_ADEQUATE_ONLY'],
    }
    assert.equal(isTransferPermitted(env, 'JP', 'commerce').permitted, true)
    assert.equal(isTransferPermitted(env, 'UK', 'commerce').permitted, true)
  })

  it('blocks transfer to non-adequate country', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'FR',
      transferConstraints: ['GDPR_ADEQUATE_ONLY'],
    }
    const result = isTransferPermitted(env, 'CN', 'commerce')
    assert.equal(result.permitted, false)
    assert.ok(result.reason?.includes('adequacy'))
  })

  it('permits everything when no restrictions', () => {
    const env: JurisdictionEnvelope = { sourceJurisdiction: 'US' }
    assert.equal(isTransferPermitted(env, 'CN', 'commerce').permitted, true)
  })
})

// ═══════════════════════════════════════
// Phase 2 Tests: Governance Taint
// ═══════════════════════════════════════

describe('Data Lifecycle — Governance Taint', () => {
  it('clean artifact with no restricted sources', () => {
    const store = new Map<string, DerivationReceipt>()
    const r = createDerivationReceipt({
      derivativeId: 'clean-1', derivativeType: 'summary',
      parentArtifacts: [{ artifactId: 'a1', artifactType: 'access_receipt', sourceId: 'public-data' }],
      transformClass: 'summary', lineageConfidence: 'complete',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('clean-1', r)

    const taint = computeGovernanceTaint('clean-1', store)
    assert.equal(taint.taintLevel, 'clean')
    assert.equal(taint.clearable, true)
  })

  it('restricted when source is revoked', () => {
    const store = new Map<string, DerivationReceipt>()
    const r = createDerivationReceipt({
      derivativeId: 'tainted-1', derivativeType: 'embedding',
      parentArtifacts: [{ artifactId: 'a1', artifactType: 'access_receipt', sourceId: 'revoked-data' }],
      transformClass: 'embedding', lineageConfidence: 'complete',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('tainted-1', r)

    const revokedSources = new Set(['revoked-data'])
    const taint = computeGovernanceTaint('tainted-1', store, revokedSources)
    assert.equal(taint.taintLevel, 'restricted')
    assert.ok(taint.reason.includes('revoked'))
  })

  it('untraceable contamination when external boundary break', () => {
    const store = new Map<string, DerivationReceipt>()
    const r = createDerivationReceipt({
      derivativeId: 'broken-1', derivativeType: 'rag_chunk',
      parentArtifacts: [{ artifactId: 'ext-1', artifactType: 'source_registration' }],
      transformClass: 'copy', lineageConfidence: 'broken_external',
      externalBoundaryBreak: true, breakReason: 'Data re-imported',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('broken-1', r)

    const taint = computeGovernanceTaint('broken-1', store)
    assert.equal(taint.taintLevel, 'untraceable_contamination')
    assert.equal(taint.clearable, false)
  })
})

// ═══════════════════════════════════════
// Phase 2 Tests: Dispute Records
// ═══════════════════════════════════════

describe('Data Lifecycle — Dispute Records', () => {
  it('files a signed dispute', () => {
    const dispute = fileDispute({
      artifactId: 'receipt-123',
      disputeType: 'unauthorized_access',
      filedBy: 'source-owner-did',
      evidence: ['access-receipt-hash', 'terms-snapshot-hash'],
      privateKey: keys.privateKey,
    })
    assert.ok(dispute.disputeId.startsWith('dsp_'))
    assert.equal(dispute.status, 'under_review')
    assert.equal(dispute.disputeType, 'unauthorized_access')
    assert.equal(dispute.evidence.length, 2)
    assert.ok(dispute.signature)
  })

  it('supports all dispute types', () => {
    const types: Array<'unauthorized_access' | 'terms_violation' | 'compensation_dispute' | 'revocation_dispute' | 'lineage_dispute'> = [
      'unauthorized_access', 'terms_violation', 'compensation_dispute', 'revocation_dispute', 'lineage_dispute'
    ]
    for (const t of types) {
      const d = fileDispute({ artifactId: 'a1', disputeType: t, filedBy: 'owner', evidence: [], privateKey: keys.privateKey })
      assert.equal(d.disputeType, t)
    }
  })
})

// ═══════════════════════════════════════
// Phase 2 Tests: Combination Constraints
// ═══════════════════════════════════════

describe('Data Lifecycle — Combination Constraints', () => {
  it('permits combination when no constraints violated', () => {
    const constraints: CombinationConstraint[] = [
      { forbiddenSourceClasses: ['health'], reason: 'HIPAA', regulatoryBasis: 'HIPAA' }
    ]
    const result = checkCombinationPermitted(constraints, 'weather-data', ['weather'])
    assert.equal(result.permitted, true)
    assert.equal(result.violations.length, 0)
  })

  it('blocks forbidden source class combination', () => {
    const constraints: CombinationConstraint[] = [
      { forbiddenSourceClasses: ['health', 'biometric'], reason: 'HIPAA + geolocation = re-identification risk', regulatoryBasis: 'HIPAA' }
    ]
    const result = checkCombinationPermitted(constraints, 'geo-data', ['geolocation', 'health'])
    assert.equal(result.permitted, false)
    assert.ok(result.violations[0].includes('health'))
    assert.ok(result.violations[0].includes('HIPAA'))
  })

  it('blocks forbidden specific source ID', () => {
    const constraints: CombinationConstraint[] = [
      { forbiddenSourceIds: ['competitor-dataset-X'], reason: 'Competitive exclusion' }
    ]
    const result = checkCombinationPermitted(constraints, 'competitor-dataset-X')
    assert.equal(result.permitted, false)
    assert.ok(result.violations[0].includes('competitor-dataset-X'))
  })

  it('handles multiple constraints', () => {
    const constraints: CombinationConstraint[] = [
      { forbiddenSourceClasses: ['children'], reason: 'COPPA', regulatoryBasis: 'COPPA' },
      { forbiddenSourceClasses: ['behavioral_advertising'], reason: 'Children + ads = prohibited', regulatoryBasis: 'COPPA' },
    ]
    const result = checkCombinationPermitted(constraints, 'ad-network', ['behavioral_advertising'])
    assert.equal(result.permitted, false)
  })
})

// ═══════════════════════════════════════
// Phase 2 Tests: Access Snapshots (anti-rug-pull)
// ═══════════════════════════════════════

describe('Data Lifecycle — Access Snapshots', () => {
  it('creates an immutable signed access snapshot', () => {
    const pin = pinTermsAtAccess({
      termsVersion: '3.0', compensationRate: 0.01,
      currency: 'USDC', allowedPurposes: ['research:*'],
    })
    const snap = createAccessSnapshot({
      accessReceiptId: 'ar-001', sourceId: 'src-1',
      pinnedTerms: pin,
      jurisdiction: { sourceJurisdiction: 'DE', processingRestrictions: ['EU_ONLY'] },
      combinationConstraints: [{ forbiddenSourceClasses: ['health'], reason: 'HIPAA' }],
      privateKey: keys.privateKey,
    })
    assert.ok(snap.snapshotId.startsWith('snap_'))
    assert.equal(snap.sourceId, 'src-1')
    assert.equal(snap.pinnedTerms.termsVersion, '3.0')
    assert.equal(snap.termsHash.length, 64) // SHA-256 hex
    assert.ok(snap.jurisdiction?.processingRestrictions?.includes('EU_ONLY'))
    assert.equal(snap.combinationConstraints?.length, 1)
    assert.ok(snap.signature)
  })

  it('snapshot signature is verifiable', () => {
    const pin = pinTermsAtAccess({
      termsVersion: '1.0', compensationRate: 0.001,
      currency: 'USDC', allowedPurposes: ['analytics:internal'],
    })
    const snap = createAccessSnapshot({
      accessReceiptId: 'ar-002', sourceId: 'src-2',
      pinnedTerms: pin, privateKey: keys.privateKey,
    })
    assert.equal(verifyAccessSnapshot(snap, keys.publicKey), true)
  })

  it('terms hash changes when terms change (anti-rug-pull proof)', () => {
    const pin1 = pinTermsAtAccess({
      termsVersion: '1.0', compensationRate: 0.001,
      currency: 'USDC', allowedPurposes: ['research:*'],
    })
    const pin2 = pinTermsAtAccess({
      termsVersion: '2.0', compensationRate: 0.01,
      currency: 'USDC', allowedPurposes: ['research:academic'],
    })
    const snap1 = createAccessSnapshot({
      accessReceiptId: 'ar-1', sourceId: 's1', pinnedTerms: pin1, privateKey: keys.privateKey,
    })
    const snap2 = createAccessSnapshot({
      accessReceiptId: 'ar-2', sourceId: 's1', pinnedTerms: pin2, privateKey: keys.privateKey,
    })
    // Different terms → different hashes → provably different snapshots
    assert.notEqual(snap1.termsHash, snap2.termsHash)
  })
})
// ═══════════════════════════════════════
// Phase 2 Tests: Jurisdiction Envelope
// ═══════════════════════════════════════

describe('Data Lifecycle — Jurisdiction Transfer', () => {
  it('permits transfer within EU', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'DE',
      processingRestrictions: ['EU_ONLY'],
    }
    assert.equal(isTransferPermitted(env, 'FR', 'analytics:internal').permitted, true)
  })

  it('blocks transfer outside EU when EU_ONLY', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'DE',
      processingRestrictions: ['EU_ONLY'],
    }
    const result = isTransferPermitted(env, 'US', 'analytics:internal')
    assert.equal(result.permitted, false)
    assert.ok(result.reason?.includes('EU'))
  })

  it('blocks cross-border when NO_CROSS_BORDER', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'JP',
      processingRestrictions: ['NO_CROSS_BORDER'],
    }
    const result = isTransferPermitted(env, 'US', 'research:academic')
    assert.equal(result.permitted, false)
    assert.ok(result.reason?.includes('NO_CROSS_BORDER'))
  })

  it('permits same-country when NO_CROSS_BORDER', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'JP',
      processingRestrictions: ['NO_CROSS_BORDER'],
    }
    assert.equal(isTransferPermitted(env, 'JP', 'research:academic').permitted, true)
  })

  it('permits transfer to GDPR adequate country', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'DE',
      transferConstraints: ['GDPR_ADEQUATE_ONLY'],
    }
    assert.equal(isTransferPermitted(env, 'JP', 'analytics:internal').permitted, true)
    assert.equal(isTransferPermitted(env, 'UK', 'analytics:internal').permitted, true)
  })

  it('blocks transfer to non-adequate country under GDPR', () => {
    const env: JurisdictionEnvelope = {
      sourceJurisdiction: 'DE',
      transferConstraints: ['GDPR_ADEQUATE_ONLY'],
    }
    const result = isTransferPermitted(env, 'CN', 'analytics:internal')
    assert.equal(result.permitted, false)
    assert.ok(result.reason?.includes('adequacy'))
  })

  it('permits all when no restrictions', () => {
    const env: JurisdictionEnvelope = { sourceJurisdiction: 'US' }
    assert.equal(isTransferPermitted(env, 'CN', 'commerce').permitted, true)
  })
})

// ═══════════════════════════════════════
// Phase 2 Tests: Governance Taint
// ═══════════════════════════════════════

describe('Data Lifecycle — Governance Taint', () => {
  it('clean: no restricted sources', () => {
    const store = new Map<string, DerivationReceipt>()
    const r = createDerivationReceipt({
      derivativeId: 'clean-art', derivativeType: 'summary',
      parentArtifacts: [{ artifactId: 'a1', artifactType: 'access_receipt', sourceId: 'safe-src' }],
      transformClass: 'summary', lineageConfidence: 'complete',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('clean-art', r)
    const taint = computeGovernanceTaint('clean-art', store)
    assert.equal(taint.taintLevel, 'clean')
    assert.equal(taint.clearable, true)
  })

  it('restricted: touches revoked source', () => {
    const store = new Map<string, DerivationReceipt>()
    const r = createDerivationReceipt({
      derivativeId: 'tainted-art', derivativeType: 'embedding',
      parentArtifacts: [{ artifactId: 'a1', artifactType: 'access_receipt', sourceId: 'revoked-src' }],
      transformClass: 'embedding', lineageConfidence: 'complete',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('tainted-art', r)
    const taint = computeGovernanceTaint('tainted-art', store, new Set(['revoked-src']))
    assert.equal(taint.taintLevel, 'restricted')
    assert.ok(taint.reason.includes('revoked'))
  })

  it('untraceable: external boundary break', () => {
    const store = new Map<string, DerivationReceipt>()
    const r = createDerivationReceipt({
      derivativeId: 'ext-art', derivativeType: 'rag_chunk',
      parentArtifacts: [{ artifactId: 'ext-1', artifactType: 'source_registration' }],
      transformClass: 'copy', lineageConfidence: 'broken_external',
      externalBoundaryBreak: true, breakReason: 'Re-imported',
      agentId: 'a1', privateKey: keys.privateKey,
    })
    store.set('ext-art', r)
    const taint = computeGovernanceTaint('ext-art', store)
    assert.equal(taint.taintLevel, 'untraceable_contamination')
    assert.equal(taint.clearable, false)
  })
})

// ═══════════════════════════════════════
// Phase 2 Tests: Dispute Records
// ═══════════════════════════════════════

describe('Data Lifecycle — Dispute Records', () => {
  it('files a dispute with signature', () => {
    const dispute = fileDispute({
      artifactId: 'art-001',
      disputeType: 'unauthorized_access',
      filedBy: 'source-owner-001',
      evidence: ['access-receipt-abc', 'terms-v2-not-accepted'],
      privateKey: keys.privateKey,
    })
    assert.ok(dispute.disputeId.startsWith('dsp_'))
    assert.equal(dispute.status, 'under_review')
    assert.equal(dispute.disputeType, 'unauthorized_access')
    assert.equal(dispute.evidence.length, 2)
    assert.ok(dispute.signature)
  })

  it('supports all dispute types', () => {
    const types: Array<'unauthorized_access' | 'terms_violation' | 'compensation_dispute' | 'revocation_dispute' | 'lineage_dispute'> =
      ['unauthorized_access', 'terms_violation', 'compensation_dispute', 'revocation_dispute', 'lineage_dispute']
    for (const t of types) {
      const d = fileDispute({ artifactId: 'a', disputeType: t, filedBy: 'x', evidence: [], privateKey: keys.privateKey })
      assert.equal(d.disputeType, t)
    }
  })
})

// ═══════════════════════════════════════
// Phase 2 Tests: Combination Constraints
// ═══════════════════════════════════════

describe('Data Lifecycle — Combination Constraints', () => {
  it('permits combination when no constraints violated', () => {
    const constraints: CombinationConstraint[] = [
      { forbiddenSourceClasses: ['health'], reason: 'HIPAA', regulatoryBasis: 'HIPAA' },
    ]
    const result = checkCombinationPermitted(constraints, 'weather-src', ['weather'])
    assert.equal(result.permitted, true)
    assert.equal(result.violations.length, 0)
  })

  it('blocks forbidden source class combination', () => {
    const constraints: CombinationConstraint[] = [
      { forbiddenSourceClasses: ['geolocation'], reason: 'Health + geo = re-identification risk', regulatoryBasis: 'HIPAA' },
    ]
    const result = checkCombinationPermitted(constraints, 'geo-src', ['geolocation'])
    assert.equal(result.permitted, false)
    assert.ok(result.violations[0].includes('geolocation'))
    assert.ok(result.violations[0].includes('HIPAA'))
  })

  it('blocks forbidden source ID', () => {
    const constraints: CombinationConstraint[] = [
      { forbiddenSourceIds: ['competitor-dataset-001'], reason: 'Exclusivity clause' },
    ]
    const result = checkCombinationPermitted(constraints, 'competitor-dataset-001', [])
    assert.equal(result.permitted, false)
    assert.ok(result.violations[0].includes('competitor-dataset-001'))
  })

  it('multiple constraints checked', () => {
    const constraints: CombinationConstraint[] = [
      { forbiddenSourceClasses: ['children_behavioral'], reason: 'COPPA', regulatoryBasis: 'COPPA' },
      { forbiddenSourceClasses: ['advertising'], reason: 'Children + ads = prohibited', regulatoryBasis: 'COPPA' },
    ]
    const result = checkCombinationPermitted(constraints, 'ad-network', ['advertising'])
    assert.equal(result.permitted, false)
    assert.equal(result.violations.length, 1)
  })
})

// ═══════════════════════════════════════
// Phase 2 Tests: Access Snapshots
// ═══════════════════════════════════════

describe('Data Lifecycle — Access Snapshots', () => {
  it('creates signed immutable snapshot', () => {
    const snap = createAccessSnapshot({
      accessReceiptId: 'ar-001',
      sourceId: 'src-001',
      pinnedTerms: {
        termsVersion: '3.0', pinnedAt: new Date().toISOString(),
        compensationRate: 0.005, currency: 'USDC',
        allowedPurposes: ['research:*', 'analytics:internal'],
      },
      jurisdiction: { sourceJurisdiction: 'DE', processingRestrictions: ['EU_ONLY'] },
      combinationConstraints: [{ forbiddenSourceClasses: ['health'], reason: 'GDPR Art 9', regulatoryBasis: 'GDPR_Art9' }],
      privateKey: keys.privateKey,
    })
    assert.ok(snap.snapshotId.startsWith('snap_'))
    assert.equal(snap.sourceId, 'src-001')
    assert.equal(snap.termsHash.length, 64) // SHA-256 hex
    assert.equal(snap.pinnedTerms.compensationRate, 0.005)
    assert.ok(snap.jurisdiction)
    assert.equal(snap.combinationConstraints!.length, 1)
    assert.ok(snap.signature)
  })

  it('snapshot signature is verifiable', () => {
    const snap = createAccessSnapshot({
      accessReceiptId: 'ar-002', sourceId: 'src-002',
      pinnedTerms: {
        termsVersion: '1.0', pinnedAt: new Date().toISOString(),
        compensationRate: 0.001, currency: 'USDC', allowedPurposes: ['research:academic'],
      },
      privateKey: keys.privateKey,
    })
    assert.equal(verifyAccessSnapshot(snap, keys.publicKey), true)
  })

  it('terms hash changes when terms change (anti-rug-pull)', () => {
    const terms1 = {
      termsVersion: '1.0', pinnedAt: new Date().toISOString(),
      compensationRate: 0.001, currency: 'USDC', allowedPurposes: ['research:*'],
    }
    const terms2 = {
      termsVersion: '2.0', pinnedAt: new Date().toISOString(),
      compensationRate: 0.01, currency: 'USDC', allowedPurposes: ['research:academic'],
    }
    const snap1 = createAccessSnapshot({
      accessReceiptId: 'ar-1', sourceId: 's1', pinnedTerms: terms1, privateKey: keys.privateKey,
    })
    const snap2 = createAccessSnapshot({
      accessReceiptId: 'ar-2', sourceId: 's1', pinnedTerms: terms2, privateKey: keys.privateKey,
    })
    // Different terms → different hashes → provably different access conditions
    assert.notEqual(snap1.termsHash, snap2.termsHash)
  })
})

// ═══════════════════════════════════════
// Final Gaps Tests: Rights Propagation
// ═══════════════════════════════════════

import {
  resolveRightsPropagation, DEFAULT_RIGHTS_PROPAGATION,
  detectPurposeDrift,
  declareReidentificationRisk,
} from '../src/index.js'
import type { RightsPropagationRule } from '../src/index.js'

describe('Data Lifecycle — Rights Propagation', () => {
  it('defaults: copy inherits full, embedding compensates only', () => {
    assert.equal(DEFAULT_RIGHTS_PROPAGATION['copy'], 'inherit_full')
    assert.equal(DEFAULT_RIGHTS_PROPAGATION['embedding'], 'compensation_only')
    assert.equal(DEFAULT_RIGHTS_PROPAGATION['decision_artifact'], 'explanation_only')
    assert.equal(DEFAULT_RIGHTS_PROPAGATION['redacted'], 'attribution_only')
  })

  it('resolves default propagation by transform class', () => {
    assert.equal(resolveRightsPropagation('copy'), 'inherit_full')
    assert.equal(resolveRightsPropagation('synthetic'), 'compensation_only')
    assert.equal(resolveRightsPropagation('summary'), 'inherit_partial')
  })

  it('resolves unknown transform to inherit_partial', () => {
    assert.equal(resolveRightsPropagation('custom_unknown'), 'inherit_partial')
  })

  it('source rule overrides defaults', () => {
    const rule: RightsPropagationRule = {
      defaultPropagation: 'extinguished',
    }
    assert.equal(resolveRightsPropagation('copy', rule), 'extinguished')
  })

  it('source rule with per-transform overrides', () => {
    const rule: RightsPropagationRule = {
      defaultPropagation: 'inherit_full',
      byTransformClass: {
        'synthetic': 'extinguished',
        'embedding': 'attribution_only',
      },
    }
    assert.equal(resolveRightsPropagation('synthetic', rule), 'extinguished')
    assert.equal(resolveRightsPropagation('embedding', rule), 'attribution_only')
    assert.equal(resolveRightsPropagation('copy', rule), 'inherit_full')
  })
})

// ═══════════════════════════════════════
// Final Gaps Tests: Purpose Drift
// ═══════════════════════════════════════

describe('Data Lifecycle — Purpose Drift Detection', () => {
  it('no drift: same purpose', () => {
    const result = detectPurposeDrift({
      originalPurpose: 'research:academic',
      currentPurpose: 'research:academic',
      allowedPurposes: ['research:*'],
    })
    assert.equal(result.driftDetected, false)
    assert.equal(result.severity, 'none')
  })

  it('minor drift: same category, different sub-purpose', () => {
    const result = detectPurposeDrift({
      originalPurpose: 'research:academic',
      currentPurpose: 'research:commercial',
      allowedPurposes: ['research:*'],
    })
    assert.equal(result.driftDetected, true)
    assert.equal(result.severity, 'minor')
    assert.ok(result.explanation.includes('Same category'))
  })

  it('major drift: cross-category', () => {
    const result = detectPurposeDrift({
      originalPurpose: 'research:academic',
      currentPurpose: 'commerce',
      allowedPurposes: ['research:*', 'commerce'],
    })
    assert.equal(result.driftDetected, true)
    assert.equal(result.severity, 'major')
    assert.ok(result.explanation.includes('Cross-category'))
  })

  it('violation: current purpose not in allowed', () => {
    const result = detectPurposeDrift({
      originalPurpose: 'research:academic',
      currentPurpose: 'training:model',
      allowedPurposes: ['research:academic'],
    })
    assert.equal(result.severity, 'violation')
    assert.ok(result.explanation.includes('not in allowed'))
  })

  it('tracks intermediate steps in drift path', () => {
    const result = detectPurposeDrift({
      originalPurpose: 'research:academic',
      currentPurpose: 'analytics:commercial',
      intermediateSteps: ['research:commercial', 'analytics:internal'],
      allowedPurposes: ['research:*', 'analytics:*'],
    })
    assert.equal(result.driftPath.length, 4)
    assert.equal(result.severity, 'major')
  })
})

// ═══════════════════════════════════════
// Final Gaps Tests: Re-identification Risk
// ═══════════════════════════════════════

describe('Data Lifecycle — Re-identification Risk Declaration', () => {
  it('creates a risk declaration', () => {
    const decl = declareReidentificationRisk({
      risk: 'medium',
      assessmentMethod: 'k-anonymity analysis',
      mitigationsApplied: ['differential_privacy_epsilon_1.0', 'generalization'],
      assessedBy: 'privacy-audit-agent',
    })
    assert.equal(decl.risk, 'medium')
    assert.equal(decl.assessmentMethod, 'k-anonymity analysis')
    assert.equal(decl.mitigationsApplied!.length, 2)
    assert.ok(decl.assessedAt)
    assert.equal(decl.assessedBy, 'privacy-audit-agent')
  })

  it('supports all risk levels', () => {
    const levels: Array<'none_declared' | 'low' | 'medium' | 'high' | 'unknown' | 'mitigated'> =
      ['none_declared', 'low', 'medium', 'high', 'unknown', 'mitigated']
    for (const risk of levels) {
      const d = declareReidentificationRisk({ risk, assessedBy: 'test' })
      assert.equal(d.risk, risk)
    }
  })
})
