// ══════════════════════════════════════════════════════════════════
// Data Lifecycle Governance — Implementation
// ══════════════════════════════════════════════════════════════════
// Extended derivation, revocation obligations, decision lineage,
// purpose taxonomy, retention TTL, terms version pinning.
// ══════════════════════════════════════════════════════════════════

import { randomBytes, createHash } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  TransformClass, LineageConfidence, DerivationReceipt, ParentArtifact,
  PostRevocationObligation, RevocationObligation, AffectedArtifact,
  DecisionLineageReceipt, ContributingSource,
  RetentionPolicy, TermsVersionPin,
} from '../types/data-lifecycle.js'

// ═══════════════════════════════════════
// Extended Derivation Continuity
// ═══════════════════════════════════════

/**
 * Artifact type → default post-revocation obligation.
 * Different artifact types have different erasure physics.
 */
export const DEFAULT_OBLIGATIONS: Record<string, PostRevocationObligation> = {
  'cached_raw': 'delete_if_cached',
  'rag_chunk': 'delete_if_cached',
  'embedding': 'quarantine',
  'fine_tune_corpus': 'no_future_use',
  'model_weights': 'retraining_required',
  'decision_artifact': 'immutable_ledger_exempt',
  'settlement_record': 'immutable_ledger_exempt',
  'output_derivative': 'no_future_use',
  'synthetic_derivative': 'compensation_only',
}

/**
 * Create an extended derivation receipt with lineage metadata.
 * Tracks multi-hop derivation with transform class, confidence,
 * and explicit break markers when provenance crosses boundaries.
 */
export function createDerivationReceipt(opts: {
  derivativeId: string
  derivativeType: string
  parentArtifacts: ParentArtifact[]
  transformClass: TransformClass
  lineageConfidence: LineageConfidence
  externalBoundaryBreak?: boolean
  breakReason?: string
  upstreamObligationsRetained?: boolean
  retainedObligationIds?: string[]
  isSyntheticDerivative?: boolean
  agentId: string
  delegationId?: string
  privateKey: string
}): DerivationReceipt {
  const receipt: Omit<DerivationReceipt, 'signature'> = {
    receiptId: 'drv_' + randomBytes(12).toString('hex'),
    timestamp: new Date().toISOString(),
    derivativeId: opts.derivativeId,
    derivativeType: opts.derivativeType,
    parentArtifacts: opts.parentArtifacts,
    transformClass: opts.transformClass,
    lineageConfidence: opts.lineageConfidence,
    externalBoundaryBreak: opts.externalBoundaryBreak ?? false,
    breakReason: opts.breakReason,
    upstreamObligationsRetained: opts.upstreamObligationsRetained ?? true,
    retainedObligationIds: opts.retainedObligationIds,
    isSyntheticDerivative: opts.isSyntheticDerivative ?? false,
    agentId: opts.agentId,
    delegationId: opts.delegationId,
  }
  const sig = sign(canonicalize(receipt), opts.privateKey)
  return { ...receipt, signature: sig }
}

/**
 * Resolve extended lineage from a derivative back through all parents.
 * Unbounded depth with cycle detection.
 * Returns the full chain with confidence at each hop.
 */
export function resolveExtendedLineage(
  derivativeId: string,
  receiptStore: Map<string, DerivationReceipt>,
  maxDepth: number = 50
): { chain: DerivationReceipt[]; confidence: LineageConfidence; hasBreaks: boolean; depth: number } {
  const chain: DerivationReceipt[] = []
  const visited = new Set<string>()
  let overallConfidence: LineageConfidence = 'complete'
  let hasBreaks = false

  function traverse(id: string, depth: number) {
    if (depth > maxDepth || visited.has(id)) return
    visited.add(id)
    const receipt = receiptStore.get(id)
    if (!receipt) return
    chain.push(receipt)
    if (receipt.externalBoundaryBreak) {
      hasBreaks = true
      overallConfidence = downgradeConfidence(overallConfidence, 'broken_external')
    }
    overallConfidence = downgradeConfidence(overallConfidence, receipt.lineageConfidence)
    for (const parent of receipt.parentArtifacts) {
      traverse(parent.artifactId, depth + 1)
    }
  }

  traverse(derivativeId, 0)
  return { chain, confidence: overallConfidence, hasBreaks, depth: chain.length }
}

const CONFIDENCE_ORDER: LineageConfidence[] = [
  'complete', 'partial', 'asserted', 'inferred', 'broken_external', 'unverifiable'
]

function downgradeConfidence(current: LineageConfidence, incoming: LineageConfidence): LineageConfidence {
  const ci = CONFIDENCE_ORDER.indexOf(current)
  const ii = CONFIDENCE_ORDER.indexOf(incoming)
  return ii > ci ? incoming : current
}

// ═══════════════════════════════════════
// Post-Revocation Obligation Propagation
// ═══════════════════════════════════════

/**
 * Evaluate revocation impact across all derivation chains from a source.
 * Produces a RevocationObligation listing every affected artifact
 * and its specific obligation based on artifact type.
 */
export function evaluateRevocationImpact(opts: {
  sourceId: string
  receiptStore: Map<string, DerivationReceipt>
  privateKey: string
}): RevocationObligation {
  const affected: AffectedArtifact[] = []
  const obligationsByType: Record<string, PostRevocationObligation> = {}

  // Find all receipts that trace back to this source
  for (const [id, receipt] of opts.receiptStore) {
    const lineage = resolveExtendedLineage(id, opts.receiptStore)
    const touchesSource = lineage.chain.some((r: DerivationReceipt) =>
      r.parentArtifacts.some((p: ParentArtifact) => p.sourceId === opts.sourceId)
    )
    if (!touchesSource && !receipt.parentArtifacts.some((p: ParentArtifact) => p.sourceId === opts.sourceId)) continue

    const obligation = DEFAULT_OBLIGATIONS[receipt.derivativeType] ?? 'no_future_use'
    affected.push({
      artifactId: receipt.derivativeId,
      artifactType: receipt.derivativeType,
      obligation,
      reason: `Derived from revoked source ${opts.sourceId} via ${receipt.transformClass}`,
      derivationDepth: lineage.depth,
    })
    obligationsByType[receipt.derivativeType] = obligation
  }

  const obligation: Omit<RevocationObligation, 'signature'> = {
    obligationId: 'rvo_' + randomBytes(12).toString('hex'),
    sourceId: opts.sourceId,
    revokedAt: new Date().toISOString(),
    affectedArtifacts: affected,
    totalAffected: affected.length,
    obligationsByType,
  }
  const sig = sign(canonicalize(obligation), opts.privateKey)
  return { ...obligation, signature: sig }
}

// ═══════════════════════════════════════
// Decision Lineage Receipt
// ═══════════════════════════════════════

/**
 * Create a decision lineage receipt — the bridge between
 * Module 37 (decision artifacts) and data modules (38-42).
 * Answers: "what data influenced this decision?"
 */
export function createDecisionLineageReceipt(opts: {
  decisionArtifactId: string
  decisionType: string
  contributingSources: ContributingSource[]
  lineageCompleteness: LineageConfidence
  externalHopsPresent?: boolean
  transformChain?: TransformClass[]
  governingPurpose?: string
  jurisdictionContext?: string
  explanation?: string
  privateKey: string
}): DecisionLineageReceipt {
  const receipt: Omit<DecisionLineageReceipt, 'signature'> = {
    receiptId: 'dlr_' + randomBytes(12).toString('hex'),
    timestamp: new Date().toISOString(),
    decisionArtifactId: opts.decisionArtifactId,
    decisionType: opts.decisionType,
    contributingSources: opts.contributingSources,
    lineageCompleteness: opts.lineageCompleteness,
    externalHopsPresent: opts.externalHopsPresent ?? false,
    transformChain: opts.transformChain ?? [],
    governingPurpose: opts.governingPurpose,
    jurisdictionContext: opts.jurisdictionContext,
    explanation: opts.explanation,
  }
  const sig = sign(canonicalize(receipt), opts.privateKey)
  return { ...receipt, signature: sig }
}

// ═══════════════════════════════════════
// Hierarchical Purpose Taxonomy
// ═══════════════════════════════════════

/**
 * Check if a requested purpose is permitted under allowed purposes.
 * Supports wildcard matching: 'research:*' permits 'research:academic'.
 * Supports exact matching: 'research:academic' only permits that exact purpose.
 */
export function isPurposePermitted(requested: string, allowed: string[]): boolean {
  for (const a of allowed) {
    if (a === requested) return true
    // Wildcard: 'research:*' matches 'research:academic', 'research:commercial'
    if (a.endsWith(':*')) {
      const prefix = a.slice(0, -1) // 'research:'
      if (requested.startsWith(prefix)) return true
    }
    // Parent covers child: 'research' matches 'research:academic'
    if (!a.includes(':') && requested.startsWith(a + ':')) return true
  }
  return false
}

/**
 * Extract the purpose category from a hierarchical purpose string.
 * e.g. 'research:academic' → 'research'
 */
export function purposeCategory(purpose: string): string {
  const idx = purpose.indexOf(':')
  return idx === -1 ? purpose : purpose.slice(0, idx)
}

// ═══════════════════════════════════════
// Terms Version Pinning + Retention TTL
// ═══════════════════════════════════════

/**
 * Pin terms at the moment of access.
 * Settlement should always use the pinned version, not current terms.
 */
export function pinTermsAtAccess(opts: {
  termsVersion: string
  compensationRate: number
  currency: string
  allowedPurposes: string[]
  retentionPolicy?: RetentionPolicy
}): TermsVersionPin {
  return {
    termsVersion: opts.termsVersion,
    pinnedAt: new Date().toISOString(),
    compensationRate: opts.compensationRate,
    currency: opts.currency,
    allowedPurposes: opts.allowedPurposes,
    retentionPolicy: opts.retentionPolicy,
  }
}

/**
 * Check if retained data has expired its TTL.
 */
export function isRetentionExpired(
  accessTimestamp: string,
  retentionPolicy: RetentionPolicy,
  accessType: 'ephemeral' | 'persistent' = 'persistent'
): boolean {
  const ttl = accessType === 'ephemeral'
    ? (retentionPolicy.ephemeralAccessMs ?? retentionPolicy.maxRetentionMs)
    : (retentionPolicy.persistentAccessMs ?? retentionPolicy.maxRetentionMs)

  if (ttl === null || ttl === undefined) return false // no limit

  const accessTime = new Date(accessTimestamp).getTime()
  const now = Date.now()
  return (now - accessTime) > ttl
}

/**
 * Verify a derivation receipt signature.
 */
export function verifyDerivationReceipt(
  receipt: DerivationReceipt,
  publicKey: string
): boolean {
  const { signature, ...unsigned } = receipt
  return verify(canonicalize(unsigned), signature, publicKey)
}

/**
 * Verify a decision lineage receipt signature.
 */
export function verifyDecisionLineageReceipt(
  receipt: DecisionLineageReceipt,
  publicKey: string
): boolean {
  const { signature, ...unsigned } = receipt
  return verify(canonicalize(unsigned), signature, publicKey)
}
