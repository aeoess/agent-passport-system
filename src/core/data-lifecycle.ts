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


// ═══════════════════════════════════════
// Phase 2: Aggregation Controls
// ═══════════════════════════════════════

import type {
  AggregateConstraint, AggregateAccessLog,
  JurisdictionEnvelope, GovernanceTaint, TaintRecord,
  DisputeStatus, DisputeRecord,
  CombinationConstraint, AccessSnapshot,
} from '../types/data-lifecycle.js'

/**
 * Check if an access would violate aggregate constraints.
 * Uses a rolling window log per source+agent pair.
 */
export function checkAggregateConstraints(
  constraint: AggregateConstraint,
  log: AggregateAccessLog,
  now: number = Date.now()
): { permitted: boolean; reason?: string } {
  // Check if we're still in the window
  const windowEnd = log.windowStartMs + (constraint.windowMs ?? 86400000)
  const inWindow = now < windowEnd && now >= log.windowStartMs

  if (inWindow) {
    if (constraint.maxAccessesPerWindow && log.accessCount >= constraint.maxAccessesPerWindow) {
      return { permitted: false, reason: `Aggregate limit: ${log.accessCount}/${constraint.maxAccessesPerWindow} accesses in window` }
    }
    if (constraint.maxRecordsPerWindow && log.recordCount >= constraint.maxRecordsPerWindow) {
      return { permitted: false, reason: `Record limit: ${log.recordCount}/${constraint.maxRecordsPerWindow} records in window` }
    }
  }

  // Burst check (last 1s)
  if (constraint.burstLimit) {
    const timeSinceLast = now - log.lastAccessMs
    if (timeSinceLast < 1000 && log.accessCount > constraint.burstLimit) {
      return { permitted: false, reason: `Burst limit exceeded: ${constraint.burstLimit}/second` }
    }
  }

  return { permitted: true }
}

// ═══════════════════════════════════════
// Phase 2: Jurisdiction Transfer Check
// ═══════════════════════════════════════

/**
 * Check if a data transfer is permitted under jurisdiction constraints.
 * The protocol carries context, not legal logic.
 */
export function isTransferPermitted(
  envelope: JurisdictionEnvelope,
  targetJurisdiction: string,
  purpose: string
): { permitted: boolean; reason?: string } {
  if (!envelope.sourceJurisdiction) return { permitted: true }

  // Check processing restrictions
  if (envelope.processingRestrictions?.includes('EU_ONLY')) {
    const euCountries = ['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE']
    if (!euCountries.includes(targetJurisdiction)) {
      return { permitted: false, reason: `EU_ONLY restriction: ${targetJurisdiction} is not an EU member state` }
    }
  }

  if (envelope.processingRestrictions?.includes('NO_CROSS_BORDER')) {
    if (targetJurisdiction !== envelope.sourceJurisdiction) {
      return { permitted: false, reason: `NO_CROSS_BORDER: cannot transfer from ${envelope.sourceJurisdiction} to ${targetJurisdiction}` }
    }
  }

  // Check transfer constraints
  if (envelope.transferConstraints?.includes('GDPR_ADEQUATE_ONLY')) {
    const adequateCountries = ['AR','CA','GG','IL','IM','JP','JE','NZ','KR','CH','UY','UK','US']
    const euPlus = ['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE']
    const allAdequate = [...euPlus, ...adequateCountries]
    if (!allAdequate.includes(targetJurisdiction)) {
      return { permitted: false, reason: `GDPR_ADEQUATE_ONLY: ${targetJurisdiction} lacks adequacy decision` }
    }
  }

  return { permitted: true }
}

// ═══════════════════════════════════════
// Phase 2: Governance Taint
// ═══════════════════════════════════════

/**
 * Compute the governance taint level for an artifact based on its
 * derivation chain and source restrictions.
 */
export function computeGovernanceTaint(
  artifactId: string,
  receiptStore: Map<string, DerivationReceipt>,
  revokedSources: Set<string> = new Set()
): TaintRecord {
  const lineage = resolveExtendedLineage(artifactId, receiptStore)
  const touchedSources: string[] = []
  let taint: GovernanceTaint = 'clean'

  for (const receipt of lineage.chain) {
    for (const parent of receipt.parentArtifacts) {
      if (parent.sourceId) {
        touchedSources.push(parent.sourceId)
        if (revokedSources.has(parent.sourceId)) {
          taint = 'restricted'
        }
      }
    }
    if (receipt.externalBoundaryBreak && taint === 'clean') {
      taint = 'untraceable_contamination'
    }
  }

  // Multiple distinct sources with restrictions = mixed
  const uniqueSources = [...new Set(touchedSources)]
  if (taint === 'clean' && uniqueSources.length > 1) {
    taint = 'source_bound'
  }
  if (taint === 'restricted' && uniqueSources.length > 1) {
    taint = 'mixed'
  }

  return {
    artifactId,
    taintLevel: taint,
    sources: uniqueSources,
    reason: taint === 'clean' ? 'No restricted data contact'
      : taint === 'restricted' ? `Touches revoked source(s)`
      : taint === 'untraceable_contamination' ? 'External boundary break — contamination possible'
      : `Touches ${uniqueSources.length} source(s)`,
    detectedAt: new Date().toISOString(),
    clearable: taint !== 'untraceable_contamination',
    clearCondition: taint === 'restricted' ? 'Clear revocation obligations' : undefined,
  }
}

// ═══════════════════════════════════════
// Phase 2: Dispute Records
// ═══════════════════════════════════════

/**
 * File a dispute against a data artifact.
 * The protocol records the dispute — resolution is external.
 */
export function fileDispute(opts: {
  artifactId: string
  disputeType: DisputeRecord['disputeType']
  filedBy: string
  evidence: string[]
  privateKey: string
}): DisputeRecord {
  const record: Omit<DisputeRecord, 'signature'> = {
    disputeId: 'dsp_' + randomBytes(12).toString('hex'),
    artifactId: opts.artifactId,
    disputeType: opts.disputeType,
    status: 'under_review',
    filedBy: opts.filedBy,
    filedAt: new Date().toISOString(),
    evidence: opts.evidence,
  }
  const sig = sign(canonicalize(record), opts.privateKey)
  return { ...record, signature: sig }
}

// ═══════════════════════════════════════
// Phase 2: Combination Constraints
// ═══════════════════════════════════════

/**
 * Check if combining data from two sources is permitted.
 * Prevents prohibited inferences (e.g. health + geolocation).
 */
export function checkCombinationPermitted(
  sourceConstraints: CombinationConstraint[],
  otherSourceId: string,
  otherSourceClasses: string[] = []
): { permitted: boolean; violations: string[] } {
  const violations: string[] = []

  for (const constraint of sourceConstraints) {
    if (constraint.forbiddenSourceIds?.includes(otherSourceId)) {
      violations.push(`Source ${otherSourceId} forbidden: ${constraint.reason}`)
    }
    for (const cls of otherSourceClasses) {
      if (constraint.forbiddenSourceClasses?.includes(cls)) {
        violations.push(`Source class "${cls}" forbidden: ${constraint.reason} (${constraint.regulatoryBasis ?? 'unspecified'})`)
      }
    }
  }
  return { permitted: violations.length === 0, violations }
}

// ═══════════════════════════════════════
// Phase 2: Access Snapshots (anti-rug-pull)
// ═══════════════════════════════════════

/**
 * Create an immutable access snapshot — freezes the exact terms,
 * jurisdiction, and constraints at the moment of access.
 * Prevents retroactive term changes from holding downstream models hostage.
 */
export function createAccessSnapshot(opts: {
  accessReceiptId: string
  sourceId: string
  pinnedTerms: TermsVersionPin
  jurisdiction?: JurisdictionEnvelope
  combinationConstraints?: CombinationConstraint[]
  privateKey: string
}): AccessSnapshot {
  const termsHash = createHash('sha256')
    .update(canonicalize(opts.pinnedTerms))
    .digest('hex')

  const snapshot: Omit<AccessSnapshot, 'signature'> = {
    snapshotId: 'snap_' + randomBytes(12).toString('hex'),
    accessReceiptId: opts.accessReceiptId,
    sourceId: opts.sourceId,
    termsHash,
    pinnedTerms: opts.pinnedTerms,
    jurisdiction: opts.jurisdiction,
    combinationConstraints: opts.combinationConstraints,
    timestamp: new Date().toISOString(),
  }
  const sig = sign(canonicalize(snapshot), opts.privateKey)
  return { ...snapshot, signature: sig }
}

/**
 * Verify an access snapshot signature.
 */
export function verifyAccessSnapshot(
  snapshot: AccessSnapshot,
  publicKey: string
): boolean {
  const { signature, ...unsigned } = snapshot
  return verify(canonicalize(unsigned), signature, publicKey)
}


// ═══════════════════════════════════════
// Rights Propagation
// ═══════════════════════════════════════

import type {
  RightsPropagation, RightsPropagationRule,
  PurposeDriftCheck, ReidentificationRisk, ReidentificationDeclaration,
} from '../types/data-lifecycle.js'

/** Default rights propagation rules by transform class */
export const DEFAULT_RIGHTS_PROPAGATION: Record<string, RightsPropagation> = {
  'copy': 'inherit_full',
  'subset': 'inherit_full',
  'summary': 'inherit_partial',
  'embedding': 'compensation_only',
  'aggregation': 'compensation_only',
  'synthetic': 'compensation_only',
  'model_training': 'compensation_only',
  'fine_tune': 'compensation_only',
  'rag_index': 'inherit_partial',
  'decision_artifact': 'explanation_only',
  'redacted': 'attribution_only',
}

/**
 * Resolve rights propagation for a derivation.
 * Uses source rules if provided, falls back to defaults by transform class.
 */
export function resolveRightsPropagation(
  transformClass: string,
  sourceRule?: RightsPropagationRule
): RightsPropagation {
  if (sourceRule) {
    // Check transform-specific override
    if (sourceRule.byTransformClass?.[transformClass]) {
      return sourceRule.byTransformClass[transformClass]
    }
    return sourceRule.defaultPropagation
  }
  return DEFAULT_RIGHTS_PROPAGATION[transformClass] ?? 'inherit_partial'
}

// ═══════════════════════════════════════
// Purpose Drift Detection
// ═══════════════════════════════════════

/**
 * Detect purpose drift through a derivation chain.
 * Compares original access purpose to current usage purpose.
 * Same category = minor drift. Cross-category = major. Not permitted = violation.
 */
export function detectPurposeDrift(opts: {
  originalPurpose: string
  currentPurpose: string
  intermediateSteps?: string[]
  allowedPurposes: string[]
}): PurposeDriftCheck {
  const origCat = purposeCategory(opts.originalPurpose)
  const currCat = purposeCategory(opts.currentPurpose)
  const path = [opts.originalPurpose, ...(opts.intermediateSteps ?? []), opts.currentPurpose]

  // Check if current purpose is even permitted
  const permitted = isPurposePermitted(opts.currentPurpose, opts.allowedPurposes)

  if (!permitted) {
    return {
      originalPurpose: opts.originalPurpose,
      currentPurpose: opts.currentPurpose,
      driftDetected: true, driftPath: path,
      severity: 'violation',
      explanation: `Purpose "${opts.currentPurpose}" not in allowed: [${opts.allowedPurposes.join(', ')}]`,
    }
  }

  if (opts.originalPurpose === opts.currentPurpose) {
    return {
      originalPurpose: opts.originalPurpose,
      currentPurpose: opts.currentPurpose,
      driftDetected: false, driftPath: path,
      severity: 'none',
      explanation: 'Purpose unchanged',
    }
  }

  if (origCat === currCat) {
    return {
      originalPurpose: opts.originalPurpose,
      currentPurpose: opts.currentPurpose,
      driftDetected: true, driftPath: path,
      severity: 'minor',
      explanation: `Same category "${origCat}" but sub-purpose changed: ${opts.originalPurpose} → ${opts.currentPurpose}`,
    }
  }

  return {
    originalPurpose: opts.originalPurpose,
    currentPurpose: opts.currentPurpose,
    driftDetected: true, driftPath: path,
    severity: 'major',
    explanation: `Cross-category drift: ${origCat} → ${currCat}`,
  }
}

// ═══════════════════════════════════════
// Re-identification Risk Declaration
// ═══════════════════════════════════════

/**
 * Create a re-identification risk declaration for a derivation.
 * Attached to synthetic or transformed data to declare
 * whether source identity might be recoverable.
 */
export function declareReidentificationRisk(opts: {
  risk: ReidentificationRisk
  assessmentMethod?: string
  mitigationsApplied?: string[]
  assessedBy: string
}): ReidentificationDeclaration {
  return {
    risk: opts.risk,
    assessmentMethod: opts.assessmentMethod,
    mitigationsApplied: opts.mitigationsApplied,
    assessedAt: new Date().toISOString(),
    assessedBy: opts.assessedBy,
  }
}
