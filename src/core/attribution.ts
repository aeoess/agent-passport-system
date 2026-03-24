// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Beneficiary Attribution Protocol — Trace, Attribute, Prove
// Layer 3 of the Agent Social Contract
//
// Design philosophy:
//   This system produces EVIDENCE and PROOFS.
//   Attribution weights are configurable, not hardcoded gospel.
//   The Merkle tree is the real innovation — everything else is plumbing.
//   Keep the plumbing clean so the innovation shines.

import { v4 as uuidv4 } from 'uuid'
import { createHash } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  ActionReceipt, Delegation,
  BeneficiaryTrace, DelegationHop,
  AttributionEntry, AttributionReport,
  MerkleProof, MerkleProofNode,
  BeneficiaryInfo
} from '../types/passport.js'

// ══════════════════════════════════════
// HASH PRIMITIVES
// ══════════════════════════════════════

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex')
}

export function hashReceipt(receipt: ActionReceipt): string {
  return sha256(canonicalize(receipt))
}

// ══════════════════════════════════════
// BENEFICIARY TRACING
// ══════════════════════════════════════

/**
 * Follow the cryptographic chain from an action receipt back
 * to the human who authorized it.
 *
 * This is the fundamental primitive: every agent action resolves
 * to a human. Not through policy. Through math.
 */
export function traceBeneficiary(
  receipt: ActionReceipt,
  delegations: Delegation[],
  beneficiaryMap: Map<string, BeneficiaryInfo>
): BeneficiaryTrace {
  const chain: DelegationHop[] = []
  const keyChain = receipt.delegationChain

  for (let i = 0; i < keyChain.length - 1; i++) {
    const from = keyChain[i]
    const to = keyChain[i + 1]
    const del = delegations.find(d => d.delegatedBy === from && d.delegatedTo === to)

    chain.push({
      from, to,
      delegationId: del?.delegationId || 'unknown',
      scope: del?.scope || [],
      depth: i
    })
  }

  const principalKey = keyChain[0]
  const beneficiary = beneficiaryMap.get(principalKey)

  return {
    traceId: 'trace_' + uuidv4().slice(0, 12),
    receiptId: receipt.receiptId,
    executorAgent: receipt.agentId,
    beneficiary: beneficiary?.principalId || principalKey,
    chain,
    totalDepth: chain.length,
    verified: !!beneficiary && chain.every(h => h.delegationId !== 'unknown')
  }
}

// ══════════════════════════════════════
// ATTRIBUTION WEIGHTS — CONFIGURABLE, NOT GOSPEL
// ══════════════════════════════════════

/**
 * Default scope weights. These are DEFAULTS, not universal truth.
 *
 * A healthcare protocol might weight data_analysis at 2.0.
 * A creative protocol might weight coordination at 1.5.
 * The protocol provides the mechanism; the community provides the values.
 *
 * If you don't provide custom weights, these are reasonable.
 * If you do, yours override completely.
 */
export const DEFAULT_SCOPE_WEIGHTS: Record<string, number> = {
  code_execution: 1.0,
  system_control: 0.9,
  data_analysis: 0.8,
  git_operations: 0.7,
  coordination: 0.6,
  file_management: 0.5,
  browser_automation: 0.5,
  email_management: 0.4,
  web_search: 0.3
}

const RESULT_MULTIPLIER: Record<string, number> = {
  success: 1.0,
  partial: 0.5,
  failure: 0.0
}

export interface AttributionConfig {
  scopeWeights?: Record<string, number>
  defaultScopeWeight?: number  // for unrecognized scopes
}

/**
 * Compute attribution with configurable weights.
 *
 * Formula: weight = scope_weight × result × (1 + ln(1 + spend))
 *
 * The logarithm on spend is the one opinion we hardcode,
 * because it's a mechanism design choice, not a value judgment:
 * linear spend weighting creates an arms race. Logarithmic doesn't.
 * This is game theory, not preference.
 */
export function computeAttribution(
  receipts: ActionReceipt[],
  agentId: string,
  beneficiary: string,
  privateKey: string,
  config?: AttributionConfig
): AttributionReport {
  const weights = config?.scopeWeights || DEFAULT_SCOPE_WEIGHTS
  const defaultWeight = config?.defaultScopeWeight ?? 0.3
  const agentReceipts = receipts.filter(r => r.agentId === agentId)

  const entries: AttributionEntry[] = agentReceipts.map(receipt => {
    const sw = weights[receipt.action.scopeUsed] ?? defaultWeight
    const rm = RESULT_MULTIPLIER[receipt.result.status] ?? 0
    const spend = receipt.action.spend?.amount || 0
    const weight = sw * rm * (1 + Math.log(1 + spend))

    return {
      receiptId: receipt.receiptId,
      agentId: receipt.agentId,
      action: receipt.action.type,
      scopeUsed: receipt.action.scopeUsed,
      spend,
      resultStatus: receipt.result.status,
      weight: Math.round(weight * 1000) / 1000,
      timestamp: receipt.timestamp
    }
  })

  const totalWeight = entries.reduce((sum, e) => sum + e.weight, 0)
  const timestamps = entries.map(e => e.timestamp).sort()
  const receiptHashes = agentReceipts.map(r => hashReceipt(r))
  const merkleRoot = buildMerkleRoot(receiptHashes)
  const entriesHash = sha256(canonicalize(entries))

  const report: Omit<AttributionReport, 'signature'> = {
    reportId: 'attr_' + uuidv4().slice(0, 12),
    beneficiary,
    agentId,
    period: {
      from: timestamps[0] || new Date().toISOString(),
      to: timestamps[timestamps.length - 1] || new Date().toISOString()
    },
    entries,
    totalWeight: Math.round(totalWeight * 1000) / 1000,
    receiptCount: agentReceipts.length,
    merkleRoot,
    entriesHash,
    generatedAt: new Date().toISOString()
  }

  const canonical = canonicalize(report)
  const signature = sign(canonical, privateKey)
  return { ...report, signature }
}

export function verifyAttributionReport(
  report: AttributionReport,
  publicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  const { signature, ...unsigned } = report
  if (!verify(canonicalize(unsigned), signature, publicKey)) {
    errors.push('Invalid attribution report signature')
  }

  if (report.receiptCount !== report.entries.length) {
    errors.push(`Receipt count mismatch: ${report.receiptCount} vs ${report.entries.length} entries`)
  }

  const expectedWeight = report.entries.reduce((sum, e) => sum + e.weight, 0)
  if (Math.abs(report.totalWeight - Math.round(expectedWeight * 1000) / 1000) > 0.001) {
    errors.push('Total weight does not match entry weights')
  }

  if (report.entriesHash) {
    const expected = sha256(canonicalize(report.entries))
    if (report.entriesHash !== expected) {
      errors.push('Entries hash mismatch — weights may have been tampered')
    }
  }

  return { valid: errors.length === 0, errors }
}

// ══════════════════════════════════════
// MERKLE TREE
// ══════════════════════════════════════
// This is the real contribution. Everything above is plumbing.
// The Merkle tree lets you commit to N receipts in 32 bytes
// and prove any individual receipt in O(log N) hashes.
// This is how you scale attribution to millions of actions.

/**
 * Build a Merkle root from leaf hashes.
 * Leaves are sorted for determinism — same set always produces same root.
 * Odd levels duplicate the last node (standard Bitcoin-style).
 */
export function buildMerkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) return sha256('empty')
  if (leafHashes.length === 1) return leafHashes[0]

  const sorted = [...leafHashes].sort()
  let level = sorted

  while (level.length > 1) {
    const next: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]
      const right = i + 1 < level.length ? level[i + 1] : left
      next.push(sha256(left + right))
    }
    level = next
  }

  return level[0]
}

/**
 * Generate an inclusion proof for one receipt in the tree.
 * Returns the sibling hashes needed to recompute the root.
 */
export function generateMerkleProof(
  leafHashes: string[],
  targetHash: string
): MerkleProof | null {
  if (leafHashes.length === 0) return null

  const sorted = [...leafHashes].sort()
  const targetIndex = sorted.indexOf(targetHash)
  if (targetIndex === -1) return null

  const proof: MerkleProofNode[] = []
  let level = sorted
  let index = targetIndex

  while (level.length > 1) {
    const next: string[] = []
    const sibling = index % 2 === 0 ? index + 1 : index - 1

    if (sibling < level.length && sibling !== index) {
      proof.push({ hash: level[sibling], position: index % 2 === 0 ? 'right' : 'left' })
    } else {
      proof.push({ hash: level[index], position: 'right' })
    }

    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]
      const right = i + 1 < level.length ? level[i + 1] : left
      next.push(sha256(left + right))
    }

    level = next
    index = Math.floor(index / 2)
  }

  return { receiptHash: targetHash, root: level[0], proof, index: targetIndex }
}

/**
 * Verify a Merkle inclusion proof.
 * Recompute the root from the leaf + proof, compare against claimed root.
 */
export function verifyMerkleProof(proof: MerkleProof): boolean {
  let hash = proof.receiptHash

  for (const node of proof.proof) {
    hash = node.position === 'left'
      ? sha256(node.hash + hash)
      : sha256(hash + node.hash)
  }

  return hash === proof.root
}

// ══════════════════════════════════════
// MULTI-AGENT COLLABORATION ATTRIBUTION
// ══════════════════════════════════════

export interface CollaborationAttribution {
  collaborationId: string
  participants: {
    agentId: string
    beneficiary: string
    weight: number
    percentage: number
    receiptCount: number
  }[]
  totalWeight: number
  merkleRoot: string
  generatedAt: string
}

export function computeCollaborationAttribution(
  allReceipts: ActionReceipt[],
  beneficiaryMap: Map<string, string>,
  config?: AttributionConfig
): CollaborationAttribution {
  const weights = config?.scopeWeights || DEFAULT_SCOPE_WEIGHTS
  const defaultWeight = config?.defaultScopeWeight ?? 0.3

  const byAgent = new Map<string, ActionReceipt[]>()
  for (const r of allReceipts) {
    const list = byAgent.get(r.agentId) || []
    list.push(r)
    byAgent.set(r.agentId, list)
  }

  const participants: CollaborationAttribution['participants'] = []
  let totalWeight = 0

  for (const [agentId, receipts] of byAgent) {
    const w = receipts.reduce((sum, r) => {
      const sw = weights[r.action.scopeUsed] ?? defaultWeight
      const rm = RESULT_MULTIPLIER[r.result.status] ?? 0
      const spend = r.action.spend?.amount || 0
      return sum + sw * rm * (1 + Math.log(1 + spend))
    }, 0)

    totalWeight += w
    participants.push({
      agentId,
      beneficiary: beneficiaryMap.get(agentId) || 'unknown',
      weight: Math.round(w * 1000) / 1000,
      percentage: 0,
      receiptCount: receipts.length
    })
  }

  for (const p of participants) {
    p.percentage = totalWeight > 0 ? Math.round((p.weight / totalWeight) * 10000) / 100 : 0
  }

  participants.sort((a, b) => b.percentage - a.percentage)

  return {
    collaborationId: 'collab_' + uuidv4().slice(0, 12),
    participants,
    totalWeight: Math.round(totalWeight * 1000) / 1000,
    merkleRoot: buildMerkleRoot(allReceipts.map(r => hashReceipt(r))),
    generatedAt: new Date().toISOString()
  }
}
