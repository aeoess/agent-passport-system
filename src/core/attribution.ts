// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Beneficiary Attribution Protocol — Trace, Attribute, Prove
// Layer 3 of the Agent Social Contract
//
// This module is the PRIMITIVE half of attribution: pure Merkle math,
// beneficiary trace, hash helpers, and signed-report verification.
// The weight-based report generators (computeAttribution,
// computeCollaborationAttribution, DEFAULT_SCOPE_WEIGHTS) are product
// policy and live in the gateway. See MIGRATION.md#attribution-reports.

import { v4 as uuidv4 } from 'uuid'
import { createHash } from 'node:crypto'
import { verify } from '../crypto/keys.js'
import { verifyDelegation, verifyReceipt } from './delegation.js'
import { canonicalize } from './canonical.js'
import type {
  ActionReceipt, Delegation,
  BeneficiaryTrace, DelegationHop,
  AttributionReport,
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
 * Follow the delegation chain from an action receipt back to the human who
 * authorized it. Reports two DISTINCT, honestly-named properties:
 *
 *   resolved  Lookup success only. Every hop's (from,to) key pair maps to a
 *             known delegation record AND the principal resolves to a known
 *             beneficiary. This proves the lineage RESOLVES against the supplied
 *             records, NOT that it is authentic: a creator-supplied chain that
 *             happens to match known records can be `resolved`. Do not trust it
 *             as proof of authorization.
 *
 *   verified  Cryptographic verification. The receipt signature is authentic
 *             (checked with verifyReceipt against the executor at the chain
 *             tail) AND every delegation in the traced lineage passes
 *             verifyDelegation (its own ed25519 signature by its delegator is
 *             valid and it is within its validity window). A tampered or forged
 *             chain CANNOT be `verified`: a hop whose delegator key the caller
 *             does not hold fails verifyDelegation. This reuses the canonical
 *             verifiers and does not reimplement crypto.
 *
 *             Scope of the claim: `verified` attests that the lineage signatures
 *             are authentic and temporally valid. It does NOT check that the
 *             action was authorized (scopeUsed within the delegation scope) or
 *             that scope narrows between hops (use verifyDelegationChain /
 *             scopeAuthorizes), and it does NOT consult revocation
 *             (verifyDelegation runs fail-open on this path unless the caller
 *             threads a revocation cache).
 *
 * Every agent action resolves to a human. `verified` is the field to trust;
 * `resolved` is a convenience lookup that makes no cryptographic claim.
 */
export function traceBeneficiary(
  receipt: ActionReceipt,
  delegations: Delegation[],
  beneficiaryMap: Map<string, BeneficiaryInfo>
): BeneficiaryTrace {
  const chain: DelegationHop[] = []
  const keyChain = receipt.delegationChain ?? []

  // Walk each hop. A single (from,to) key pair may have MORE THAN ONE matching
  // delegation (e.g. a re-issued one), so the two concerns are kept independent:
  //
  //   verified (security): a hop is authentic iff SOME matching delegation
  //     passes the canonical verifyDelegation (ed25519 signature + temporal
  //     validity; revocation is fail-open on this path). This does not depend on
  //     WHICH delegation gets reported, so a re-used key pair cannot turn a valid
  //     lineage into verified=false, and a hop with no valid delegation still
  //     breaks `verified`.
  //
  //   reported chain (determinism): one delegation is chosen per hop so the same
  //     inputs always produce the same chain. Order: valid first, then by
  //     delegationId. The TAIL hop additionally prefers the delegation the
  //     receipt was issued under (receipt.delegationId), so the reported lineage
  //     is consistent with the executor's own delegationId rather than whichever
  //     duplicate happened to be first in the array.
  let everyHopAuthentic = true
  for (let i = 0; i < keyChain.length - 1; i++) {
    const from = keyChain[i]
    const to = keyChain[i + 1]
    const isTail = i === keyChain.length - 2

    const matches = delegations
      .filter(d => d.delegatedBy === from && d.delegatedTo === to)
      .map(d => ({ del: d, valid: verifyDelegation(d).valid }))

    if (!matches.some(m => m.valid)) everyHopAuthentic = false

    const ordered = [...matches].sort((a, b) =>
      a.valid !== b.valid
        ? (a.valid ? -1 : 1)
        : (a.del.delegationId < b.del.delegationId ? -1 : a.del.delegationId > b.del.delegationId ? 1 : 0)
    )
    const chosen =
      (isTail ? ordered.find(m => m.del.delegationId === receipt.delegationId) : undefined)
      ?? ordered[0]

    chain.push({
      from, to,
      delegationId: chosen?.del.delegationId || 'unknown',
      scope: chosen?.del.scope || [],
      depth: i
    })
  }

  const principalKey = keyChain[0]
  const beneficiary = beneficiaryMap.get(principalKey)

  // resolved: the previous semantics, honestly renamed. Lookup success only,
  // no cryptographic claim.
  const resolved = !!beneficiary && keyChain.length > 1 && chain.every(h => h.delegationId !== 'unknown')

  // verified: real cryptographic verification of the traced lineage. The
  // receipt must be signed by the executor at the tail of the chain, every
  // delegation along the way must verify, and there must be at least one hop.
  // Absent or invalid signatures => not verified.
  const executorKey = keyChain[keyChain.length - 1]
  const receiptAuthentic = keyChain.length > 0 && verifyReceipt(receipt, executorKey).valid
  const verified = keyChain.length > 1 && receiptAuthentic && everyHopAuthentic

  return {
    traceId: 'trace_' + uuidv4().slice(0, 12),
    receiptId: receipt.receiptId,
    executorAgent: receipt.agentId,
    beneficiary: beneficiary?.principalId || principalKey,
    chain,
    totalDepth: chain.length,
    resolved,
    verified
  }
}

// ══════════════════════════════════════
// ATTRIBUTION REPORT VERIFICATION (pure)
// ══════════════════════════════════════

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
// This is the real contribution. The Merkle tree lets you commit to N
// receipts in 32 bytes and prove any individual receipt in O(log N)
// hashes. This is how attribution scales to millions of actions.

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
// DEPRECATION STUBS — moved to @aeoess/gateway
// ══════════════════════════════════════
// Kept as throwing stubs so downstream import sites fail loudly with a
// migration pointer instead of producing silently-broken reports.

const MOVED = 'Moved to @aeoess/gateway. See MIGRATION.md#attribution-reports'

export const DEFAULT_SCOPE_WEIGHTS: Record<string, number> = new Proxy({}, {
  get() { throw new Error(MOVED) }
}) as Record<string, number>

export function computeAttribution(..._args: unknown[]): never {
  throw new Error(MOVED)
}

export function computeCollaborationAttribution(..._args: unknown[]): never {
  throw new Error(MOVED)
}
