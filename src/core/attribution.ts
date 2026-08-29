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
import { verifyDelegation, verifyReceipt, type RevocationCheckPolicy } from './delegation.js'
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
/** Revocation posture for an attribution walk.
 *
 *  A chain walk checks MANY delegations, so it cannot take the single
 *  `cachedRevocationState` the other entrypoints take: one delegation's
 *  evidence applied to every hop would be a new defect, not a fix. Evidence is
 *  supplied per delegation through a resolver instead, the same shape the v2
 *  authority-delegation verifier uses.
 *
 *  Omitting this leaves the historical default exactly: policy `fail_open`,
 *  no evidence consulted, which is what this walk has always done. */
export interface AttributionRevocationOptions {
  revocationCheckPolicy?: RevocationCheckPolicy
  cacheGraceMs?: number
  /** Called once per candidate delegation. Return undefined when no evidence
   *  is held for that delegation; under `fail_closed` that hop is then not
   *  authentic, which is the point of selecting it. */
  resolveRevocation?: (delegation: Delegation) => { revoked: boolean; checkedAt: string } | undefined
}

export function traceBeneficiary(
  receipt: ActionReceipt,
  delegations: Delegation[],
  beneficiaryMap: Map<string, BeneficiaryInfo>,
  revocation?: AttributionRevocationOptions
): BeneficiaryTrace {
  const chain: DelegationHop[] = []
  const keyChain = receipt.delegationChain ?? []

  // Walk each hop. A single (from,to) key pair may have MORE THAN ONE matching
  // delegation (e.g. a re-issued one), so the two concerns are kept independent:
  //
  //   verified (security): a hop is authentic iff SOME matching delegation
  //     passes the canonical verifyDelegation (ed25519 signature + temporal
  //     validity, and whatever revocation posture the caller passed, which
  //     defaults to fail-open). This does not depend on
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

    // The revocation posture is the caller's, defaulting to fail_open, which
    // is what this walk has always done.
    //
    // An earlier version of this comment argued that a posture must NOT be
    // available here, because letting present-day revocation state change a
    // historical verdict would retroactively erase the record of who did what.
    // That argument does not survive its own call site: verifyDelegation
    // checks EXPIRY too, so the present-day clock already flips a hop from
    // authentic to not, on this exact line, and has always done so. The
    // property the comment claimed to protect was not held. An optional
    // fail_open-defaulted posture preserves the historical default exactly and
    // removes a capability from a caller who genuinely wants attribution to
    // depend on revocation, so withholding it protected nothing.
    const matches = delegations
      .filter(d => d.delegatedBy === from && d.delegatedTo === to)
      .map(d => ({
        del: d,
        valid: verifyDelegation(d, {
          revocationCheckPolicy: revocation?.revocationCheckPolicy,
          cacheGraceMs: revocation?.cacheGraceMs,
          cachedRevocationState: revocation?.resolveRevocation?.(d),
        }).valid,
      }))

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

// Domain separation (CVE-2012-2459 class). Leaves are hashed under a 0x00
// prefix and internal nodes under a 0x01 prefix so an internal node value
// can never be reinterpreted as a leaf. Odd nodes are promoted unchanged
// rather than duplicated, so distinct receipt multisets (for example
// [a,b,c] versus [a,b,c,c]) can never fold to the same root.
function hashLeafNode(leaf: string): string {
  return sha256('\x00' + leaf)
}

function hashInternalNode(left: string, right: string): string {
  return sha256('\x01' + left + right)
}

/**
 * Build a Merkle root from leaf hashes.
 * Leaves are sorted for determinism — same set always produces same root.
 * Leaves and internal nodes are domain-separated; an odd node at any level
 * is carried up unchanged (never duplicated) to avoid the CVE-2012-2459
 * duplicate-leaf collision.
 */
export function buildMerkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) return sha256('empty')

  const sorted = [...leafHashes].sort()
  let level = sorted.map(hashLeafNode)

  while (level.length > 1) {
    const next: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      next.push(
        i + 1 < level.length
          ? hashInternalNode(level[i], level[i + 1])
          : level[i], // odd node promoted unchanged, never duplicated
      )
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
  let level = sorted.map(hashLeafNode)
  let index = targetIndex

  while (level.length > 1) {
    const isRightChild = index % 2 === 1
    const siblingIndex = isRightChild ? index - 1 : index + 1

    // A lone odd node is promoted unchanged: it has no sibling, so it
    // contributes no proof node at this level.
    if (siblingIndex < level.length) {
      proof.push({ hash: level[siblingIndex], position: isRightChild ? 'left' : 'right' })
    }

    const next: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      next.push(
        i + 1 < level.length ? hashInternalNode(level[i], level[i + 1]) : level[i],
      )
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
  let hash = hashLeafNode(proof.receiptHash)

  for (const node of proof.proof) {
    hash = node.position === 'left'
      ? hashInternalNode(node.hash, hash)
      : hashInternalNode(hash, node.hash)
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
