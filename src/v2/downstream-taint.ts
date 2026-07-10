// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Downstream Taint (Module 4) — public cascade primitive
// ══════════════════════════════════════════════════════════════════
// Per DECISIONS.md 2026-05-02 Option B: the cascade closure ships in
// the public SDK so the gateway, third-party verifiers, and external
// auditors all consume the same logic. This module is pure: no I/O,
// no aggregation, no signing, no key resolution. The caller surfaces
// the candidate reference graph; the function computes the transitive
// closure of receipts downstream of an upheld or remedied
// contestation.
//
// The reference shape is deliberately abstract. A candidate declares
// which other receipt_ids it references — by action_id, by
// parent_receipt_id, by derived_from, by any other field name. The
// SDK does not introspect receipt internals here; it walks the graph
// the caller provides. That keeps the primitive composable across
// receipt families that have not yet been written, and keeps it
// honest about what it does and does not know.
// ══════════════════════════════════════════════════════════════════

import { RecordType } from './claim-evidence-types.js'
import type { ContestabilityReceipt } from './accountability/types/contestability.js'

/**
 * A contestation taints downstream receipts iff the controller has
 * upheld or remedied it. Filed/under_review contestations record a
 * dispute but do not yet justify cascade. Rejected/expired/abandoned
 * contestations never taint.
 */
export function isContestationTainting(c: ContestabilityReceipt): boolean {
  const status = c.controller_response?.status
  return status === 'upheld' || status === 'remedied'
}

export interface TaintedRecord {
  receiptId: string
  recordType: RecordType
  taintReason: string
  /** 1 = direct reference to the contested action_id. 2+ = transitive. */
  taintDepth: number
}

export interface TaintedSet {
  rootActionId: string
  rootContestationId: string
  tainted: TaintedRecord[]
}

export interface TaintCandidate {
  receiptId: string
  recordType: RecordType
  /** Receipt_ids this candidate depends on. The caller decides which
   *  of its own fields qualify as references. */
  references: string[]
}

export function computeDownstreamTaint(
  contestation: ContestabilityReceipt,
  candidates: TaintCandidate[],
): TaintedSet | null {
  if (!isContestationTainting(contestation)) {
    return null
  }

  const rootActionId = contestation.action_id
  const tainted = new Map<string, TaintedRecord>()

  // Depth 1: candidates whose references include the contested action_id.
  let frontier: TaintedRecord[] = []
  for (const c of candidates) {
    if (c.references.includes(rootActionId)) {
      const t: TaintedRecord = {
        receiptId: c.receiptId,
        recordType: c.recordType,
        taintReason: `Directly references contested action ${rootActionId}`,
        taintDepth: 1,
      }
      tainted.set(c.receiptId, t)
      frontier.push(t)
    }
  }

  // Depth 2+: BFS expansion. A candidate joins the tainted set when it
  // references any receiptId already in the set. Dedup via the map
  // keeps cycles from looping forever.
  while (frontier.length > 0) {
    const next: TaintedRecord[] = []
    for (const parent of frontier) {
      for (const c of candidates) {
        if (tainted.has(c.receiptId)) continue
        if (c.references.includes(parent.receiptId)) {
          const t: TaintedRecord = {
            receiptId: c.receiptId,
            recordType: c.recordType,
            taintReason: `Transitively references tainted receipt ${parent.receiptId}`,
            taintDepth: parent.taintDepth + 1,
          }
          tainted.set(c.receiptId, t)
          next.push(t)
        }
      }
    }
    frontier = next
  }

  return {
    rootActionId,
    rootContestationId: contestation.receipt_id,
    tainted: [...tainted.values()],
  }
}
