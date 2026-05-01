// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CustodyReceipt — declares a custody event over a batch of receipts
// ══════════════════════════════════════════════════════════════════
// Spec: specs/full-accountability-mvp.md
// Verbal confession: this receipt asserts WHO held WHAT receipts at
// WHAT moment, for WHAT purpose. It does not assert the custodians
// claim is factually accurate; the protocol records the claim, truth
// is rebuttable. The chain remains verifiable across erasure events
// (cryptographic-erasure pattern: merkle_root and count are preserved
// even when the underlying content is destroyed).
// ══════════════════════════════════════════════════════════════════

import type { AccountabilityReceiptBase } from './base.js'

export type CustodyEventType =
  | 'created'
  | 'sealed'
  | 'transferred'
  | 'disclosed'
  | 'redacted'
  | 'erased'
  | 'expired'
  | 'verified'

export type CustodyPurpose =
  | 'internal_audit'
  | 'regulator_disclosure'
  | 'subject_access'
  | 'litigation_discovery'
  | 'vendor_handoff'
  | 'archival'
  | 'incident_response'

export interface CustodyReceipt extends AccountabilityReceiptBase {
  claim_type: 'aps:custody:v1'
  custodian_did: string
  event_type: CustodyEventType
  subject_receipt_batch: {
    merkle_root: string
    count: number
  }
  /** Chains custody events. Set to the previous CustodyReceipt.receipt_id. */
  previous_custody_id?: string
  /** Receiving custodian DID. Required when event_type === 'transferred'. */
  next_custodian_did?: string
  purpose: CustodyPurpose
}
