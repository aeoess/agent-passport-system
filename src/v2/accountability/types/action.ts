// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// ActionReceipt — declares an action the system observed an agent take
// ══════════════════════════════════════════════════════════════════
// Spec: specs/full-accountability-mvp.md
// Verbal confession: this receipt asserts WHAT happened (kind, target,
// parameters, side-effect classes). It does not claim the agent
// understood why; that is a separate primitive.
// ══════════════════════════════════════════════════════════════════

import type { AccountabilityReceiptBase } from './base.js'

export type SideEffectClass =
  | 'financial'
  | 'data_modification'
  | 'external_message'
  | 'irreversible'
  | 'subject_affecting'
  | 'internal_only'

export interface ActionReceipt extends AccountabilityReceiptBase {
  claim_type: 'aps:action:v1'
  agent_did: string
  /** sha256 hex of the canonical delegation chain that authorized the agent. */
  delegation_chain_root: string
  intent_ref?: string
  policy_ref?: string
  action: {
    kind: string
    target: string
    parameters?: Record<string, unknown>
    resource_version?: string
  }
  side_effect_classes: SideEffectClass[]
  transparency_log_inclusion?: {
    log_url: string
    leaf_hash: string
  }
  /** RFC 3161 timestamp token, base64-encoded. Optional. */
  rfc3161_timestamp?: string
}
