// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Finality — Shared provisionality/finality state for transactional artifacts
// ══════════════════════════════════════════════════════════════════
// Every transactional artifact (escrow, receipt, dispute resolution)
// has a finality state. This is the institutional layer:
// when is something temporarily true, frozen, contested, or final?
// ══════════════════════════════════════════════════════════════════

/** Finality status for transactional artifacts.
 *  - provisional: created but not yet confirmed
 *  - maturing: awaiting witness attestation (receipt maturation)
 *  - finalized: witnessed and/or TTL passed without challenge
 *  - frozen: dispute active, finality suspended
 *  - appealable: resolved but within appeal window
 *  - irrevocable: past all challenge windows, permanent */
export type FinalityStatus =
  | 'provisional'
  | 'maturing'
  | 'finalized'
  | 'frozen'
  | 'appealable'
  | 'irrevocable'

export interface FinalityState {
  status: FinalityStatus
  /** When this finality status was entered */
  since: string
  /** When provisional/appealable becomes final (ISO datetime) */
  challengeWindowEnds?: string
  /** DisputeId that froze this artifact (if frozen) */
  frozenBy?: string
}
