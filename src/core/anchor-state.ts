// ══════════════════════════════════════════════════════════════════
// Anchor States — External verifiability tracking for receipts
// ══════════════════════════════════════════════════════════════════
// Consilium Priority 6. Gemini: "explicit receipt anchor states."
// desiorac (A2A #1672): batch commitment lags individual receipts.
//
// Every receipt and batch carries an anchor state:
//   unanchored → batched_pending → anchored → critical_direct_anchor
//
// Auto-batching: configurable window (N seconds or N receipts).
// ══════════════════════════════════════════════════════════════════

/** External anchor state for a receipt or batch.
 *  unanchored: exists only in gateway memory
 *  batched_pending: included in a Merkle batch, root not yet anchored externally
 *  anchored: Merkle root published to external log (Rekor, Solana, etc.)
 *  critical_direct_anchor: individual receipt anchored directly (bypass batching) */
export type AnchorState = 'unanchored' | 'batched_pending' | 'anchored' | 'critical_direct_anchor'

/** Anchor metadata on a receipt */
export interface AnchorMetadata {
  state: AnchorState
  /** Batch ID if batched_pending or anchored */
  batchId?: string
  /** External anchor reference (URL, transaction ID, etc.) */
  anchorRef?: string
  /** When the anchor was confirmed */
  anchoredAt?: string
  /** Which anchor backend was used */
  anchorBackend?: string
}

/** Auto-batch configuration */
export interface AutoBatchConfig {
  /** Maximum seconds between batch commits (0 = disabled) */
  maxIntervalSeconds: number
  /** Maximum receipts before auto-commit (0 = disabled) */
  maxReceiptsPerBatch: number
  /** Whether critical/irreversible actions get direct anchor */
  directAnchorCritical: boolean
}

export const DEFAULT_AUTO_BATCH_CONFIG: AutoBatchConfig = {
  maxIntervalSeconds: 300,   // 5 minutes
  maxReceiptsPerBatch: 100,
  directAnchorCritical: true,
}

/** Create initial anchor metadata for a new receipt */
export function createAnchorMetadata(critical: boolean = false): AnchorMetadata {
  return {
    state: critical ? 'critical_direct_anchor' : 'unanchored',
  }
}

/** Transition anchor state when receipt is added to a batch */
export function markBatched(anchor: AnchorMetadata, batchId: string): AnchorMetadata {
  if (anchor.state === 'critical_direct_anchor') return anchor // already anchored
  if (anchor.state === 'anchored') return anchor // already anchored
  return { ...anchor, state: 'batched_pending', batchId }
}

/** Transition anchor state when batch root is externally anchored */
export function markAnchored(
  anchor: AnchorMetadata,
  anchorRef: string,
  anchorBackend: string,
): AnchorMetadata {
  if (anchor.state === 'critical_direct_anchor') return anchor
  return {
    ...anchor,
    state: 'anchored',
    anchorRef, anchorBackend,
    anchoredAt: new Date().toISOString(),
  }
}

/** Check if auto-batch should fire based on config and current state */
export function shouldAutoBatch(
  pendingCount: number,
  lastBatchTime: string | null,
  config: AutoBatchConfig = DEFAULT_AUTO_BATCH_CONFIG,
): { trigger: boolean; reason: 'max_receipts' | 'max_interval' | null } {
  if (pendingCount === 0) return { trigger: false, reason: null }

  // Receipt count trigger
  if (config.maxReceiptsPerBatch > 0 && pendingCount >= config.maxReceiptsPerBatch) {
    return { trigger: true, reason: 'max_receipts' }
  }

  // Time interval trigger
  if (config.maxIntervalSeconds > 0 && lastBatchTime) {
    const elapsed = (Date.now() - new Date(lastBatchTime).getTime()) / 1000
    if (elapsed >= config.maxIntervalSeconds) {
      return { trigger: true, reason: 'max_interval' }
    }
  }

  // First batch ever — trigger on interval if no previous batch
  if (config.maxIntervalSeconds > 0 && !lastBatchTime && pendingCount > 0) {
    return { trigger: true, reason: 'max_interval' }
  }

  return { trigger: false, reason: null }
}

/** Anchor state ordering — higher number = more externally verifiable */
const ANCHOR_ORDER: Record<AnchorState, number> = {
  unanchored: 0,
  batched_pending: 1,
  anchored: 2,
  critical_direct_anchor: 3,
}

/** Check if an anchor state meets a minimum requirement */
export function meetsAnchorRequirement(
  current: AnchorState,
  minimum: AnchorState,
): boolean {
  return ANCHOR_ORDER[current] >= ANCHOR_ORDER[minimum]
}

/** Check if anchor state transition is valid (can only move forward) */
export function isValidAnchorTransition(from: AnchorState, to: AnchorState): boolean {
  return ANCHOR_ORDER[to] >= ANCHOR_ORDER[from]
}

/** Exported ordering for cross-language verification */
export const ANCHOR_STATE_ORDER = ANCHOR_ORDER
