// ══════════════════════════════════════════════════════════════════
// Receipt Bundle — Signed, portable, verifiable receipt export
// ══════════════════════════════════════════════════════════════════
// Exports receipts as a self-contained bundle that can be verified
// independently without access to the gateway database.
//
// Use cases:
// - Backup: principal exports and stores receipt history
// - Audit: third party verifies execution chain
// - Portability: move receipt history between backends
// - Evidence: prove what happened in a dispute
// ══════════════════════════════════════════════════════════════════

import { canonicalize } from '../core/canonical.js'
import { sign, verify } from '../crypto/keys.js'
import type { ActionReceipt } from '../types/passport.js'
import type { ReceiptFilter } from './types.js'

const BUNDLE_VERSION = '1.0'

// ── Bundle Types ──

export interface ReceiptBundle {
  /** Bundle format version */
  version: string
  /** ID of the gateway that produced these receipts */
  gatewayId: string
  /** When this bundle was created */
  exportedAt: string
  /** Filter used to select receipts */
  filter: ReceiptFilter
  /** Total receipts in this bundle */
  count: number
  /** Hash of the first receipt in the bundle (chain start) */
  chainStartHash: string
  /** Hash of the last receipt in the bundle (chain end) */
  chainEndHash: string
  /** Whether the internal chain is valid (no gaps) */
  chainValid: boolean
  /** The receipts themselves */
  receipts: ActionReceipt[]
  /** Gateway signature over the bundle metadata (proves authenticity) */
  signature: string
}

export interface BundleVerificationResult {
  valid: boolean
  bundleSignatureValid: boolean
  chainIntegrityValid: boolean
  receiptCount: number
  tombstonedCount: number
  errors: string[]
}

// ── Hash a receipt for chain continuity ──

function hashReceipt(receipt: ActionReceipt): string {
  const payload = canonicalize({
    receiptId: receipt.receiptId,
    agentId: receipt.agentId,
    delegationId: receipt.delegationId,
    action: receipt.action,
    result: receipt.result,
    timestamp: receipt.timestamp,
    signature: receipt.signature
  })
  // Simple hash — use the canonical form as the chain link
  // In production, use SHA-256. For now, deterministic string hash.
  let hash = 0
  for (let i = 0; i < payload.length; i++) {
    const chr = payload.charCodeAt(i)
    hash = ((hash << 5) - hash) + chr
    hash |= 0
  }
  return Math.abs(hash).toString(16).padStart(8, '0')
}

// ── Verify chain integrity within a set of receipts ──

function verifyChain(receipts: ActionReceipt[]): { valid: boolean; brokenAt: number[] } {
  if (receipts.length <= 1) return { valid: true, brokenAt: [] }
  const brokenAt: number[] = []
  for (let i = 1; i < receipts.length; i++) {
    if (receipts[i].previousReceiptHash) {
      const expectedHash = hashReceipt(receipts[i - 1])
      if (receipts[i].previousReceiptHash !== expectedHash) {
        brokenAt.push(i)
      }
    }
  }
  return { valid: brokenAt.length === 0, brokenAt }
}

// ══════════════════════════════════════════════════════════════════
// CREATE — produce a signed, portable bundle
// ══════════════════════════════════════════════════════════════════

export function createReceiptBundle(opts: {
  gatewayId: string
  gatewayPrivateKey: string
  receipts: ActionReceipt[]
  filter: ReceiptFilter
}): ReceiptBundle {
  const { gatewayId, gatewayPrivateKey, receipts, filter } = opts

  // Stamp chain hashes if not already present
  const stamped = receipts.map((r, i) => {
    if (i === 0 || r.previousReceiptHash) return r
    return { ...r, previousReceiptHash: hashReceipt(receipts[i - 1]) }
  })

  const chain = verifyChain(stamped)
  const startHash = stamped.length > 0 ? hashReceipt(stamped[0]) : '0'
  const endHash = stamped.length > 0 ? hashReceipt(stamped[stamped.length - 1]) : '0'

  // Sign the bundle metadata (not the receipts — they're already signed individually)
  const exportedAt = new Date().toISOString()
  const metadata = canonicalize({
    version: BUNDLE_VERSION,
    gatewayId,
    count: stamped.length,
    chainStartHash: startHash,
    chainEndHash: endHash,
    chainValid: chain.valid,
    exportedAt
  })
  const signature = sign(metadata, gatewayPrivateKey)

  return {
    version: BUNDLE_VERSION,
    gatewayId,
    exportedAt,
    filter,
    count: stamped.length,
    chainStartHash: startHash,
    chainEndHash: endHash,
    chainValid: chain.valid,
    receipts: stamped,
    signature
  }
}

// ══════════════════════════════════════════════════════════════════
// VERIFY — check a bundle's authenticity and integrity
// ══════════════════════════════════════════════════════════════════

export function verifyReceiptBundle(
  bundle: ReceiptBundle,
  gatewayPublicKey: string
): BundleVerificationResult {
  const errors: string[] = []

  // 1. Verify bundle signature
  const metadata = canonicalize({
    version: bundle.version,
    gatewayId: bundle.gatewayId,
    count: bundle.count,
    chainStartHash: bundle.chainStartHash,
    chainEndHash: bundle.chainEndHash,
    chainValid: bundle.chainValid,
    exportedAt: bundle.exportedAt
  })

  let bundleSignatureValid = false
  try {
    bundleSignatureValid = verify(metadata, bundle.signature, gatewayPublicKey)
  } catch (_e) {
    errors.push('Bundle signature verification failed')
  }

  // 2. Verify receipt count matches
  if (bundle.receipts.length !== bundle.count) {
    errors.push(`Receipt count mismatch: declared ${bundle.count}, actual ${bundle.receipts.length}`)
  }

  // 3. Verify chain integrity
  const chain = verifyChain(bundle.receipts)
  if (!chain.valid) {
    errors.push(`Chain broken at positions: ${chain.brokenAt.join(', ')}`)
  }

  // 4. Verify chain start/end hashes
  if (bundle.receipts.length > 0) {
    const actualStart = hashReceipt(bundle.receipts[0])
    const actualEnd = hashReceipt(bundle.receipts[bundle.receipts.length - 1])
    if (actualStart !== bundle.chainStartHash) {
      errors.push('Chain start hash mismatch')
    }
    if (actualEnd !== bundle.chainEndHash) {
      errors.push('Chain end hash mismatch')
    }
  }

  // 5. Count tombstoned
  const tombstonedCount = bundle.receipts.filter(r => r.tombstoned).length

  return {
    valid: bundleSignatureValid && chain.valid && errors.length === 0,
    bundleSignatureValid,
    chainIntegrityValid: chain.valid,
    receiptCount: bundle.receipts.length,
    tombstonedCount,
    errors
  }
}

// ══════════════════════════════════════════════════════════════════
// IMPORT — load a verified bundle into a StorageBackend
// ══════════════════════════════════════════════════════════════════

export async function importReceiptBundle(
  bundle: ReceiptBundle,
  gatewayPublicKey: string,
  storage: { appendReceipt(r: ActionReceipt): Promise<void>; transaction<T>(fn: (tx: { appendReceipt(r: ActionReceipt): Promise<void> }) => Promise<T>): Promise<T> }
): Promise<{ imported: number; skipped: number; errors: string[] }> {
  // Verify first
  const verification = verifyReceiptBundle(bundle, gatewayPublicKey)
  if (!verification.valid) {
    return { imported: 0, skipped: 0, errors: ['Bundle verification failed: ' + verification.errors.join('; ')] }
  }

  let imported = 0
  let skipped = 0
  const errors: string[] = []

  // Import in batches within a transaction
  try {
    await storage.transaction(async (tx) => {
      for (const receipt of bundle.receipts) {
        try {
          await tx.appendReceipt(receipt)
          imported++
        } catch (_e) {
          // Duplicate receipt (already exists) — skip
          skipped++
        }
      }
    })
  } catch (e: any) {
    errors.push(`Import transaction failed: ${e.message}`)
  }

  return { imported, skipped, errors }
}

// ── Re-export hash function for testing ──
export { hashReceipt }
