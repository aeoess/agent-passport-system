// ══════════════════════════════════════════════════════════════════
// Storage — barrel export
// ══════════════════════════════════════════════════════════════════

export type {
  StorageBackend,
  StorageOperations,
  StoredAgentRecord,
  CursorPage,
  ReceiptFilter,
  SpendReservation,
  SpendReservationResult,
  GatewayCheckpoint,
  IntegrityReport,
  CheckpointCallback
} from './types.js'

export { VolatileBackend } from './volatile-backend.js'

export {
  createReceiptBundle, verifyReceiptBundle, importReceiptBundle, hashReceipt
} from './receipt-bundle.js'
export type { ReceiptBundle, BundleVerificationResult } from './receipt-bundle.js'
