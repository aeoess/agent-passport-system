// ══════════════════════════════════════════════════════════════════
// StorageBackend — Persistence interface for APS
// ══════════════════════════════════════════════════════════════════
// Defines the contract between the protocol and any persistence
// implementation (volatile, SQLite, Postgres, etc).
//
// Design principles:
// 1. Events are truth (receipts, revocations, demotions, key rotations)
// 2. State is derived (spend totals, reputation, delegation status)
// 3. Transactions are mandatory for invariant preservation
// 4. Append-only semantics for audit-critical data
// 5. Signed protocol objects, never signed storage rows
// ══════════════════════════════════════════════════════════════════

import type { Delegation, RevocationRecord, ActionReceipt, SignedPassport, FloorAttestation } from '../types/passport.js'
import type { ScopedReputation, DemotionEvent } from '../types/reputation-authority.js'
import type { KeyRotationEntry } from '../types/identity.js'

// ── Pagination ──

export interface CursorPage<T> {
  items: T[]
  nextCursor?: string
  hasMore: boolean
}

export interface ReceiptFilter {
  agentId?: string
  delegationId?: string
  scope?: string
  after?: string   // ISO timestamp
  before?: string  // ISO timestamp
}

// ── Spend Reservation (reserve/commit/release pattern) ──

export interface SpendReservation {
  reservationId: string
  delegationId: string
  amount: number
  currency: string
  reservedAt: string
  expiresAt: string
  status: 'reserved' | 'committed' | 'released'
}

export interface SpendReservationResult {
  success: boolean
  reservationId?: string
  currentSpent?: number
  limit?: number
  reason?: string
}

// ── Agent Record (stored representation) ──

export interface StoredAgentRecord {
  agentId: string
  passport: SignedPassport
  attestation: FloorAttestation
  registeredAt: string
  metadata?: Record<string, unknown>
}

// ── Gateway Checkpoint ──

export interface GatewayCheckpoint {
  checkpointId: string
  gatewayId: string
  sequence: number          // monotonically increasing, never resets
  receiptHeadHash: string   // hash of most recent receipt
  stateRootHash: string     // hash over delegation+revocation+reputation state
  delegationCount: number
  revocationCount: number
  receiptCount: number
  protocolVersion: string
  createdAt: string
  previousCheckpointHash: string  // links to prior checkpoint
  signature: string         // signed by gateway key
}

// ── Integrity Report ──

export interface IntegrityReport {
  schemaVersion: number
  receiptChainValid: boolean
  receiptCount: number
  brokenLinks: string[]     // receipt IDs where chain hash doesn't match
  delegationCount: number
  revocationCount: number
  checkpointSequence: number
  checkpointValid: boolean
  errors: string[]
}

// ── Checkpoint Callback (external anchoring) ──

export type CheckpointCallback = (hash: string, sequence: number) => void | Promise<void>

// ══════════════════════════════════════════════════════════════════
// StorageOperations — atomic read/write methods
// Used inside transaction callbacks. Each method operates within
// the transaction boundary when called via tx parameter.
// ══════════════════════════════════════════════════════════════════

export interface StorageOperations {
  // ── Agents ──
  putAgent(agent: StoredAgentRecord): Promise<void>
  getAgent(agentId: string): Promise<StoredAgentRecord | null>
  listAgents(): Promise<StoredAgentRecord[]>

  // ── Delegations ──
  putDelegation(delegation: Delegation): Promise<void>
  getDelegation(delegationId: string): Promise<Delegation | null>
  getDelegationsForAgent(agentPublicKey: string): Promise<Delegation[]>

  // ── Spend (reserve/commit/release — prevents race conditions) ──
  reserveSpend(delegationId: string, amount: number, currency: string, ttlSeconds?: number): Promise<SpendReservationResult>
  commitSpend(reservationId: string): Promise<boolean>
  releaseSpend(reservationId: string): Promise<boolean>
  getSpentAmount(delegationId: string): Promise<number>

  // ── Revocations (append-only events) ──
  appendRevocation(revocation: RevocationRecord): Promise<void>
  isRevoked(delegationId: string): Promise<boolean>
  getRevocationsBy(revokedBy: string): Promise<RevocationRecord[]>

  // ── Receipts (append-only event log) ──
  appendReceipt(receipt: ActionReceipt): Promise<void>
  getReceipt(receiptId: string): Promise<ActionReceipt | null>
  queryReceipts(filter: ReceiptFilter, limit?: number, cursor?: string): Promise<CursorPage<ActionReceipt>>
  getReceiptCount(agentId?: string, scope?: string): Promise<number>
  /** GDPR tombstone: redacts payload but preserves hash chain + signature */
  tombstoneReceipt(receiptId: string, reason: string): Promise<boolean>

  // ── Reputation (derived state — cache of receipt projections) ──
  getReputation(agentId: string, scope: string): Promise<ScopedReputation | null>
  putReputation(rep: ScopedReputation): Promise<void>

  // ── Demotions (append-only, permanent, never deleted) ──
  appendDemotion(demotion: DemotionEvent): Promise<void>
  getDemotionCount(agentId: string): Promise<number>
  getDemotions(agentId: string): Promise<DemotionEvent[]>

  // ── Key Rotations (append-only events) ──
  appendKeyRotation(entry: KeyRotationEntry): Promise<void>
  getKeyRotations(publicKey: string): Promise<KeyRotationEntry[]>

  // ── Replay Protection ──
  checkAndStoreNonce(requestId: string, ttlSeconds: number): Promise<boolean>
}

// ══════════════════════════════════════════════════════════════════
// StorageBackend — the primary persistence interface
// Extends StorageOperations with lifecycle, transactions, and
// checkpoint management.
// ══════════════════════════════════════════════════════════════════

export interface StorageBackend extends StorageOperations {
  /** Initialize the backend (create tables, run migrations, etc) */
  initialize(): Promise<void>

  /** Clean shutdown */
  close(): Promise<void>

  /**
   * Run multiple operations in an atomic ACID transaction.
   * If any operation throws, ALL operations roll back.
   * The callback receives a transactional StorageOperations object.
   * CRITICAL: Use tx methods inside the callback, not the outer backend.
   */
  transaction<T>(fn: (tx: StorageOperations) => Promise<T>): Promise<T>

  /**
   * Verify integrity of persisted state on startup.
   * Checks: receipt chain hashes, checkpoint sequence monotonicity,
   * delegation/revocation consistency, schema version.
   * Gateway should enter read-only mode if this returns errors.
   */
  verifyIntegrity(): Promise<IntegrityReport>

  /**
   * Rebuild derived state (reputation, spend totals) from event log.
   * Called when cache and events disagree, or after recovery.
   */
  rebuildDerivedState(): Promise<void>

  /** Prune expired replay nonces and spend reservations */
  pruneExpired(): Promise<{ nonces: number; reservations: number }>

  // ── Checkpoints (signed state snapshots) ──

  /** Generate and store a new checkpoint. Returns the checkpoint. */
  createCheckpoint(gatewayId: string, gatewayPrivateKey: string): Promise<GatewayCheckpoint>

  /** Get the latest checkpoint (for rollback detection on startup) */
  getLatestCheckpoint(): Promise<GatewayCheckpoint | null>

  /** Register a callback for external checkpoint anchoring.
   *  Called after every createCheckpoint with (hash, sequence).
   *  Default: noop. In production: log, webhook, email, etc.
   *  The system cannot prove its own temporal integrity from within. */
  onCheckpoint(callback: CheckpointCallback): void

  // ── Export/Import ──

  /** Export receipts as a signed, self-contained verifiable bundle */
  exportReceipts(filter: ReceiptFilter): Promise<{ receipts: ActionReceipt[]; chainValid: boolean }>
}
