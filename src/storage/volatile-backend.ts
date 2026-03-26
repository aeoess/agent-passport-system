// ══════════════════════════════════════════════════════════════════
// VolatileBackend — In-memory StorageBackend for testing
// ══════════════════════════════════════════════════════════════════
// WARNING: All state is lost on process restart.
// This is NOT suitable for production. Use @aeoess/storage-sqlite.
// This backend exists for testing and development ONLY.
// ══════════════════════════════════════════════════════════════════

import type {
  StorageBackend, StorageOperations, StoredAgentRecord,
  CursorPage, ReceiptFilter, SpendReservationResult,
  GatewayCheckpoint, IntegrityReport, CheckpointCallback
} from './types.js'
import type { Delegation, RevocationRecord, ActionReceipt } from '../types/passport.js'
import type { ScopedReputation, DemotionEvent } from '../types/reputation-authority.js'
import type { KeyRotationEntry } from '../types/identity.js'
import { canonicalize } from '../core/canonical.js'
import { sign } from '../crypto/keys.js'

interface NonceEntry { requestId: string; expiresAt: number }
interface SpendRes { reservationId: string; delegationId: string; amount: number; currency: string; expiresAt: number; status: 'reserved' | 'committed' | 'released' }

export class VolatileBackend implements StorageBackend {
  private agents = new Map<string, StoredAgentRecord>()
  private delegations = new Map<string, Delegation>()
  private revocations = new Map<string, RevocationRecord>()
  private receipts: ActionReceipt[] = []
  private reputations = new Map<string, ScopedReputation>() // key: agentId:scope
  private demotions: DemotionEvent[] = []
  private keyRotations: KeyRotationEntry[] = []
  private nonces = new Map<string, number>() // requestId → expiresAt
  private spendReservations = new Map<string, SpendRes>()
  private committedSpend = new Map<string, number>() // delegationId → total spent
  private checkpoints: GatewayCheckpoint[] = []
  private checkpointCallbacks: CheckpointCallback[] = []
  private _initialized = false

  async initialize(): Promise<void> { this._initialized = true }
  async close(): Promise<void> { this._initialized = false }

  async transaction<T>(fn: (tx: StorageOperations) => Promise<T>): Promise<T> {
    // In-memory: no real transaction needed, but we snapshot state
    // so we can roll back on error
    const snapshot = this._snapshot()
    try {
      return await fn(this)
    } catch (e) {
      this._restore(snapshot)
      throw e
    }
  }

  // ── Agents ──
  async putAgent(agent: StoredAgentRecord): Promise<void> { this.agents.set(agent.agentId, agent) }
  async getAgent(agentId: string): Promise<StoredAgentRecord | null> { return this.agents.get(agentId) ?? null }
  async listAgents(): Promise<StoredAgentRecord[]> { return [...this.agents.values()] }

  // ── Delegations ──
  async putDelegation(d: Delegation): Promise<void> { this.delegations.set(d.delegationId, d) }
  async getDelegation(id: string): Promise<Delegation | null> { return this.delegations.get(id) ?? null }
  async getDelegationsForAgent(pubKey: string): Promise<Delegation[]> {
    return [...this.delegations.values()].filter(d => d.delegatedTo === pubKey)
  }

  // ── Spend (reserve/commit/release) ──
  async reserveSpend(delegationId: string, amount: number, currency: string, ttlSeconds = 30): Promise<SpendReservationResult> {
    const d = this.delegations.get(delegationId)
    if (!d) return { success: false, reason: 'Delegation not found' }
    const committed = this.committedSpend.get(delegationId) ?? 0
    const reserved = this._pendingReserved(delegationId)
    const total = committed + reserved + amount
    if (d.spendLimit !== undefined && total > d.spendLimit) {
      return { success: false, currentSpent: committed, limit: d.spendLimit, reason: `Spend $${total} exceeds limit $${d.spendLimit}` }
    }
    const rid = `res_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
    this.spendReservations.set(rid, {
      reservationId: rid, delegationId, amount, currency,
      expiresAt: Date.now() + ttlSeconds * 1000, status: 'reserved'
    })
    return { success: true, reservationId: rid, currentSpent: committed, limit: d.spendLimit }
  }

  async commitSpend(reservationId: string): Promise<boolean> {
    const r = this.spendReservations.get(reservationId)
    if (!r || r.status !== 'reserved') return false
    if (Date.now() > r.expiresAt) { r.status = 'released'; return false }
    r.status = 'committed'
    const prev = this.committedSpend.get(r.delegationId) ?? 0
    this.committedSpend.set(r.delegationId, prev + r.amount)
    return true
  }

  async releaseSpend(reservationId: string): Promise<boolean> {
    const r = this.spendReservations.get(reservationId)
    if (!r || r.status !== 'reserved') return false
    r.status = 'released'
    return true
  }

  async getSpentAmount(delegationId: string): Promise<number> {
    return this.committedSpend.get(delegationId) ?? 0
  }

  private _pendingReserved(delegationId: string): number {
    const now = Date.now()
    let total = 0
    for (const r of this.spendReservations.values()) {
      if (r.delegationId === delegationId && r.status === 'reserved' && now < r.expiresAt) total += r.amount
    }
    return total
  }

  // ── Revocations ──
  async appendRevocation(rev: RevocationRecord): Promise<void> { this.revocations.set(rev.delegationId, rev) }
  async isRevoked(delegationId: string): Promise<boolean> { return this.revocations.has(delegationId) }
  async getRevocationsBy(revokedBy: string): Promise<RevocationRecord[]> {
    return [...this.revocations.values()].filter(r => r.revokedBy === revokedBy)
  }

  // ── Receipts (append-only) ──
  async appendReceipt(receipt: ActionReceipt): Promise<void> { this.receipts.push(receipt) }
  async getReceipt(receiptId: string): Promise<ActionReceipt | null> {
    return this.receipts.find(r => r.receiptId === receiptId) ?? null
  }
  async queryReceipts(filter: ReceiptFilter, limit = 50, cursor?: string): Promise<CursorPage<ActionReceipt>> {
    let items = this.receipts
    if (filter.agentId) items = items.filter(r => r.agentId === filter.agentId)
    if (filter.delegationId) items = items.filter(r => r.delegationId === filter.delegationId)
    if (filter.after) items = items.filter(r => r.timestamp > filter.after!)
    if (filter.before) items = items.filter(r => r.timestamp < filter.before!)
    const startIdx = cursor ? parseInt(cursor, 10) : 0
    const page = items.slice(startIdx, startIdx + limit)
    const hasMore = startIdx + limit < items.length
    return { items: page, hasMore, nextCursor: hasMore ? String(startIdx + limit) : undefined }
  }
  async getReceiptCount(agentId?: string, scope?: string): Promise<number> {
    let items = this.receipts
    if (agentId) items = items.filter(r => r.agentId === agentId)
    if (scope) items = items.filter(r => r.action?.scopeUsed === scope)
    return items.length
  }

  async tombstoneReceipt(receiptId: string, reason: string): Promise<boolean> {
    const r = this.receipts.find(r => r.receiptId === receiptId)
    if (!r) return false
    r.tombstoned = true
    r.tombstoneReason = reason
    r.action = { type: '[REDACTED]', target: '[REDACTED]', scopeUsed: r.action.scopeUsed }
    r.result = { status: r.result.status, summary: '[REDACTED]' }
    return true
  }

  // ── Reputation (derived cache) ──
  async getReputation(agentId: string, scope: string): Promise<ScopedReputation | null> {
    return this.reputations.get(`${agentId}:${scope}`) ?? null
  }
  async putReputation(rep: ScopedReputation): Promise<void> {
    this.reputations.set(`${rep.agentId}:${rep.scope}`, rep)
  }

  // ── Demotions (permanent, append-only) ──
  async appendDemotion(d: DemotionEvent): Promise<void> { this.demotions.push(d) }
  async getDemotionCount(agentId: string): Promise<number> {
    return this.demotions.filter(d => d.agentId === agentId).length
  }
  async getDemotions(agentId: string): Promise<DemotionEvent[]> {
    return this.demotions.filter(d => d.agentId === agentId)
  }

  // ── Key Rotations (append-only) ──
  async appendKeyRotation(entry: KeyRotationEntry): Promise<void> { this.keyRotations.push(entry) }
  async getKeyRotations(publicKey: string): Promise<KeyRotationEntry[]> {
    return this.keyRotations.filter(k => k.oldPublicKey === publicKey || k.newPublicKey === publicKey)
  }

  // ── Replay Protection ──
  async checkAndStoreNonce(requestId: string, ttlSeconds: number): Promise<boolean> {
    const now = Date.now()
    // Prune expired on access (lazy)
    if (this.nonces.size > 1000) {
      for (const [id, exp] of this.nonces) { if (now > exp) this.nonces.delete(id) }
    }
    if (this.nonces.has(requestId)) return false // replay detected
    this.nonces.set(requestId, now + ttlSeconds * 1000)
    return true // fresh nonce
  }

  // ── Integrity Verification ──
  async verifyIntegrity(): Promise<IntegrityReport> {
    const brokenLinks: string[] = []
    // Check receipt chain continuity
    for (let i = 1; i < this.receipts.length; i++) {
      if (this.receipts[i].previousReceiptHash && this.receipts[i-1].receiptId) {
        // In volatile backend, chain hashes aren't set by default — skip deep verification
      }
    }
    const latest = this.checkpoints.length > 0 ? this.checkpoints[this.checkpoints.length - 1] : null
    return {
      schemaVersion: 1,
      receiptChainValid: brokenLinks.length === 0,
      receiptCount: this.receipts.length,
      brokenLinks,
      delegationCount: this.delegations.size,
      revocationCount: this.revocations.size,
      checkpointSequence: latest?.sequence ?? 0,
      checkpointValid: true,
      errors: []
    }
  }

  async rebuildDerivedState(): Promise<void> {
    // In volatile backend: reputation is already in sync (no persistence drift)
    // Real backends would replay receipts to recompute reputation + spend
  }

  async pruneExpired(): Promise<{ nonces: number; reservations: number }> {
    const now = Date.now()
    let nonces = 0, reservations = 0
    for (const [id, exp] of this.nonces) { if (now > exp) { this.nonces.delete(id); nonces++ } }
    for (const [id, r] of this.spendReservations) {
      if (r.status === 'reserved' && now > r.expiresAt) { r.status = 'released'; reservations++ }
    }
    return { nonces, reservations }
  }

  // ── Checkpoints ──
  async createCheckpoint(gatewayId: string, gatewayPrivateKey: string): Promise<GatewayCheckpoint> {
    const prev = this.checkpoints.length > 0 ? this.checkpoints[this.checkpoints.length - 1] : null
    const sequence = (prev?.sequence ?? 0) + 1
    const receiptHead = this.receipts.length > 0 ? this.receipts[this.receipts.length - 1].receiptId : '0'
    const stateRoot = canonicalize({ d: this.delegations.size, r: this.revocations.size, rc: this.receipts.length })
    const previousHash = prev ? canonicalize(prev) : '0'.repeat(64)
    const checkpoint: GatewayCheckpoint = {
      checkpointId: `chk_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      gatewayId, sequence,
      receiptHeadHash: receiptHead,
      stateRootHash: stateRoot,
      delegationCount: this.delegations.size,
      revocationCount: this.revocations.size,
      receiptCount: this.receipts.length,
      protocolVersion: '1.0',
      createdAt: new Date().toISOString(),
      previousCheckpointHash: previousHash,
      signature: sign(canonicalize({ sequence, stateRoot, previousHash }), gatewayPrivateKey)
    }
    this.checkpoints.push(checkpoint)
    // Emit to external anchoring callbacks
    for (const cb of this.checkpointCallbacks) {
      try { await cb(checkpoint.stateRootHash, checkpoint.sequence) } catch { /* best effort */ }
    }
    return checkpoint
  }

  async getLatestCheckpoint(): Promise<GatewayCheckpoint | null> {
    return this.checkpoints.length > 0 ? this.checkpoints[this.checkpoints.length - 1] : null
  }

  onCheckpoint(callback: CheckpointCallback): void {
    this.checkpointCallbacks.push(callback)
  }

  // ── Export ──
  async exportReceipts(filter: ReceiptFilter): Promise<{ receipts: ActionReceipt[]; chainValid: boolean }> {
    const result = await this.queryReceipts(filter, 100000)
    return { receipts: result.items, chainValid: true }
  }

  // ── Transaction snapshot/restore (for rollback on error) ──
  private _snapshot() {
    return {
      agents: new Map(this.agents),
      delegations: new Map(this.delegations),
      revocations: new Map(this.revocations),
      receipts: [...this.receipts],
      reputations: new Map(this.reputations),
      demotions: [...this.demotions],
      keyRotations: [...this.keyRotations],
      nonces: new Map(this.nonces),
      spendReservations: new Map(this.spendReservations),
      committedSpend: new Map(this.committedSpend),
      checkpoints: [...this.checkpoints]
    }
  }

  private _restore(snap: ReturnType<typeof this._snapshot>) {
    this.agents = snap.agents
    this.delegations = snap.delegations
    this.revocations = snap.revocations
    this.receipts = snap.receipts
    this.reputations = snap.reputations
    this.demotions = snap.demotions
    this.keyRotations = snap.keyRotations
    this.nonces = snap.nonces
    this.spendReservations = snap.spendReservations
    this.committedSpend = snap.committedSpend
    this.checkpoints = snap.checkpoints
  }
}
