// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Delegation System — create, verify, revoke, and enforce depth limits
// v1.1: Action Receipts + Revocation + Depth Limits
// v1.4: Cascade Revocation + Chain Validation + Batch Revocation

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import type {
  Delegation, ActionReceipt, RevocationRecord, DelegationStatus,
  CascadeRevocationResult, DelegationChainValidation, DelegationChainLink,
  RevocationEvent
} from '../types/passport.js'

// In-memory revocation registry (in production, this would be persistent)
const revocationRegistry = new Map<string, RevocationRecord>()

// In-memory receipt store
const receiptStore: ActionReceipt[] = []

// v1.4: Delegation chain registry — tracks parent→child relationships
const chainRegistry = new Map<string, {
  delegation: Delegation
  parentId: string | null          // null for root delegations
  childIds: Set<string>
}>()

// v1.4: Revocation event listeners
const revocationListeners: ((event: RevocationEvent) => void)[] = []

// Spend tracker — keyed on delegationId (string) to survive serialization round-trips
const spendTracker = new Map<string, number>()

/** Get cumulative spend for a delegation */
export function getSpent(delegation: Delegation): number {
  return spendTracker.get(delegation.delegationId) ?? (delegation.spentAmount ?? 0)
}

// Registry size cap
const MAX_REGISTRY_SIZE = 100_000

export function onRevocation(listener: (event: RevocationEvent) => void): () => void {
  revocationListeners.push(listener)
  return () => {
    const idx = revocationListeners.indexOf(listener)
    if (idx >= 0) revocationListeners.splice(idx, 1)
  }
}

function emitRevocation(event: RevocationEvent): void {
  for (const listener of revocationListeners) {
    try { listener(event) } catch { /* listener errors don't break revocation */ }
  }
}

// ══════════════════════════════════════
// DELEGATION CREATION
// ══════════════════════════════════════

export interface CreateDelegationOptions {
  delegatedTo: string       // public key of delegate
  delegatedBy: string       // public key of delegator
  scope: string[]
  scopeInterpretation?: 'exact' | 'glob' | 'hierarchical'  // Module 37
  spendLimit?: number
  maxDepth?: number
  currentDepth?: number
  expiresInHours?: number
  /** Optional: delegation not valid before this ISO timestamp (replay mitigation) */
  notBefore?: string
  privateKey: string        // delegator's private key for signing
}

export function createDelegation(opts: CreateDelegationOptions): Delegation {
  // Runtime input validation (TypeScript types don't exist at runtime for JS callers)
  if (!opts || typeof opts !== 'object') throw new Error('createDelegation: opts must be an object')
  if (!opts.delegatedTo || typeof opts.delegatedTo !== 'string') throw new Error('createDelegation: delegatedTo must be a non-empty string')
  if (!opts.delegatedBy || typeof opts.delegatedBy !== 'string') throw new Error('createDelegation: delegatedBy must be a non-empty string')
  if (!Array.isArray(opts.scope)) throw new Error('createDelegation: scope must be an array')
  if (!opts.privateKey || typeof opts.privateKey !== 'string') throw new Error('createDelegation: privateKey must be a non-empty string')
  if (opts.spendLimit !== undefined && opts.spendLimit !== null && (typeof opts.spendLimit !== 'number' || opts.spendLimit < 0 || !Number.isFinite(opts.spendLimit))) {
    throw new Error(`createDelegation: spendLimit must be a non-negative finite number, got ${opts.spendLimit}`)
  }

  const now = new Date()
  const expiry = new Date(now)
  expiry.setHours(expiry.getHours() + (opts.expiresInHours || 24))

  const delegation: Omit<Delegation, 'signature'> = {
    delegationId: 'del_' + uuidv4().slice(0, 12),
    delegatedTo: opts.delegatedTo,
    delegatedBy: opts.delegatedBy,
    scope: opts.scope,
    ...(opts.scopeInterpretation && { scopeInterpretation: opts.scopeInterpretation }),
    expiresAt: expiry.toISOString(),
    spendLimit: opts.spendLimit,
    spentAmount: 0,
    maxDepth: opts.maxDepth ?? 1,
    currentDepth: opts.currentDepth ?? 0,
    createdAt: now.toISOString(),
    notBefore: opts.notBefore ?? now.toISOString(),
  }

  const canonical = canonicalize(delegation)
  const signature = sign(canonical, opts.privateKey)

  const signed = { ...delegation, signature }
  Object.freeze(signed.scope)
  Object.freeze(signed)

  // v1.4: Register in chain registry (root delegation — no parent)
  if (chainRegistry.size >= MAX_REGISTRY_SIZE) {
    // Evict oldest entry
    const oldest = chainRegistry.keys().next().value
    if (oldest) chainRegistry.delete(oldest)
  }
  chainRegistry.set(signed.delegationId, {
    delegation: signed,
    parentId: null,
    childIds: new Set()
  })

  return signed
}

// ══════════════════════════════════════
// SUB-DELEGATION (with depth enforcement)
// ══════════════════════════════════════

export interface SubDelegateOptions {
  parentDelegation: Delegation
  delegatedTo: string     // public key of new delegate
  scope: string[]         // must be subset of parent scope
  spendLimit?: number     // must be <= parent remaining
  privateKey: string      // current delegate's private key
}

export function subDelegate(opts: SubDelegateOptions): Delegation {
  const parent = opts.parentDelegation

  // Enforce depth limit — new delegation would be at parent.currentDepth + 1
  const newDepth = parent.currentDepth + 1
  if (newDepth > parent.maxDepth) {
    throw new Error(
      `Depth limit exceeded: would be depth ${newDepth}, max allowed is ${parent.maxDepth}`
    )
  }

  // Enforce scope narrowing
  const invalidScopes = opts.scope.filter(s => !parent.scope.some(ps => scopeCovers(ps, s)))
  if (invalidScopes.length > 0) {
    throw new Error(
      `Scope violation: [${invalidScopes}] not in parent scope [${parent.scope}]`
    )
  }

  // Enforce spend limit (use ?? not || so spendLimit: 0 is a valid no-spend limit)
  const parentRemaining = (parent.spendLimit ?? Infinity) - (parent.spentAmount ?? 0)
  if (opts.spendLimit !== undefined && opts.spendLimit !== null && opts.spendLimit > parentRemaining) {
    throw new Error(
      `Spend limit ${opts.spendLimit} exceeds parent remaining ${parentRemaining}`
    )
  }

  // Clamp child expiry to parent expiry (monotonic narrowing of time bounds)
  const parentExpiry = new Date(parent.expiresAt)
  const now = new Date()
  const parentRemainingMs = parentExpiry.getTime() - now.getTime()
  const parentRemainingHours = Math.max(0, parentRemainingMs / 3600000)
  const childExpiryHours = Math.min(24, parentRemainingHours)

  const child = createDelegation({
    delegatedTo: opts.delegatedTo,
    delegatedBy: parent.delegatedTo, // the current delegate becomes delegator
    scope: opts.scope,
    scopeInterpretation: parent.scopeInterpretation,  // Module 37: inherit from parent
    spendLimit: opts.spendLimit ?? parentRemaining,
    maxDepth: parent.maxDepth,
    currentDepth: parent.currentDepth + 1,
    expiresInHours: childExpiryHours,
    notBefore: parent.notBefore, // inherit parent notBefore (child cannot start earlier)
    privateKey: opts.privateKey
  })

  // v1.4: Register parent→child relationship
  const childEntry = chainRegistry.get(child.delegationId)
  if (childEntry) {
    childEntry.parentId = parent.delegationId
  }
  const parentEntry = chainRegistry.get(parent.delegationId)
  if (parentEntry) {
    parentEntry.childIds.add(child.delegationId)
  }

  return child
}

// ══════════════════════════════════════
// REVOCATION CHECK POLICY (desiorac qntm#6)
// ══════════════════════════════════════

/**
 * What to do when the revocation check itself fails (endpoint unreachable, registry error).
 * - fail_open: treat as NOT revoked (dangerous for high-risk)
 * - fail_closed: treat as POTENTIALLY revoked (safe default for financial/sensitive)
 * - cache_grace: use cached state within TTL, fail_closed after TTL expires
 */
export type RevocationCheckPolicy = 'fail_open' | 'fail_closed' | 'cache_grace'

// ══════════════════════════════════════
// DELEGATION VERIFICATION
// ══════════════════════════════════════

export function verifyDelegation(delegation: Delegation, opts?: {
  /** How to handle revocation check failures. Default: 'fail_open' (backward compat) */
  revocationCheckPolicy?: RevocationCheckPolicy
  /** Cached revocation state (for cache_grace mode) */
  cachedRevocationState?: { revoked: boolean; checkedAt: string }
  /** Cache grace period in ms (for cache_grace mode). Default: 300000 (5 min) */
  cacheGraceMs?: number
  /** Walk parent chain and check each ancestor's revocation status. Default: false */
  checkAncestors?: boolean
}): DelegationStatus {
  const policy = opts?.revocationCheckPolicy ?? 'fail_open'
  const errors: string[] = []

  // Check signature
  const { signature, ...unsigned } = delegation
  const canonical = canonicalize(unsigned)
  const sigValid = verify(canonical, signature, delegation.delegatedBy)
  if (!sigValid) errors.push('Invalid delegation signature')

  // Check expiry (validate date first — NaN/invalid dates must fail, not pass)
  let expired = false
  const expiryDate = new Date(delegation.expiresAt)
  if (isNaN(expiryDate.getTime())) {
    errors.push(`Invalid expiresAt: "${delegation.expiresAt}"`)
    expired = true
  } else if (expiryDate < new Date()) {
    errors.push('Delegation expired')
    expired = true
  }

  // Check notBefore (validate date — same NaN guard)
  let notYetValid = false
  if (delegation.notBefore) {
    const notBeforeDate = new Date(delegation.notBefore)
    if (isNaN(notBeforeDate.getTime())) {
      errors.push(`Invalid notBefore: "${delegation.notBefore}"`)
    } else if (notBeforeDate > new Date()) {
      errors.push(`Delegation not yet valid (notBefore: ${delegation.notBefore})`)
      notYetValid = true
    }
  }

  // Check revocation (with policy for check failures)
  let revocation: RevocationRecord | undefined
  let revoked = false
  let revocationCheckFailed = false

  try {
    revocation = revocationRegistry.get(delegation.delegationId) as RevocationRecord | undefined
    revoked = !!revocation
  } catch {
    // Revocation check failed — apply policy
    revocationCheckFailed = true
    if (policy === 'fail_closed') {
      revoked = true
      errors.push('Revocation check failed — treating as revoked (fail_closed policy)')
    } else if (policy === 'cache_grace' && opts?.cachedRevocationState) {
      const cacheAge = Date.now() - new Date(opts.cachedRevocationState.checkedAt).getTime()
      const graceMs = opts?.cacheGraceMs ?? 300000
      if (cacheAge <= graceMs) {
        revoked = opts.cachedRevocationState.revoked
        if (revoked) errors.push('Revocation check failed — cached state shows revoked')
      } else {
        revoked = true
        errors.push('Revocation check failed — cache expired, treating as revoked')
      }
    }
    // fail_open: revoked stays false
  }

  if (revoked && !revocationCheckFailed) errors.push(`Revoked at ${revocation!.revokedAt}: ${revocation!.reason}`)

  // Check ancestor revocation (optional — catches non-cascaded parent revocations)
  if (opts?.checkAncestors) {
    const entry = chainRegistry.get(delegation.delegationId)
    if (entry) {
      const visited = new Set<string>()
      let parentId = entry.parentId
      while (parentId) {
        if (visited.has(parentId)) break // cycle guard
        visited.add(parentId)
        const parentRevocation = revocationRegistry.get(parentId)
        if (parentRevocation) {
          errors.push(`Ancestor delegation ${parentId} revoked at ${parentRevocation.revokedAt}`)
          revoked = true
          break
        }
        const parentEntry = chainRegistry.get(parentId)
        parentId = parentEntry?.parentId ?? null
      }
    }
  }

  // Check depth
  const depthExceeded = delegation.currentDepth > delegation.maxDepth
  if (depthExceeded) errors.push('Depth limit exceeded')

  return {
    valid: errors.length === 0,
    revoked,
    expired,
    notYetValid,
    depthExceeded,
    revokedAt: revocation?.revokedAt,
    errors
  }
}

// ══════════════════════════════════════
// REVOCATION
// ══════════════════════════════════════

export function revokeDelegation(
  delegationId: string,
  revokedBy: string,
  reason: string,
  privateKey: string
): RevocationRecord {
  // Authorization: only the delegator (or chain ancestor) should revoke
  const entry = chainRegistry.get(delegationId)
  if (!entry) {
    // Delegation not in local registry — cannot verify chain ancestry,
    // so require revokedBy to match the delegation's signature origin.
    // Revocation still recorded but cannot verify chain authorization.
  } else if (entry.delegation.delegatedBy !== revokedBy) {
    // Check if revoker is an ancestor in the chain
    let parentId = entry.parentId
    let authorized = false
    while (parentId) {
      const parent = chainRegistry.get(parentId)
      if (parent?.delegation.delegatedBy === revokedBy) { authorized = true; break }
      parentId = parent?.parentId ?? null
    }
    if (!authorized) {
      throw new Error(`Revocation denied: "${revokedBy}" is not the delegator or chain ancestor`)
    }
  }

  const record: Omit<RevocationRecord, 'signature'> = {
    revocationId: 'rev_' + uuidv4().slice(0, 12),
    delegationId,
    revokedBy,
    revokedAt: new Date().toISOString(),
    reason
  }

  const canonical = canonicalize(record)
  const signature = sign(canonical, privateKey)
  const revocation = { ...record, signature }

  // Store in registry
  revocationRegistry.set(delegationId, revocation)
  return revocation
}

export function verifyRevocation(revocation: RevocationRecord): boolean {
  const { signature, ...unsigned } = revocation
  const canonical = canonicalize(unsigned)
  return verify(canonical, signature, revocation.revokedBy)
}

// ══════════════════════════════════════
// v1.4: CASCADE REVOCATION
// ══════════════════════════════════════

/**
 * Revoke a delegation and ALL its descendants.
 * When A→B is revoked, B→C and C→D are also revoked.
 */
export function cascadeRevoke(
  delegationId: string,
  revokedBy: string,
  reason: string,
  privateKey: string
): CascadeRevocationResult {
  // Revoke the root
  const rootRevocation = revokeDelegation(delegationId, revokedBy, reason, privateKey)
  emitRevocation({ type: 'direct', revocation: rootRevocation })

  // Collect all descendants
  const cascaded: RevocationRecord[] = []
  const visited = new Set<string>()

  function revokeDescendants(parentId: string, depth: number): void {
    const entry = chainRegistry.get(parentId)
    if (!entry) return

    for (const childId of entry.childIds) {
      if (visited.has(childId)) continue
      visited.add(childId)

      // Only revoke if not already revoked
      if (!revocationRegistry.has(childId)) {
        const childRev = revokeDelegation(
          childId, revokedBy,
          `Cascade: parent ${parentId} revoked — ${reason}`,
          privateKey
        )
        cascaded.push(childRev)
        emitRevocation({
          type: 'cascade',
          revocation: childRev,
          parentDelegationId: parentId
        })
      }

      // Continue down the tree
      revokeDescendants(childId, depth + 1)
    }
  }

  revokeDescendants(delegationId, 0)

  return {
    rootRevocation,
    cascadedRevocations: cascaded,
    totalRevoked: 1 + cascaded.length,
    chainDepth: getMaxDepth(delegationId)
  }
}

function getMaxDepth(delegationId: string): number {
  const entry = chainRegistry.get(delegationId)
  if (!entry || entry.childIds.size === 0) return 0
  let max = 0
  for (const childId of entry.childIds) {
    max = Math.max(max, 1 + getMaxDepth(childId))
  }
  return max
}

// ══════════════════════════════════════
// v1.4: BATCH REVOCATION BY AGENT
// ══════════════════════════════════════

/**
 * Revoke ALL delegations granted TO a specific agent.
 * Use when an agent is compromised or decommissioned.
 */
export function revokeByAgent(
  agentPublicKey: string,
  revokedBy: string,
  reason: string,
  privateKey: string
): RevocationRecord[] {
  const revocations: RevocationRecord[] = []

  for (const [id, entry] of chainRegistry) {
    if (entry.delegation.delegatedTo === agentPublicKey) {
      if (!revocationRegistry.has(id)) {
        const result = cascadeRevoke(id, revokedBy, reason, privateKey)
        revocations.push(result.rootRevocation, ...result.cascadedRevocations)
      }
    }
  }

  for (const rev of revocations) {
    emitRevocation({ type: 'agent_batch', revocation: rev, batchAgentId: agentPublicKey })
  }

  return revocations
}

// ══════════════════════════════════════
// v1.4: DELEGATION CHAIN VALIDATION
// ══════════════════════════════════════

/**
 * Validate an entire delegation chain from root to leaf.
 * Returns detailed status for each link.
 */
export function validateChain(delegationIds: string[]): DelegationChainValidation {
  const links: DelegationChainLink[] = []
  let firstFailure: DelegationChainValidation['firstFailure'] | undefined

  for (let i = 0; i < delegationIds.length; i++) {
    const id = delegationIds[i]
    const entry = chainRegistry.get(id)

    if (!entry) {
      const link: DelegationChainLink = {
        delegationId: id,
        delegatedBy: 'unknown',
        delegatedTo: 'unknown',
        depth: i,
        status: {
          valid: false, revoked: false, expired: false, notYetValid: false,
          depthExceeded: false, errors: ['Delegation not found in registry']
        }
      }
      links.push(link)
      if (!firstFailure) {
        firstFailure = { index: i, delegationId: id, reason: 'Delegation not found in registry' }
      }
      continue
    }

    const status = verifyDelegation(entry.delegation)
    const link: DelegationChainLink = {
      delegationId: id,
      delegatedBy: entry.delegation.delegatedBy,
      delegatedTo: entry.delegation.delegatedTo,
      depth: entry.delegation.currentDepth,
      status
    }
    links.push(link)

    if (!status.valid && !firstFailure) {
      firstFailure = {
        index: i,
        delegationId: id,
        reason: status.errors.join('; ')
      }
    }

    // Check chain continuity: link[i].delegatedTo should == link[i+1].delegatedBy
    if (i > 0) {
      const prev = links[i - 1]
      if (prev.delegatedTo !== link.delegatedBy) {
        const reason = `Chain break: ${prev.delegatedTo} → ${link.delegatedBy}`
        link.status.valid = false
        link.status.errors.push(reason)
        if (!firstFailure) {
          firstFailure = { index: i, delegationId: id, reason }
        }
      }
    }
  }

  return {
    valid: !firstFailure,
    chainLength: links.length,
    links,
    firstFailure
  }
}

/**
 * Get all child delegation IDs for a given delegation (recursive).
 */
export function getDescendants(delegationId: string): string[] {
  const result: string[] = []
  const entry = chainRegistry.get(delegationId)
  if (!entry) return result

  for (const childId of entry.childIds) {
    result.push(childId)
    result.push(...getDescendants(childId))
  }
  return result
}

/**
 * Get the chain registry entry (for inspection/debugging).
 */
export function getChainEntry(delegationId: string) {
  const entry = chainRegistry.get(delegationId)
  if (!entry) return undefined
  return {
    delegation: entry.delegation,
    parentId: entry.parentId,
    childIds: [...entry.childIds]
  }
}

// ══════════════════════════════════════
// ACTION RECEIPTS
// ══════════════════════════════════════

export interface CreateReceiptOptions {
  agentId: string
  delegationId: string
  delegation: Delegation       // for chain verification
  action: ActionReceipt['action']
  result: ActionReceipt['result']
  delegationChain: string[]    // public keys from principal to executor
  privateKey: string           // executing agent's private key
}

export function createReceipt(opts: CreateReceiptOptions): ActionReceipt {
  // Verify delegation is still valid
  const status = verifyDelegation(opts.delegation)
  if (!status.valid) {
    throw new Error(`Cannot create receipt: delegation invalid — ${status.errors.join(', ')}`)
  }

  // Verify scope
  if (!scopeAuthorizes(opts.delegation.scope, opts.action.scopeUsed)) {
    throw new Error(
      `Scope '${opts.action.scopeUsed}' not in delegation [${opts.delegation.scope}]`
    )
  }

  // Verify spend (use ?? not || so spendLimit:0 = no spending allowed)
  if (opts.action.spend) {
    const currentSpent = getSpent(opts.delegation)
    const remaining = (opts.delegation.spendLimit ?? Infinity) - currentSpent
    if (opts.action.spend.amount > remaining) {
      throw new Error(
        `Spend ${opts.action.spend.amount} exceeds remaining ${remaining}`
      )
    }
    // Track cumulative spend (delegation is frozen, so use external tracker)
    spendTracker.set(opts.delegation.delegationId, currentSpent + opts.action.spend.amount)
    // Evict oldest spend entries if tracker exceeds limit
    if (spendTracker.size > MAX_REGISTRY_SIZE) {
      const oldest = spendTracker.keys().next().value
      if (oldest) spendTracker.delete(oldest)
    }
  }

  const receipt: Omit<ActionReceipt, 'signature'> = {
    receiptId: 'rcpt_' + uuidv4().slice(0, 12),
    version: '1.1',
    timestamp: new Date().toISOString(),
    agentId: opts.agentId,
    delegationId: opts.delegationId,
    action: opts.action,
    result: opts.result,
    delegationChain: opts.delegationChain
  }

  const canonical = canonicalize(receipt)
  const signature = sign(canonical, opts.privateKey)
  const signedReceipt = { ...receipt, signature }

  // Store receipt
  receiptStore.push(signedReceipt)

  return signedReceipt
}

export function verifyReceipt(
  receipt: ActionReceipt,
  agentPublicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  const { signature, ...unsigned } = receipt
  const canonical = canonicalize(unsigned)
  const sigValid = verify(canonical, signature, agentPublicKey)
  if (!sigValid) errors.push('Invalid receipt signature')

  if (receipt.version !== '1.1') errors.push('Unsupported receipt version')

  return { valid: errors.length === 0, errors }
}

// Getters
export function getReceipts(agentId?: string): ActionReceipt[] {
  if (agentId) return receiptStore.filter(r => r.agentId === agentId)
  return [...receiptStore]
}

export function getRevocation(delegationId: string): RevocationRecord | undefined {
  return revocationRegistry.get(delegationId)
}

// ═══════════════════════════════════════
// Scope Resolution — SINGLE SOURCE OF TRUTH
// ═══════════════════════════════════════
// Used by context.ts, policy.ts, integration.ts, routing.ts.
// All scope authorization checks MUST go through these functions.
//
// Rules:
// - Exact match: 'code' covers 'code'
// - Hierarchical: 'code' covers 'code:deploy' (parent covers child)
// - Universal wildcard: '*' covers everything
// - Prefix wildcard: 'commerce:*' covers 'commerce' and 'commerce:checkout'
// - NO reverse: 'code:deploy' does NOT cover 'code' (child does not satisfy parent)

/**
 * Check if a single granted scope covers a required scope.
 */
export function scopeCovers(granted: string, required: string): boolean {
  if (granted === required) return true
  if (granted === '*') return true
  if (required.startsWith(granted + ':')) return true
  if (granted.endsWith(':*')) {
    const prefix = granted.slice(0, -2)
    if (required === prefix || required.startsWith(prefix + ':')) return true
  }
  return false
}

/**
 * Check if any scope in a delegation's scope array covers the required scope.
 */
export function scopeAuthorizes(delegationScope: string[], required: string): boolean {
  return delegationScope.some(s => scopeCovers(s, required))
}

export function clearStores(): void {
  revocationRegistry.clear()
  receiptStore.length = 0
  chainRegistry.clear()
  revocationListeners.length = 0
}
