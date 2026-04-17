// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Delegation — pure primitives (signing + validation + scope resolution)
// ══════════════════════════════════════════════════════════════════════
// The module-scope revocation/receipt/chain/spend registries that used to
// live here have been split out to `DelegationStore` in @aeoess/gateway
// (src/sdk-migrated/core/delegation-store.ts). This module keeps ONLY the
// pure primitives downstream consumers rely on:
//
//   createDelegation, subDelegate   — signing + narrowing validation
//   verifyDelegation                — signature / expiry / notBefore checks
//   verifyRevocation, verifyReceipt — pure signature checks
//   scopeCovers, scopeAuthorizes    — scope resolution (SINGLE SOURCE OF TRUTH)
//   createReceipt                   — signing + scope/spend validation
//
// Stateful helpers (revokeDelegation, cascadeRevoke, validateChain,
// getReceipts, …) remain exported as deprecation stubs that throw and point
// callers to DelegationStore. The public SIGNATURES are unchanged so
// downstream consumers (Microsoft AGT, AgentID interop, SINT, InsumerAPI,
// our MCP server, Python SDK) compile without edits.
//
// Spend accumulation note: `createReceipt` now validates against the
// `delegation.spentAmount` baked into the delegation at sign time.
// Cumulative per-delegation spend across multiple receipt calls requires
// DelegationStore (gateway).
// ══════════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import type {
  Delegation, ActionReceipt, RevocationRecord, DelegationStatus,
  CascadeRevocationResult, DelegationChainValidation,
  RevocationEvent,
} from '../types/passport.js'

const MOVED =
  'This function has moved to DelegationStore in @aeoess/gateway. ' +
  'Instantiate a DelegationStore and call the corresponding method. ' +
  'See MIGRATION.md#delegation-store'

// ══════════════════════════════════════
// DELEGATION CREATION (pure)
// ══════════════════════════════════════

export interface CreateDelegationOptions {
  delegatedTo: string
  delegatedBy: string
  scope: string[]
  scopeInterpretation?: 'exact' | 'glob' | 'hierarchical'
  spendLimit?: number
  spendLimitUnit?: 'currency' | 'invocations'
  maxDepth?: number
  currentDepth?: number
  expiresInHours?: number
  notBefore?: string
  derivation_rights?: import('../types/passport.js').DerivationRights
  observation_policy?: import('../types/passport.js').ObservationPolicy
  credentialCheckPolicy?: import('../v2/credential-check-policy/types.js').CredentialCheckPolicy
  privateKey: string
}

export function createDelegation(opts: CreateDelegationOptions): Delegation {
  if (!opts || typeof opts !== 'object') throw new Error('createDelegation: opts must be an object')
  if (!opts.delegatedTo || typeof opts.delegatedTo !== 'string') throw new Error('createDelegation: delegatedTo must be a non-empty string')
  if (!opts.delegatedBy || typeof opts.delegatedBy !== 'string') throw new Error('createDelegation: delegatedBy must be a non-empty string')
  if (!Array.isArray(opts.scope)) throw new Error('createDelegation: scope must be an array')
  if (!opts.privateKey || typeof opts.privateKey !== 'string') throw new Error('createDelegation: privateKey must be a non-empty string')
  if (opts.spendLimit !== undefined && opts.spendLimit !== null && (typeof opts.spendLimit !== 'number' || opts.spendLimit < 0 || !Number.isFinite(opts.spendLimit))) {
    throw new Error(`createDelegation: spendLimit must be a non-negative finite number, got ${opts.spendLimit}`)
  }

  const hasTelemetryScope = opts.scope.some(s => s.startsWith('telemetry:'))
  if (hasTelemetryScope && !opts.derivation_rights) {
    throw new Error('createDelegation: telemetry scopes require derivation_rights to be defined')
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
    ...(opts.spendLimitUnit && { spendLimitUnit: opts.spendLimitUnit }),
    maxDepth: opts.maxDepth ?? 1,
    currentDepth: opts.currentDepth ?? 0,
    createdAt: now.toISOString(),
    notBefore: opts.notBefore ?? now.toISOString(),
    ...(opts.derivation_rights && { derivation_rights: opts.derivation_rights }),
    ...(opts.observation_policy && { observation_policy: opts.observation_policy }),
    ...(opts.credentialCheckPolicy && { credentialCheckPolicy: opts.credentialCheckPolicy }),
  }

  const canonical = canonicalize(delegation)
  const signature = sign(canonical, opts.privateKey)

  const signed = { ...delegation, signature }
  Object.freeze(signed.scope)
  Object.freeze(signed)
  return signed
}

// ══════════════════════════════════════
// SUB-DELEGATION — pure narrowing validation + signing
// ══════════════════════════════════════

export interface SubDelegateOptions {
  parentDelegation: Delegation
  delegatedTo: string
  scope: string[]
  spendLimit?: number
  spendLimitUnit?: 'currency' | 'invocations'
  derivation_rights?: import('../types/passport.js').DerivationRights
  privateKey: string
}

export function subDelegate(opts: SubDelegateOptions): Delegation {
  const parent = opts.parentDelegation

  const newDepth = parent.currentDepth + 1
  if (newDepth > parent.maxDepth) {
    throw new Error(
      `Depth limit exceeded: would be depth ${newDepth}, max allowed is ${parent.maxDepth}`,
    )
  }

  const invalidScopes = opts.scope.filter(s => !parent.scope.some(ps => scopeCovers(ps, s)))
  if (invalidScopes.length > 0) {
    throw new Error(
      `Scope violation: [${invalidScopes}] not in parent scope [${parent.scope}]`,
    )
  }

  if (opts.derivation_rights && parent.derivation_rights) {
    const pr = parent.derivation_rights
    const cr = opts.derivation_rights
    if (!pr.retention_permitted && cr.retention_permitted) {
      throw new Error('Derivation rights violation: parent does not permit retention')
    }
    if (pr.retention_ttl !== undefined && cr.retention_ttl !== undefined && cr.retention_ttl > pr.retention_ttl) {
      throw new Error(`Derivation rights violation: child retention_ttl (${cr.retention_ttl}) exceeds parent (${pr.retention_ttl})`)
    }
    if (!pr.export_permitted && cr.export_permitted) {
      throw new Error('Derivation rights violation: parent does not permit export')
    }
    if (pr.derivation_classes && cr.derivation_classes) {
      const invalid = cr.derivation_classes.filter(c => !pr.derivation_classes!.includes(c))
      if (invalid.length > 0) {
        throw new Error(`Derivation rights violation: classes [${invalid}] not in parent [${pr.derivation_classes}]`)
      }
    }
  }
  if (opts.derivation_rights && !parent.derivation_rights) {
    throw new Error('Derivation rights violation: parent delegation has no derivation_rights — child cannot introduce them')
  }

  const parentUnit = parent.spendLimitUnit ?? 'currency'
  const childUnit = opts.spendLimitUnit ?? parentUnit
  const unitsMatch = childUnit === parentUnit
  const parentRemaining = (parent.spendLimit ?? Infinity) - (parent.spentAmount ?? 0)
  if (unitsMatch && opts.spendLimit !== undefined && opts.spendLimit !== null && opts.spendLimit > parentRemaining) {
    throw new Error(
      `Spend limit ${opts.spendLimit} exceeds parent remaining ${parentRemaining}`,
    )
  }

  const parentExpiry = new Date(parent.expiresAt)
  const now = new Date()
  const parentRemainingMs = parentExpiry.getTime() - now.getTime()
  const parentRemainingHours = Math.max(0, parentRemainingMs / 3600000)
  const childExpiryHours = Math.min(24, parentRemainingHours)

  return createDelegation({
    delegatedTo: opts.delegatedTo,
    delegatedBy: parent.delegatedTo,
    scope: opts.scope,
    scopeInterpretation: parent.scopeInterpretation,
    spendLimit: opts.spendLimit ?? (unitsMatch ? parentRemaining : undefined),
    spendLimitUnit: opts.spendLimitUnit,
    maxDepth: parent.maxDepth,
    currentDepth: parent.currentDepth + 1,
    expiresInHours: childExpiryHours,
    notBefore: parent.notBefore,
    derivation_rights: opts.derivation_rights ?? parent.derivation_rights,
    observation_policy: parent.observation_policy,
    privateKey: opts.privateKey,
  })
}

// ══════════════════════════════════════
// REVOCATION CHECK POLICY (desiorac qntm#6)
// ══════════════════════════════════════

export type RevocationCheckPolicy = 'fail_open' | 'fail_closed' | 'cache_grace'

// ══════════════════════════════════════
// DELEGATION VERIFICATION — pure
// ══════════════════════════════════════
// Signature / expiry / notBefore / depth checks are pure. Revocation status
// is drawn exclusively from `opts.cachedRevocationState` — callers that need
// live revocation enforcement (or ancestor-chain walks) use DelegationStore.

export function verifyDelegation(delegation: Delegation, opts?: {
  /** How to handle revocation check failures. Default: 'fail_open' (backward compat) */
  revocationCheckPolicy?: RevocationCheckPolicy
  /** Cached revocation state (for cache_grace mode or stateless verification) */
  cachedRevocationState?: { revoked: boolean; checkedAt: string }
  /** Cache grace period in ms (for cache_grace mode). Default: 300000 (5 min) */
  cacheGraceMs?: number
  /** Walk parent chain and check each ancestor's revocation status.
   *  No-op without a DelegationStore; the option is preserved for API
   *  compatibility but ancestor walks now require store.validateChain(). */
  checkAncestors?: boolean
}): DelegationStatus {
  const policy = opts?.revocationCheckPolicy ?? 'fail_open'
  const errors: string[] = []

  const { signature, ...unsigned } = delegation
  const canonical = canonicalize(unsigned)
  const sigValid = verify(canonical, signature, delegation.delegatedBy)
  if (!sigValid) errors.push('Invalid delegation signature')

  let expired = false
  const expiryDate = new Date(delegation.expiresAt)
  if (isNaN(expiryDate.getTime())) {
    errors.push(`Invalid expiresAt: "${delegation.expiresAt}"`)
    expired = true
  } else if (expiryDate < new Date()) {
    errors.push('Delegation expired')
    expired = true
  }

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

  // Revocation status from caller-supplied cache only. Without cached state
  // the SDK cannot check revocation (registries live in DelegationStore); the
  // result is the same as a clean registry lookup that returned nothing —
  // revoked=false regardless of policy. The cache_grace path still honours
  // TTL; fail_closed/fail_open only differ once a check *has* happened and
  // produced an error, which is a gateway-side concern.
  let revoked = false
  let revokedAt: string | undefined
  if (opts?.cachedRevocationState) {
    if (policy === 'cache_grace') {
      const cacheAge = Date.now() - new Date(opts.cachedRevocationState.checkedAt).getTime()
      const graceMs = opts?.cacheGraceMs ?? 300000
      if (cacheAge <= graceMs) {
        revoked = opts.cachedRevocationState.revoked
      } else {
        revoked = true
        errors.push('Revocation cache expired, treating as revoked')
      }
    } else {
      revoked = opts.cachedRevocationState.revoked
    }
    if (revoked) {
      revokedAt = opts.cachedRevocationState.checkedAt
      errors.push(`Revoked (cached state checked ${opts.cachedRevocationState.checkedAt})`)
    }
  }

  const depthExceeded = delegation.currentDepth > delegation.maxDepth
  if (depthExceeded) errors.push('Depth limit exceeded')

  return {
    valid: errors.length === 0,
    revoked,
    expired,
    notYetValid,
    depthExceeded,
    revokedAt,
    errors,
  }
}

// ══════════════════════════════════════
// REVOCATION SIGNATURE (pure)
// ══════════════════════════════════════

export function verifyRevocation(revocation: RevocationRecord): boolean {
  const { signature, ...unsigned } = revocation
  const canonical = canonicalize(unsigned)
  return verify(canonical, signature, revocation.revokedBy)
}

// ══════════════════════════════════════
// ACTION RECEIPTS — pure (validation + signing)
// ══════════════════════════════════════

export interface CreateReceiptOptions {
  agentId: string
  delegationId: string
  delegation: Delegation
  action: ActionReceipt['action']
  result: ActionReceipt['result']
  delegationChain: string[]
  privateKey: string
}

export function createReceipt(opts: CreateReceiptOptions): ActionReceipt {
  const status = verifyDelegation(opts.delegation)
  if (!status.valid) {
    throw new Error(`Cannot create receipt: delegation invalid — ${status.errors.join(', ')}`)
  }

  if (!scopeAuthorizes(opts.delegation.scope, opts.action.scopeUsed)) {
    throw new Error(
      `Scope '${opts.action.scopeUsed}' not in delegation [${opts.delegation.scope}]`,
    )
  }

  if (opts.action.spend) {
    const baseline = opts.delegation.spentAmount ?? 0
    const remaining = (opts.delegation.spendLimit ?? Infinity) - baseline
    if (opts.action.spend.amount > remaining) {
      throw new Error(`Spend ${opts.action.spend.amount} exceeds remaining ${remaining}`)
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
    delegationChain: opts.delegationChain,
  }

  const canonical = canonicalize(receipt)
  const signature = sign(canonical, opts.privateKey)
  return { ...receipt, signature }
}

export function verifyReceipt(
  receipt: ActionReceipt,
  agentPublicKey: string,
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  const { signature, ...unsigned } = receipt
  const canonical = canonicalize(unsigned)
  const sigValid = verify(canonical, signature, agentPublicKey)
  if (!sigValid) errors.push('Invalid receipt signature')

  if (receipt.version !== '1.1') errors.push('Unsupported receipt version')

  return { valid: errors.length === 0, errors }
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

export function scopeAuthorizes(delegationScope: string[], required: string): boolean {
  return delegationScope.some(s => scopeCovers(s, required))
}

// ══════════════════════════════════════════════════════════════════════
// STATEFUL HELPERS — moved to DelegationStore in @aeoess/gateway
// ══════════════════════════════════════════════════════════════════════
// Public signatures preserved so downstream TypeScript compiles. Calls at
// runtime throw a MOVED error pointing to the gateway replacement.

export function revokeDelegation(
  _delegationId: string, _revokedBy: string, _reason: string, _privateKey: string,
): RevocationRecord { throw new Error(MOVED) }

export function cascadeRevoke(
  _delegationId: string, _revokedBy: string, _reason: string, _privateKey: string,
): CascadeRevocationResult { throw new Error(MOVED) }

export function revokeByAgent(
  _agentPublicKey: string, _revokedBy: string, _reason: string, _privateKey: string,
): RevocationRecord[] { throw new Error(MOVED) }

export function validateChain(_delegationIds: string[]): DelegationChainValidation {
  throw new Error(MOVED)
}

export function getDescendants(_delegationId: string): string[] { throw new Error(MOVED) }

export function getChainEntry(_delegationId: string): undefined {
  throw new Error(MOVED)
}

export function onRevocation(_listener: (event: RevocationEvent) => void): () => void {
  throw new Error(MOVED)
}

export function getReceipts(_agentId?: string): ActionReceipt[] { throw new Error(MOVED) }

export function getRevocation(_delegationId: string): RevocationRecord | undefined {
  throw new Error(MOVED)
}

export function getSpent(_delegation: Delegation): number { throw new Error(MOVED) }

/**
 * Back-compat no-op. The SDK no longer holds module-scope state, so there
 * is nothing to clear. Still exported because test suites historically
 * called it in beforeEach hooks.
 */
export function clearStores(): void {
  // Intentionally empty — DelegationStore.clear() replaces it.
}
