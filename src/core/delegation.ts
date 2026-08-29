// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
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
import { isRecord } from '../core/is-record.js'
import type {
  Delegation, ActionReceipt, RevocationRecord, DelegationStatus,
  CascadeRevocationResult, DelegationChainValidation,
  RevocationEvent,
} from '../types/passport.js'
import { canonicalizeForWrite } from './canonical.js'

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
  /** Absolute expiry (ISO 8601). When present it WINS over expiresInHours (strict
   *  precedence) and is used directly as the signed expiresAt field. Input only;
   *  never stored as a relative field. subDelegate uses this to pass an
   *  already-capped, absolute child expiry rather than a re-basable duration. */
  expiresAt?: string
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
  // Absolute expiresAt option wins (strict precedence); otherwise compute from the
  // duration with millisecond math. Never `|| 24` (which coerces a legitimate 0 into
  // 24h) and never setHours (which truncates fractional hours). expiresInHours of 0
  // yields immediate expiry; a negative duration yields a past expiry, consistent
  // with feasibility.ts. This matches the cross-chain.ts expiry pattern.
  const expiresAtIso = opts.expiresAt ?? new Date(now.getTime() + (opts.expiresInHours ?? 24) * 3600000).toISOString()

  const delegation: Omit<Delegation, 'signature'> = {
    delegationId: 'del_' + uuidv4().slice(0, 12),
    delegatedTo: opts.delegatedTo,
    delegatedBy: opts.delegatedBy,
    scope: opts.scope,
    ...(opts.scopeInterpretation && { scopeInterpretation: opts.scopeInterpretation }),
    expiresAt: expiresAtIso,
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

  const canonical = canonicalizeForWrite(delegation)
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
  /** Revocation posture for the PARENT check below. A sub-delegation mints
   *  new authority from the parent, so a caller who requires fresh
   *  revocation evidence before extending authority selects it here.
   *  Omitted leaves the previous behaviour: signature and expiry only. */
  revocation?: RevocationCheckOptions
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

  // Resolve the parent's spend dimension. A spend limit (even with the unit tag
  // omitted, which defaults to currency) or an explicit unit each establish one;
  // a parent with neither is unconstrained on spend.
  const parentHasSpendDimension = parent.spendLimit !== undefined || parent.spendLimitUnit !== undefined
  const parentUnit = parent.spendLimitUnit ?? (parent.spendLimit !== undefined ? 'currency' : undefined)
  const childUnit = opts.spendLimitUnit ?? parentUnit
  // Spend unit narrowing (locked Option A): once the parent
  // carries a spend dimension, a child may not change its unit at the narrowing
  // layer. A declared currency conversion belongs at the payment-rails layer (v2
  // preAuthorize), not in core subDelegate. A child may still introduce a unit on
  // an otherwise unconstrained parent, which is narrowing rather than conversion.
  if (parentHasSpendDimension && childUnit !== parentUnit) {
    throw new Error(
      `Spend unit change rejected at the narrowing layer: child spendLimitUnit "${childUnit}" differs from parent "${parentUnit}". subDelegate does not convert spend units; a declared currency conversion belongs at the payment-rails layer (v2 preAuthorize).`,
    )
  }
  const parentRemaining = (parent.spendLimit ?? Infinity) - (parent.spentAmount ?? 0)
  // Cap and inheritance apply only when child and parent share a finite spend
  // budget in the same unit. Gated explicitly so unit-compatibility and budget
  // narrowing stay separate concerns rather than riding one overloaded flag.
  const sharesFiniteParentBudget = parentUnit !== undefined && childUnit === parentUnit && parent.spendLimit !== undefined
  if (sharesFiniteParentBudget && opts.spendLimit !== undefined && opts.spendLimit !== null && opts.spendLimit > parentRemaining) {
    throw new Error(
      `Spend limit ${opts.spendLimit} exceeds parent remaining ${parentRemaining}`,
    )
  }

  // Temporal narrowing (creation-time). Capture now ONCE and reuse it for both the
  // expiry guard and the cap so the result is deterministic. The finite guard comes
  // first: a NaN expiry would slip past the `<= 0` reject (NaN <= 0 is false).
  const now = Date.now()
  const parentExpiryMs = Date.parse(parent.expiresAt)
  if (!Number.isFinite(parentExpiryMs)) {
    throw new Error('cannot sub-delegate: parent delegation has an invalid expiresAt')
  }
  if (parentExpiryMs - now <= 0) {
    throw new Error('cannot sub-delegate from an expired parent delegation')
  }
  // Verify the parent's signature (and not-before / expiry) before minting a child. Previously
  // subDelegate checked only the parent's expiry timestamp, so a parent with a forged signature
  // could still mint an authority-bearing child. Parity with the Python sub_delegate parent check.
  const parentStatus = verifyDelegation(parent, opts.revocation)
  if (!parentStatus.valid) {
    throw new Error(`cannot sub-delegate from an invalid parent: ${parentStatus.errors.join(', ')}`)
  }
  // Child's ABSOLUTE expiry: the tighter of the 24h ceiling and the parent's expiry.
  // Passed to createDelegation as an absolute expiresAt (not a duration), so it is
  // never re-based on a later now(), which is what let the child outlive the parent
  // by the compute gap.
  const childExpiresAt = new Date(Math.min(now + 24 * 3600000, parentExpiryMs)).toISOString()

  return createDelegation({
    delegatedTo: opts.delegatedTo,
    delegatedBy: parent.delegatedTo,
    scope: opts.scope,
    scopeInterpretation: parent.scopeInterpretation,
    spendLimit: opts.spendLimit ?? (sharesFiniteParentBudget ? parentRemaining : undefined),
    // Sign the RESOLVED unit, not the raw option. When the caller omits spendLimitUnit, childUnit
    // falls back to the parent's unit; passing opts.spendLimitUnit (undefined) here silently dropped
    // the parent's unit from the signed child, letting an invocations budget read as currency two
    // hops down. The narrowing guard above already enforces childUnit === parentUnit.
    spendLimitUnit: childUnit,
    maxDepth: parent.maxDepth,
    currentDepth: parent.currentDepth + 1,
    expiresAt: childExpiresAt,
    notBefore: parent.notBefore,
    derivation_rights: opts.derivation_rights ?? parent.derivation_rights,
    observation_policy: parent.observation_policy,
    privateKey: opts.privateKey,
  })
}

// ══════════════════════════════════════
// REVOCATION CHECK POLICY (desiorac qntm#6)
// ══════════════════════════════════════

/** How a verifier treats the revocation evidence it was given.
 *
 *  - `fail_open`   (default, backward compatible): missing or stale revocation
 *                  evidence does not block. Whatever cached state the caller
 *                  supplies is taken at face value, however old it is.
 *  - `cache_grace` cached evidence is honoured while it is inside the grace
 *                  window and treated as a revocation once it is outside it.
 *  - `fail_closed` the delegation is admissible only against revocation
 *                  evidence that is present AND inside the freshness bound.
 *                  Absent or stale evidence refuses; it does not assert that
 *                  a revocation was observed, only that none can be ruled out.
 *
 *  The three are observably different on the same input, which is the point:
 *  `fail_closed` used to be read into a local and never compared, so it ran
 *  the `fail_open` path and accepted two-hour-old revocation state.
 */
export type RevocationCheckPolicy = 'fail_open' | 'fail_closed' | 'cache_grace'

/** The complete set of accepted policy values, exported so a caller reading a
 *  policy out of configuration can check it before handing it over. */
export const REVOCATION_CHECK_POLICIES: readonly RevocationCheckPolicy[] =
  Object.freeze(['fail_open', 'fail_closed', 'cache_grace'])

/** Default freshness bound for cached revocation evidence, in milliseconds.
 *  Used by `cache_grace` as the grace window and by `fail_closed` as the
 *  maximum age of evidence it will accept. */
export const DEFAULT_REVOCATION_FRESHNESS_MS = 300000

/** The revocation posture a caller can select, as one object.
 *
 *  Every primitive in the SDK that verifies a delegation on the caller's
 *  behalf accepts this, so selecting `fail_closed` is reachable from a
 *  shipped entrypoint rather than only from a direct verifyDelegation call.
 *  Omitting it everywhere leaves the previous behaviour exactly: the
 *  policy defaults to `fail_open` and no revocation evidence is consulted. */
export interface RevocationCheckOptions {
  /** How to handle missing or stale revocation evidence. Default:
   *  'fail_open' (backward compat). See RevocationCheckPolicy. */
  revocationCheckPolicy?: RevocationCheckPolicy
  /** Cached revocation state. The SDK holds no revocation registry, so this
   *  is the entire evidence base; live lookups live in DelegationStore. */
  cachedRevocationState?: { revoked: boolean; checkedAt: string }
  /** Maximum accepted age of that evidence, in ms. Grace window for
   *  'cache_grace', freshness bound for 'fail_closed'. Default 300000. */
  cacheGraceMs?: number
}

// ══════════════════════════════════════
// DELEGATION VERIFICATION — pure
// ══════════════════════════════════════
// Signature / expiry / notBefore / depth checks are pure. Revocation status
// is drawn exclusively from `opts.cachedRevocationState` — callers that need
// live revocation enforcement (or ancestor-chain walks) use DelegationStore.

export function verifyDelegation(delegation: Delegation, opts?: RevocationCheckOptions & {
  /** Walk parent chain and check each ancestor's revocation status.
   *  No-op without a DelegationStore; the option is preserved for API
   *  compatibility but ancestor walks now require store.validateChain(). */
  checkAncestors?: boolean
}): DelegationStatus {
  // Null / undefined / non-object (attacker-deliverable JSON `null`) rejects
  // as an invalid delegation rather than throwing on the destructuring below.
  if (!isRecord(delegation)) {
    return {
      valid: false,
      revoked: false,
      expired: false,
      notYetValid: false,
      depthExceeded: false,
      errors: ['Invalid delegation: not an object'],
      revocationEvidence: 'absent',
    }
  }
  // A policy value the SDK does not recognise is a caller configuration error,
  // and it must not resolve to the most permissive branch by falling through
  // every comparison. 'FAIL_CLOSED' used to return valid true with no error
  // and no complaint: an integrator who typed the strictest setting in the
  // wrong case silently got the weakest one. The policy is chosen by the
  // integrator and never carried in the artifact being verified, so this can
  // only ever fire on the caller's own configuration, which is why it is loud
  // rather than a silent downgrade to fail_closed.
  const requestedPolicy = opts?.revocationCheckPolicy
  if (requestedPolicy !== undefined && !REVOCATION_CHECK_POLICIES.includes(requestedPolicy)) {
    throw new Error(
      `verifyDelegation: unknown revocationCheckPolicy ${JSON.stringify(requestedPolicy)}. ` +
      `Expected one of ${REVOCATION_CHECK_POLICIES.join(', ')}.`,
    )
  }
  const policy: RevocationCheckPolicy = requestedPolicy ?? 'fail_open'
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

  // Revocation status from caller-supplied cache only. The SDK holds no
  // revocation registry (that lives in DelegationStore in the gateway), so
  // `opts.cachedRevocationState` is the entire evidence base. What the three
  // policies disagree about is what to do when that evidence is missing or
  // old, and each of them now says something different about it.
  //
  // The evidence grade is computed first and reported on the result, so a
  // caller can tell "no evidence" from "evidence says not revoked" without
  // reading the policy back out of its own options.
  const freshnessMs = opts?.cacheGraceMs ?? DEFAULT_REVOCATION_FRESHNESS_MS
  const cached = opts?.cachedRevocationState
  let revocationEvidence: 'absent' | 'stale' | 'fresh' = 'absent'
  if (cached) {
    const checkedAtMs = new Date(cached.checkedAt).getTime()
    if (!Number.isFinite(checkedAtMs)) {
      // Graded BEFORE any window comparison, not by arithmetic on a sentinel.
      // Mapping an unparseable timestamp to an Infinity age and comparing it
      // against the window looked equivalent and was not: with
      // cacheGraceMs: Infinity, Infinity <= Infinity passed, so
      // checkedAt: 'not-a-date' graded FRESH and satisfied fail_closed. A
      // timestamp that cannot be read is not evidence of when anything was
      // checked, whatever the window is set to.
      revocationEvidence = 'stale'
    } else {
      // The window is bounded on BOTH sides. Evidence dated after the moment
      // it is read is not fresh either: a negative age used to pass the upper
      // bound, so checkedAt in the year 2999 graded fresh. There is no future
      // tolerance. A verifier whose clock lags the evidence source grades that
      // evidence stale, which fail_closed refuses, which is the safe direction
      // to be wrong in.
      const cacheAge = Date.now() - checkedAtMs
      revocationEvidence = cacheAge >= 0 && cacheAge <= freshnessMs ? 'fresh' : 'stale'
    }
  }

  let revoked = false
  let revokedAt: string | undefined
  if (cached) {
    if (policy === 'cache_grace' && revocationEvidence === 'stale') {
      // cache_grace converts expiry of the window into a revocation: the
      // shipped behaviour, kept.
      revoked = true
      errors.push('Revocation cache expired, treating as revoked')
    } else {
      revoked = cached.revoked
    }
    if (revoked) {
      revokedAt = cached.checkedAt
      errors.push(`Revoked (cached state checked ${cached.checkedAt})`)
    }
  }

  // fail_closed: admissibility requires revocation evidence that is present
  // and inside the freshness bound. Absent or stale evidence refuses without
  // claiming a revocation was observed — `revoked` stays false and the reason
  // is reported as an evidence failure, because asserting a revocation the
  // verifier never saw would be a different lie from the one being fixed.
  if (policy === 'fail_closed' && revocationEvidence !== 'fresh') {
    errors.push(
      revocationEvidence === 'absent'
        ? 'fail_closed: no revocation evidence supplied, revocation status unknown'
        : `fail_closed: revocation evidence is stale (older than ${freshnessMs}ms), revocation status unknown`,
    )
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
    revocationEvidence,
  }
}

// ══════════════════════════════════════
// REVOCATION SIGNATURE (pure)
// ══════════════════════════════════════

export function verifyRevocation(revocation: RevocationRecord): boolean {
  // Null / undefined / non-object rejects (unverifiable) rather than throwing
  // on the destructuring below.
  if (!isRecord(revocation)) return false
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
  /** Revocation posture for the delegation check below. Minting a receipt
   *  is the record that an action was taken under this delegation, so a
   *  caller who will not act on unknown revocation state selects
   *  fail_closed here. Omitted leaves the previous behaviour. */
  revocation?: RevocationCheckOptions
}

export function createReceipt(opts: CreateReceiptOptions): ActionReceipt {
  const status = verifyDelegation(opts.delegation, opts.revocation)
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

  const canonical = canonicalizeForWrite(receipt)
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
