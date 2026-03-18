// ══════════════════════════════════════════════════════════════════
// Cross-Chain Data Flow Authorization — Core Implementation
// ══════════════════════════════════════════════════════════════════
// Solves the Confused Deputy problem for multi-principal delegation.
//
// Core invariant: Authority from different principals may not be
// combined in a single effectful action unless the combination
// itself is explicitly authorized via a CrossChainPermit.
//
// Propagation invariant: Any artifact derived from tainted inputs
// inherits the union of their taint contexts unless transformed
// by an approved policy.
// ══════════════════════════════════════════════════════════════════

import { createHash, randomBytes } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  TaintLabel, TaintUsage, TaintSet,
  SignedAuthorityObject, CrossChainPermit,
  ExecutionFrame, FlowCheckResult, FlowVerdict,
  TaintTransformation, TransformationType
} from '../types/cross-chain.js'

// ── Taint Labels ──

/**
 * Create a taint label when data is accessed under a delegation.
 * Every read through the gateway produces a taint label.
 */
export function createTaintLabel(
  principalId: string,
  chainId: string,
  delegationId: string,
  usage: TaintUsage = 'same-context-only'
): TaintLabel {
  return {
    principalId,
    chainId,
    delegationId,
    usage,
    taintedAt: new Date().toISOString()
  }
}

/**
 * Merge multiple taint labels into a TaintSet.
 * Automatically detects cross-chain (multi-principal) taint.
 */
export function mergeTaints(...labels: TaintLabel[]): TaintSet {
  const principals = [...new Set(labels.map(l => l.principalId))]
  return {
    labels,
    principals,
    isCrossChain: principals.length > 1
  }
}

// ── Signed Authority Objects ──

/**
 * Wrap data in a Signed Authority Object.
 * The gateway calls this when returning data from a read operation.
 * The SAO binds the data to its delegation context cryptographically.
 */
export function createSAO(
  data: unknown,
  taint: TaintLabel,
  monitorPrivateKey: string,
  monitorPublicKey: string,
  expiresInMinutes: number = 60
): SignedAuthorityObject {
  const dataStr = typeof data === 'string' ? data : JSON.stringify(data)
  const dataHash = createHash('sha256').update(dataStr).digest('hex')
  const now = new Date()

  const payload = canonicalize({
    dataHash,
    taint,
    monitorPublicKey,
    createdAt: now.toISOString()
  })

  const monitorSignature = sign(payload, monitorPrivateKey)

  return {
    saoId: `sao-${randomBytes(8).toString('hex')}`,
    data,
    taint,
    dataHash,
    monitorSignature,
    monitorPublicKey,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + expiresInMinutes * 60000).toISOString()
  }
}

/**
 * Verify an SAO's integrity and monitor signature.
 */
export function verifySAO(sao: SignedAuthorityObject): boolean {
  const dataStr = typeof sao.data === 'string' ? sao.data : JSON.stringify(sao.data)
  const expectedHash = createHash('sha256').update(dataStr).digest('hex')

  if (expectedHash !== sao.dataHash) return false

  const payload = canonicalize({
    dataHash: sao.dataHash,
    taint: sao.taint,
    monitorPublicKey: sao.monitorPublicKey,
    createdAt: sao.createdAt
  })

  return verify(payload, sao.monitorSignature, sao.monitorPublicKey)
}

/**
 * Check if an SAO has expired.
 */
export function isSAOExpired(sao: SignedAuthorityObject): boolean {
  return new Date(sao.expiresAt) < new Date()
}

// ── Execution Frame ──

/**
 * Create a new execution frame for tracking session-level taint.
 */
export function createExecutionFrame(agentId: string): ExecutionFrame {
  return {
    frameId: `frame-${randomBytes(8).toString('hex')}`,
    agentId,
    accessedContexts: [],
    frameTaint: { labels: [], principals: [], isCrossChain: false },
    startedAt: new Date().toISOString(),
    active: true
  }
}

/**
 * Record a data access in the execution frame.
 * Called whenever the agent reads data through any delegation.
 */
export function recordAccess(frame: ExecutionFrame, taint: TaintLabel): ExecutionFrame {
  const accessedContexts = [...frame.accessedContexts, taint]
  return {
    ...frame,
    accessedContexts,
    frameTaint: mergeTaints(...accessedContexts)
  }
}

/**
 * Close an execution frame. No further accesses can be recorded.
 */
export function closeFrame(frame: ExecutionFrame): ExecutionFrame {
  return { ...frame, active: false }
}

// ── Cross-Chain Permits ──

/**
 * Create a cross-chain permit (source principal signs first).
 * The permit authorizes data from sourceContext to flow into
 * actions governed by destinationContext.
 */
export function createCrossChainPermit(opts: {
  sourcePrincipalId: string
  sourcePrincipalPublicKey: string
  sourceDataClasses: string[]
  destPrincipalId: string
  destPrincipalPublicKey: string
  destAllowedScopes: string[]
  purpose: string
  destinationConstraints?: string[]
  expiresInHours?: number
  sourcePrivateKey: string
}): Omit<CrossChainPermit, 'destinationSignature'> & { destinationSignature: '' } {
  const now = new Date()
  const expiresAt = new Date(now.getTime() + (opts.expiresInHours ?? 24) * 3600000).toISOString()

  const permitBody = {
    sourceContext: {
      principalId: opts.sourcePrincipalId,
      principalPublicKey: opts.sourcePrincipalPublicKey,
      dataClasses: opts.sourceDataClasses,
    },
    destinationContext: {
      principalId: opts.destPrincipalId,
      principalPublicKey: opts.destPrincipalPublicKey,
      allowedScopes: opts.destAllowedScopes,
    },
    purpose: opts.purpose,
    destinationConstraints: opts.destinationConstraints,
    createdAt: now.toISOString(),
    expiresAt,
  }

  const payload = canonicalize(permitBody)
  const sourceSignature = sign(payload, opts.sourcePrivateKey)

  return {
    permitId: `ccp-${randomBytes(8).toString('hex')}`,
    ...permitBody,
    revoked: false,
    sourceSignature,
    destinationSignature: '' // Destination must countersign
  }
}

/**
 * Countersign a cross-chain permit (destination principal).
 * Both signatures required for the permit to be valid.
 */
export function countersignPermit(
  permit: Omit<CrossChainPermit, 'destinationSignature'> & { destinationSignature: '' },
  destPrivateKey: string
): CrossChainPermit {
  const permitBody = {
    sourceContext: permit.sourceContext,
    destinationContext: permit.destinationContext,
    purpose: permit.purpose,
    destinationConstraints: permit.destinationConstraints,
    createdAt: permit.createdAt,
    expiresAt: permit.expiresAt,
  }
  const payload = canonicalize(permitBody)
  const destinationSignature = sign(payload, destPrivateKey)

  return { ...permit, destinationSignature }
}

/**
 * Verify a cross-chain permit: both signatures valid + not expired + not revoked.
 */
export function verifyCrossChainPermit(permit: CrossChainPermit): boolean {
  if (permit.revoked) return false
  if (new Date(permit.expiresAt) < new Date()) return false
  if (!permit.destinationSignature) return false

  const permitBody = {
    sourceContext: permit.sourceContext,
    destinationContext: permit.destinationContext,
    purpose: permit.purpose,
    destinationConstraints: permit.destinationConstraints,
    createdAt: permit.createdAt,
    expiresAt: permit.expiresAt,
  }
  const payload = canonicalize(permitBody)

  const sourceValid = verify(payload, permit.sourceSignature, permit.sourceContext.principalPublicKey)
  const destValid = verify(payload, permit.destinationSignature, permit.destinationContext.principalPublicKey)

  return sourceValid && destValid
}

/**
 * Revoke a cross-chain permit.
 */
export function revokePermit(permit: CrossChainPermit): CrossChainPermit {
  return { ...permit, revoked: true }
}

// ══════════════════════════════════════════════════════════════════
// Core Enforcement: checkDataFlow
// This is called by the gateway before every outbound action.
// It is the deterministic gate that prevents the confused deputy.
// ══════════════════════════════════════════════════════════════════

/**
 * Check whether an outbound action is authorized given the taint
 * on its input data and the delegation chain authorizing the action.
 *
 * Logic:
 * 1. If all input data originated from the same principal as the
 *    action's delegation chain → ALLOWED (same-context, no issue)
 * 2. If input data originated from a DIFFERENT principal →
 *    check for a valid CrossChainPermit
 *    - Permit found and valid → PERMITTED
 *    - No permit → BLOCKED (confused deputy prevented)
 * 3. If execution frame taint includes other principals beyond
 *    the SAO-level taint → BLOCKED (laundering prevention)
 */
export function checkDataFlow(opts: {
  /** Taint set on the data being passed to the outbound tool */
  inputTaint: TaintSet
  /** Principal ID of the delegation chain authorizing this action */
  actionPrincipalId: string
  /** Scope of the action being performed */
  actionScope: string
  /** All active (non-revoked, non-expired) cross-chain permits */
  permits: CrossChainPermit[]
  /** Current execution frame (for laundering detection) */
  frame?: ExecutionFrame
}): FlowCheckResult {
  const now = new Date().toISOString()

  // Merge frame-level taint if provided (catches laundering)
  const effectiveTaint = opts.frame
    ? mergeTaints(...opts.inputTaint.labels, ...opts.frame.frameTaint.labels)
    : opts.inputTaint

  // Check for read-only taint FIRST (blocks even same-principal outbound actions)
  const readOnlyBlocks = effectiveTaint.labels.filter(l => l.usage === 'read-only')
  if (readOnlyBlocks.length > 0) {
    return {
      verdict: 'blocked',
      blockingLabels: readOnlyBlocks,
      reason: `Data from ${readOnlyBlocks[0].principalId} is marked read-only and cannot be used in outbound actions.`,
      taintSet: effectiveTaint,
      checkedAt: now
    }
  }

  // Case 1: All taint is from the same principal as the action → ALLOWED
  const foreignLabels = effectiveTaint.labels.filter(
    l => l.principalId !== opts.actionPrincipalId
  )

  if (foreignLabels.length === 0) {
    return {
      verdict: 'allowed',
      reason: 'All input data originates from the same principal as the action authorization.',
      taintSet: effectiveTaint,
      checkedAt: now
    }
  }

  // Case 2: Foreign taint detected — check for permits
  const foreignPrincipals = [...new Set(foreignLabels.map(l => l.principalId))]

  // For each foreign principal, look for a valid permit
  for (const foreignPrincipal of foreignPrincipals) {
    const permit = opts.permits.find(p =>
      !p.revoked &&
      new Date(p.expiresAt) > new Date() &&
      p.sourceContext.principalId === foreignPrincipal &&
      p.destinationContext.principalId === opts.actionPrincipalId &&
      p.destinationContext.allowedScopes.some(s =>
        s === '*' || s === opts.actionScope || opts.actionScope.startsWith(s + ':')
      )
    )

    if (!permit) {
      const blockers = foreignLabels.filter(l => l.principalId === foreignPrincipal)
      return {
        verdict: 'blocked',
        blockingLabels: blockers,
        reason: `Data from principal "${foreignPrincipal}" cannot flow into action scope "${opts.actionScope}" authorized by principal "${opts.actionPrincipalId}". No valid CrossChainPermit found. Both principals must sign a permit to authorize this flow.`,
        taintSet: effectiveTaint,
        checkedAt: now
      }
    }

    // Permit found — return permitted for the last checked principal
    // (all foreign principals have valid permits if we reach here)
  }

  // All foreign principals have valid permits
  const matchedPermit = opts.permits.find(p =>
    !p.revoked &&
    new Date(p.expiresAt) > new Date() &&
    p.sourceContext.principalId === foreignPrincipals[0] &&
    p.destinationContext.principalId === opts.actionPrincipalId
  )

  return {
    verdict: 'permitted',
    permitId: matchedPermit?.permitId,
    reason: `Cross-chain flow authorized by permit. Data from ${foreignPrincipals.join(', ')} may flow into actions by ${opts.actionPrincipalId}.`,
    taintSet: effectiveTaint,
    checkedAt: now
  }
}
