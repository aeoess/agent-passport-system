// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * Responsibility cascade for v2 delegation chains.
 *
 * Substrate for matrix v2 candidate C-II-3 (recursive delegation
 * accountability beyond two hops). Monotonic narrowing in v1 answers who
 * authorizes what at each transfer. It does not answer which human or
 * organization bears responsibility when chains from several principals
 * converge at hop three or later (the gap named in arxiv 2604.23280v1).
 *
 * The v0.1 cascade resolves a chain to one or more root principals. Mixed
 * chains return all distinct roots, jointly attributed. The divergence from
 * naive monotonic narrowing is intentional: a single most-recent principal
 * is not enough when several principals authorized parallel paths.
 *
 * v0.2 work (out of scope here): smart reputation weighting, cross-protocol
 * cascade, revocation cascade, UI affordances.
 */

import type { V2Delegation, ResponsibilityAnchor } from '../types.js'

// ══════════════════════════════════════════════════════════════
// TYPES
// ══════════════════════════════════════════════════════════════

/**
 * Ordered array of V2Delegation entries forming a delegation chain from root
 * to leaf. Position zero is the root. The cascade walks the array to resolve
 * principal-of-record.
 *
 * The same array shape is what traceV2DelegationHistory returns, so callers
 * can pass its output directly. For chains with parallel root delegations
 * (the same agent delegated to by several principals), include each root
 * delegation as a separate array entry.
 */
export type DelegationChain = V2Delegation[]

/**
 * A resolved root principal: the human or organization at the top of a
 * delegation chain.
 */
export interface RootPrincipal {
  principal_id: string
  principal_kind: 'human' | 'org'
}

/**
 * Chain integrity verdict from the cascade.
 *
 * - 'ok' means at least one root principal was resolved and no cycle was hit.
 * - 'missing_root_anchor' means the chain has only 'agent_acting_for_principal'
 *   anchors with no human or org reachable, and no legacy root delegation to
 *   fall back to. Callers must reject the action.
 * - 'circular' means the agent_acting_for_principal anchors reference each
 *   other in a cycle with no human or org exit. Callers must reject the
 *   action.
 */
export type ChainIntegrity = 'ok' | 'missing_root_anchor' | 'circular'

/** Output of cascadePrincipal. */
export interface CascadeResult {
  principals: RootPrincipal[]
  chain_integrity: ChainIntegrity
}

// ══════════════════════════════════════════════════════════════
// CASCADE
// ══════════════════════════════════════════════════════════════

/**
 * Resolve the principal of record for an action taken under the leaf of a
 * delegation chain.
 *
 * Rules (v0.1):
 *
 * 1. Direct anchor. For every hop with a responsibility_anchor of kind
 *    'human' or 'org', the principal_id is recorded as a root principal.
 * 2. Indirect anchor. For every hop with a responsibility_anchor of kind
 *    'agent_acting_for_principal', walk acting_agent_id through the chain
 *    until a 'human' or 'org' anchor is reached. Record that principal.
 *    If the walk revisits a principal it has already seen, the chain is
 *    circular. If the walk exits without reaching a human or org, the chain
 *    is missing its root anchor.
 * 3. Joint attribution. If several distinct root principals are reachable
 *    from the chain, all are returned. This is the divergence from naive
 *    monotonic narrowing required by C-II-3.
 * 4. Legacy fallback. If no anchor is present on any hop, the chain root's
 *    delegator is synthesized as a 'human' principal. This preserves
 *    pre-anchor behavior for chains issued before this SDK version.
 *
 * Invariants:
 *
 * - Returned principals are unique by principal_id (first kind wins on
 *   duplicate principal_id with mixed kinds).
 * - chain_integrity is 'ok' only when at least one principal was resolved
 *   and no cycle was observed during indirect walks.
 * - An empty chain returns no principals and chain_integrity
 *   'missing_root_anchor'.
 * - The function is pure: no store reads, no signature verification, no
 *   side effects. Pair with validateV2Delegation and
 *   validateChainComposition before relying on the result.
 */
export function cascadePrincipal(chain: DelegationChain): CascadeResult {
  if (chain.length === 0) {
    return { principals: [], chain_integrity: 'missing_root_anchor' }
  }

  const anchors: ResponsibilityAnchor[] = chain
    .map((d) => d.responsibility_anchor)
    .filter((a): a is ResponsibilityAnchor => a !== undefined)

  // Legacy fallback: no anchors anywhere. Use chain root's delegator.
  if (anchors.length === 0) {
    const root = chain[0]
    return {
      principals: [{ principal_id: root.delegator, principal_kind: 'human' }],
      chain_integrity: 'ok',
    }
  }

  const roots = new Map<string, RootPrincipal>()

  // Direct anchors first.
  for (const a of anchors) {
    if (a.principal_kind === 'human' || a.principal_kind === 'org') {
      if (!roots.has(a.principal_id)) {
        roots.set(a.principal_id, {
          principal_id: a.principal_id,
          principal_kind: a.principal_kind,
        })
      }
    }
  }

  // Indirect anchors: walk acting_agent_id through the pool of anchors.
  let sawCircular = false
  let sawUnresolved = false
  for (const a of anchors) {
    if (a.principal_kind !== 'agent_acting_for_principal') continue
    const verdict = walkActingChain(a, anchors)
    if (verdict.status === 'circular') {
      sawCircular = true
    } else if (verdict.status === 'unresolved') {
      sawUnresolved = true
    } else {
      if (!roots.has(verdict.principal.principal_id)) {
        roots.set(verdict.principal.principal_id, verdict.principal)
      }
    }
  }

  if (roots.size > 0) {
    return {
      principals: Array.from(roots.values()),
      chain_integrity: sawCircular ? 'circular' : 'ok',
    }
  }

  if (sawCircular) {
    return { principals: [], chain_integrity: 'circular' }
  }
  if (sawUnresolved) {
    return { principals: [], chain_integrity: 'missing_root_anchor' }
  }
  return { principals: [], chain_integrity: 'missing_root_anchor' }
}

// ══════════════════════════════════════════════════════════════
// INTERNAL
// ══════════════════════════════════════════════════════════════

type WalkVerdict =
  | { status: 'ok'; principal: RootPrincipal }
  | { status: 'circular' }
  | { status: 'unresolved' }

/**
 * Walk an acting_agent_id chain through the anchor pool until a human or org
 * anchor is reached, a cycle is detected, or the walk exits without reaching
 * a root. Visited principal_ids are tracked to detect cycles.
 */
function walkActingChain(start: ResponsibilityAnchor, pool: ResponsibilityAnchor[]): WalkVerdict {
  const visited = new Set<string>()
  let current: ResponsibilityAnchor | undefined = start

  while (current) {
    if (current.principal_kind === 'human' || current.principal_kind === 'org') {
      return {
        status: 'ok',
        principal: {
          principal_id: current.principal_id,
          principal_kind: current.principal_kind,
        },
      }
    }
    if (visited.has(current.principal_id)) {
      return { status: 'circular' }
    }
    visited.add(current.principal_id)
    if (!current.acting_agent_id) {
      return { status: 'unresolved' }
    }
    const nextId: string = current.acting_agent_id
    const next: ResponsibilityAnchor | undefined = pool.find(
      (a) => a.principal_id === nextId,
    )
    if (!next) {
      return { status: 'unresolved' }
    }
    current = next
  }
  return { status: 'unresolved' }
}
