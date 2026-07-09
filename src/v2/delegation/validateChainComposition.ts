// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Structural validator for delegation chains under responsibility_anchor.
 *
 * Catches malformed chains before they are passed to cascadePrincipal. The
 * cascade returns chain_integrity verdicts at runtime; this validator is the
 * earlier gate that ensures chains issued with anchors are internally
 * coherent.
 */

import type { ResponsibilityAnchor } from '../types.js'
import type { DelegationChain } from './responsibility.js'

/** Result of validateChainComposition. */
export interface ChainCompositionResult {
  valid: boolean
  failures: string[]
}

/**
 * Verify that a delegation chain is well-formed under responsibility_anchor
 * rules.
 *
 * Checks:
 *
 * 1. Every anchor of kind 'agent_acting_for_principal' has a non-empty
 *    acting_agent_id field.
 * 2. The chain has at least one 'human' or 'org' anchor reachable from every
 *    'agent_acting_for_principal' anchor (no infinite-agent chain).
 * 3. No cycle exists among 'agent_acting_for_principal' anchors via the
 *    acting_agent_id pointer.
 *
 * Chains with no anchors at all are treated as legacy and pass without
 * failures (the cascade falls back to the root delegator). This keeps the
 * validator additive against pre-anchor delegations.
 */
export function validateChainComposition(chain: DelegationChain): ChainCompositionResult {
  const failures: string[] = []

  if (chain.length === 0) {
    failures.push('Chain is empty')
    return { valid: false, failures }
  }

  const anchors: ResponsibilityAnchor[] = chain
    .map((d) => d.responsibility_anchor)
    .filter((a): a is ResponsibilityAnchor => a !== undefined)

  // Legacy chain: no anchors at all, pass.
  if (anchors.length === 0) {
    return { valid: true, failures: [] }
  }

  // Check 1: acting_agent_id required when kind is agent_acting_for_principal.
  for (let i = 0; i < chain.length; i++) {
    const a = chain[i].responsibility_anchor
    if (!a) continue
    if (a.principal_kind === 'agent_acting_for_principal') {
      if (!a.acting_agent_id || a.acting_agent_id.length === 0) {
        failures.push(
          `Hop ${i}: anchor kind 'agent_acting_for_principal' requires acting_agent_id`,
        )
      }
    }
  }

  // Check 2 and 3: walk every agent_acting_for_principal anchor. Detect cycle
  // or unreachable human/org. A cycle is recorded only once. An unreachable
  // chain is recorded only once.
  let cycleRecorded = false
  let infiniteRecorded = false
  for (const a of anchors) {
    if (a.principal_kind !== 'agent_acting_for_principal') continue
    if (!a.acting_agent_id) continue // Already recorded by check 1.

    const visited = new Set<string>()
    let cursor: ResponsibilityAnchor | undefined = a
    let landed = false
    while (cursor) {
      if (cursor.principal_kind === 'human' || cursor.principal_kind === 'org') {
        landed = true
        break
      }
      if (visited.has(cursor.principal_id)) {
        if (!cycleRecorded) {
          failures.push(
            'Circular acting_agent_id reference: chain revisits a principal without reaching a human or org root',
          )
          cycleRecorded = true
        }
        break
      }
      visited.add(cursor.principal_id)
      if (!cursor.acting_agent_id) break
      const nextId: string = cursor.acting_agent_id
      cursor = anchors.find((x) => x.principal_id === nextId)
    }

    if (!landed && !cycleRecorded && !infiniteRecorded) {
      // If a cycle was detected on this walk we already recorded it. Otherwise
      // the walk exited without finding a root.
      const ranOff = visited.size > 0 && !cursor
      if (ranOff || !cursor) {
        failures.push(
          'Infinite-agent chain: no human or org anchor reachable from an agent_acting_for_principal anchor',
        )
        infiniteRecorded = true
      }
    }
  }

  return { valid: failures.length === 0, failures }
}
