// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { isValidScopeGrant, scopeGrantCovers } from '../authority-delegation/scope.js'
import { readPlainDataChainContainer, snapshotPlainData } from '../authority-delegation/plain-data.js'
import type { PlainDataChainRejection } from '../authority-delegation/plain-data.js'
import { verifyAuthorityDelegationChain } from '../authority-delegation/verify.js'
import type {
  AuthorityDelegationV1,
  AuthorityValidationResult,
} from '../authority-delegation/types.js'
import {
  HELD_SET_CEILING,
} from './types.js'
import type {
  AuthorityBudgetReserver,
  ChainEvaluation,
  ChainSelectionFailureCode,
  ChainSelectionInput,
  ChainSelectionWithFallbackInput,
  HeldChain,
  RequiredSpendV1,
  SelectionOutcome,
} from './types.js'

const ACTION_REF = /^[0-9a-f]{64}$/

/** A canonical unsigned decimal integer, the grammar the spend facet already uses. */
const QUANTITY = /^(0|[1-9][0-9]*)$/

interface ReadHeldChain {
  chain_id: string
  chain: unknown
}

type HeldSetProblem = Extract<
  ChainSelectionFailureCode,
  'held_set_empty' | 'held_set_over_ceiling' | 'held_chain_malformed' | 'duplicate_chain_id'
>

/**
 * Read the held set once, into this module's own array.
 *
 * Every member of every held entry is read exactly here, so a caller object whose
 * property is a getter cannot answer one way when the set is checked and another way
 * when a chain is verified. A getter that throws leaves the entry malformed, which is a
 * coded result. Nothing in this module throws.
 */
function readHeldSet(held: unknown): ReadHeldChain[] | HeldSetProblem {
  let entries: unknown[]
  try {
    if (!Array.isArray(held)) return 'held_set_empty'
    if (held.length > HELD_SET_CEILING) return 'held_set_over_ceiling'
    if (held.length < 1) return 'held_set_empty'
    entries = Array.prototype.slice.call(held) as unknown[]
  } catch {
    return 'held_set_empty'
  }
  const output: ReadHeldChain[] = []
  const seen = new Set<string>()
  for (const entry of entries) {
    let chainId: unknown
    let chain: unknown
    try {
      if (entry === null || typeof entry !== 'object') return 'held_chain_malformed'
      chainId = (entry as HeldChain).chain_id
      chain = (entry as HeldChain).chain
    } catch {
      return 'held_chain_malformed'
    }
    if (typeof chainId !== 'string' || chainId.length === 0) return 'held_chain_malformed'
    if (chain === undefined) return 'held_chain_malformed'
    if (seen.has(chainId)) return 'duplicate_chain_id'
    seen.add(chainId)
    output.push({ chain_id: chainId, chain })
  }
  return output
}

/** Read the action's requirement once, the same way and for the same reason. */
function readRequirement(
  requiredGrants: unknown,
  requiredSpend: unknown,
): { grants: string[]; spend: RequiredSpendV1 | null } | null {
  let grants: unknown[]
  try {
    if (!Array.isArray(requiredGrants)) return null
    grants = Array.prototype.slice.call(requiredGrants) as unknown[]
  } catch {
    return null
  }
  const needed: string[] = []
  for (const grant of grants) {
    // An unusable needed grant is a fault in the request, never a statement that some
    // chain failed to cover it: a caller told a chain is refusing an action it was never
    // coherently asked about would report a denial the evidence does not support.
    if (typeof grant !== 'string' || !isValidScopeGrant(grant)) return null
    needed.push(grant)
  }
  if (requiredSpend === undefined || requiredSpend === null) return { grants: needed, spend: null }
  let unit: unknown
  let amount: unknown
  let actionRef: unknown
  try {
    if (typeof requiredSpend !== 'object') return null
    unit = (requiredSpend as RequiredSpendV1).unit
    amount = (requiredSpend as RequiredSpendV1).amount
    actionRef = (requiredSpend as RequiredSpendV1).action_ref
  } catch {
    return null
  }
  if (typeof unit !== 'string' || unit.length === 0) return null
  if (typeof amount !== 'string' || !QUANTITY.test(amount)) return null
  if (typeof actionRef !== 'string' || !ACTION_REF.test(actionRef)) return null
  return { grants: needed, spend: { unit, amount, action_ref: actionRef } }
}

interface Evaluated {
  evaluation: ChainEvaluation
  result: AuthorityValidationResult | null
}

/**
 * Decide ONE held chain against the action. This function never sees another chain, and
 * it is the only place a chain is judged, so neither `selectChainForAction` nor
 * `selectWithFallback` has a route by which a second chain's grants or ceiling could
 * enter a comparison. That is draft-03 section 3.3's "A verifier MUST NOT union scopes
 * or budgets from multiple chains" held by construction rather than by a check.
 *
 * Order: presentation, then chain verification, then scope, then spend. Scope before
 * spend so an action refused on both is refused under the check that does not touch the
 * ledger, which keeps a refusal from leaving a reservation behind.
 */
function evaluateHeldChain(
  entry: ReadHeldChain,
  needed: readonly string[],
  spend: RequiredSpendV1 | null,
  input: ChainSelectionInput,
  reserveBudget: AuthorityBudgetReserver | null,
): Evaluated {
  const refuse = (code: string, chainState: ChainEvaluation['chain_state']): Evaluated => ({
    evaluation: { chain_id: entry.chain_id, outcome: 'refuses', code, chain_state: chainState },
    result: null,
  })
  const undecided = (code: string, chainState: ChainEvaluation['chain_state']): Evaluated => ({
    evaluation: { chain_id: entry.chain_id, outcome: 'undecided', code, chain_state: chainState },
    result: null,
  })

  // The caller's array is read exactly once, here, and every later read is of this
  // snapshot: the presentation check, the chain verifier and the reserver are all handed
  // the same plain-data copy, so they cannot be shown three different chains.
  const rejection = { reason: 'not-a-container' as PlainDataChainRejection }
  const container = readPlainDataChainContainer(entry.chain, 1, 256, rejection)
  if (!container) {
    // Deferred to the chain verifier so the code for an unreadable container is named in
    // exactly one place in this SDK. It reads the caller's value itself in this branch,
    // which is the branch where there is nothing to snapshot.
    const result = verifyAuthorityDelegationChain(
      Array.isArray(entry.chain) ? (entry.chain as readonly unknown[]) : [],
      input.options,
    )
    const code = result.failures[0]?.code ?? 'SCHEMA_INVALID'
    return result.state === 'invalid' ? refuse(code, result.state) : undecided(code, result.state)
  }
  const records = container.map(member => snapshotPlainData(member))

  // Presentation. A member after the first with a null parent_delegation_id is a root,
  // so this entry is two or more chains concatenated rather than one root-to-leaf chain.
  // Refused before verification: the fault is that a set was presented as one chain,
  // which is precisely the shape a caller reaches for to have two chains evaluated
  // together, and naming it as chain verification's broken parent link would hide that.
  for (let i = 1; i < records.length; i++) {
    const member = records[i]
    if (member !== null && typeof member === 'object' &&
        (member as { parent_delegation_id?: unknown }).parent_delegation_id === null) {
      return refuse('chain_set_presented_as_one', null)
    }
  }

  const result = verifyAuthorityDelegationChain(records, input.options)
  if (result.state !== 'valid') {
    const code = result.failures[0]?.code ?? result.state
    return result.state === 'invalid' ? refuse(code, result.state) : undecided(code, result.state)
  }

  // Scope. The leaf's grants are what the chain's own narrowing has already reduced the
  // root's grants to, which verification above established.
  const leaf = records[records.length - 1] as AuthorityDelegationV1
  const grants = leaf.authority.scope.grants
  for (const want of needed) {
    if (!grants.some(grant => scopeGrantCovers(grant, want))) {
      return refuse('scope_not_covered', result.state)
    }
  }

  if (!spend) {
    return {
      evaluation: { chain_id: entry.chain_id, outcome: 'authorizes', code: 'scope_covered', chain_state: result.state },
      result,
    }
  }
  if (!reserveBudget) {
    // Not established, not a refusal: nothing was learned about whether this chain's
    // ceiling covers the amount.
    return undecided('spend_ledger_unavailable', result.state)
  }
  let reservation
  try {
    reservation = reserveBudget.reserve(
      records as readonly AuthorityDelegationV1[],
      spend.action_ref,
      spend.unit,
      spend.amount,
    )
  } catch {
    return undecided('spend_ledger_unavailable', result.state)
  }
  if (!reservation || typeof reservation !== 'object' || typeof reservation.code !== 'string') {
    return undecided('spend_ledger_unavailable', result.state)
  }
  if (reservation.ok !== true) {
    return refuse(reservation.code, result.state)
  }
  return {
    evaluation: { chain_id: entry.chain_id, outcome: 'authorizes', code: reservation.code, chain_state: result.state },
    result,
  }
}

function failureFor(evaluations: readonly ChainEvaluation[]): ChainSelectionFailureCode {
  // One undecided candidate is enough to make the whole answer not established: nothing
  // was learned about that chain, so "no chain covers the action" is a claim the
  // evaluations do not support. Where every candidate did refuse, a candidate that
  // verified valid and then failed scope or spend establishes that a valid chain did not
  // cover the action. A candidate that never verified valid establishes nothing about
  // coverage, only that it was not a usable chain.
  if (evaluations.some(item => item.outcome === 'undecided')) return 'selection_undecided'
  return evaluations.some(item => item.chain_state === 'valid')
    ? 'no_chain_covers_action'
    : 'no_valid_chain'
}

function fail(code: ChainSelectionFailureCode, evaluations: readonly ChainEvaluation[]): SelectionOutcome {
  return { selected: false, chain_id: null, code, evaluations }
}

/**
 * Select the one chain an action is decided against, out of the set an agent holds.
 *
 * draft-03 section 3.3 (lines 594-596) states the rule this implements: "Each action
 * selects one root-to-leaf authority chain.  A verifier MUST NOT union scopes or budgets
 * from multiple chains.  Cross-principal composition requires a separate profile."
 * Required behaviour, not a proposal. The one part of this module that is proposed
 * rather than specified is the fallback surface, and it lives in `selectWithFallback`.
 *
 * Selection rule, which draft-03 does not state and this implementation therefore fixes
 * and documents. Candidates are evaluated in held order. The FIRST candidate that both
 * verifies `valid` and covers every needed scope grant is the selected chain, and the
 * action's spend is then reserved against that chain and no other. A spend refusal is that chain's
 * refusal, and no further candidate is read. Scope selects, spend admits or refuses. The
 * alternative, continuing past a spend refusal to a chain with a larger ceiling, is a
 * fallback in everything but name, and this function does not do it silently.
 *
 * `held` never shrinks to the one chain: every candidate this call read appears in
 * `evaluations`, and the chosen `chain_id` is one string, so a caller and an auditor can
 * both see which chain the action was decided against and which chains were passed over.
 *
 * A caller that already had a chain selected and is now asking again because that chain
 * failed is switching, not selecting, and should use `selectWithFallback`. This function
 * does not know that a previous selection existed and cannot report a switch.
 *
 * Nothing here reads a clock, a random source or the network: `options.now` and the three
 * resolvers are the caller's, exactly as `verifyAuthorityDelegationChain` takes them.
 * This function never throws.
 */
export function selectChainForAction(input: ChainSelectionInput): SelectionOutcome {
  const held = readHeldSet(input?.held)
  if (typeof held === 'string') return fail(held, [])
  const requirement = readRequirement(input?.requiredGrants, input?.requiredSpend)
  if (!requirement) return fail('invalid_action_requirement', [])
  const reserveBudget = input?.reserveBudget ?? null

  const evaluations: ChainEvaluation[] = []
  // Two passes over the candidates, because a reservation mutates a ledger and a refused
  // scope check does not: every candidate is scope-checked with no spend requirement
  // first, and only the one that wins is reserved against. A single pass would reserve
  // against a chain that a later, better candidate replaces.
  let chosen: ReadHeldChain | null = null
  let chosenResult: AuthorityValidationResult | null = null
  for (const entry of held) {
    const evaluated = evaluateHeldChain(entry, requirement.grants, null, input, null)
    evaluations.push(evaluated.evaluation)
    if (evaluated.evaluation.outcome === 'authorizes') {
      chosen = entry
      chosenResult = evaluated.result
      break
    }
  }
  if (!chosen || !chosenResult) return fail(failureFor(evaluations), evaluations)
  if (!requirement.spend) {
    return { selected: true, chain_id: chosen.chain_id, result: chosenResult, evaluations }
  }
  // Re-evaluate the winner with the spend requirement attached. This is the only
  // reservation this call makes.
  const admitted = evaluateHeldChain(chosen, requirement.grants, requirement.spend, input, reserveBudget)
  evaluations[evaluations.length - 1] = admitted.evaluation
  if (admitted.evaluation.outcome !== 'authorizes' || !admitted.result) {
    return fail(failureFor(evaluations), evaluations)
  }
  return { selected: true, chain_id: chosen.chain_id, result: admitted.result, evaluations }
}

/**
 * Decide an action against the chain it already selected, and switch to another held
 * chain only when the caller has explicitly authorized a switch.
 *
 * The preferred-chain half is draft-03 section 3.3: one chain, no union. The fallback
 * half is PROPOSED and has no counterpart in draft-03, where `fallback`, `fall back`,
 * `resurrect` and `reselect` occur zero times. It serves a proposed rule this SDK does
 * not claim is specified anywhere: a switch to another stored grant should be a visible
 * decision, not a retry.
 *
 * `fallback: null` is that proposed rule in one parameter. It reads no held chain other
 * than `preferred_chain_id`, so `evaluations` has exactly one entry and
 * `fallback_considered` is false. There is no code path on which this function reaches
 * another chain without the caller having passed an authorization object.
 *
 * With an authorization object, the remaining held chains are evaluated in held order
 * and the first that authorizes the action is selected. The result then carries
 * `switched_from`, the chain the action had selected, and `fallback_ref`, the caller's
 * opaque reference, so the switch is in the result rather than only in the caller's head.
 * That reference is recorded and NEVER interpreted: nothing specified defines what makes
 * a fallback explicitly authorized, and this SDK does not invent a definition, so a
 * `fallback_ref` is not evidence that anything authorized anything.
 *
 * The preferred chain is always evaluated first and its own outcome is always
 * `evaluations[0]`, including when a fallback then succeeds, so the reason the action
 * left its selected chain stays in the record. A later finding never rewrites it.
 *
 * This function never throws.
 */
export function selectWithFallback(input: ChainSelectionWithFallbackInput): SelectionOutcome {
  const held = readHeldSet(input?.held)
  if (typeof held === 'string') return fail(held, [])
  const requirement = readRequirement(input?.requiredGrants, input?.requiredSpend)
  if (!requirement) return fail('invalid_action_requirement', [])
  let preferredId: unknown
  try { preferredId = input?.preferred_chain_id } catch { preferredId = undefined }
  const preferred = typeof preferredId === 'string'
    ? held.find(entry => entry.chain_id === preferredId) ?? null
    : null
  if (!preferred) return fail('preferred_chain_not_held', [])
  let fallback: unknown
  try { fallback = input?.fallback } catch { fallback = undefined }
  let fallbackRef: string | null = null
  if (fallback !== null && fallback !== undefined) {
    let ref: unknown
    try { ref = (fallback as { authorization_ref?: unknown }).authorization_ref } catch { ref = undefined }
    // An authorization object with no usable reference is not an authorization. Refusing
    // to switch is the fail-closed answer: a switch recorded with no reference would be
    // exactly the invisible switch the proposed rule above is about.
    if (typeof ref !== 'string' || ref.length === 0) return fail('invalid_action_requirement', [])
    fallbackRef = ref
  }

  const reserveBudget = input?.reserveBudget ?? null
  const evaluations: ChainEvaluation[] = []

  const decide = (entry: ReadHeldChain): { ok: boolean; result: AuthorityValidationResult | null } => {
    const scoped = evaluateHeldChain(entry, requirement.grants, null, input, null)
    if (scoped.evaluation.outcome !== 'authorizes') {
      evaluations.push(scoped.evaluation)
      return { ok: false, result: null }
    }
    if (!requirement.spend) {
      evaluations.push(scoped.evaluation)
      return { ok: true, result: scoped.result }
    }
    const admitted = evaluateHeldChain(entry, requirement.grants, requirement.spend, input, reserveBudget)
    evaluations.push(admitted.evaluation)
    return { ok: admitted.evaluation.outcome === 'authorizes' && admitted.result !== null, result: admitted.result }
  }

  const first = decide(preferred)
  if (first.ok && first.result) {
    return {
      selected: true,
      chain_id: preferred.chain_id,
      result: first.result,
      evaluations,
      fallback_considered: fallbackRef !== null,
    }
  }
  if (fallbackRef === null) {
    return { ...fail(failureFor(evaluations), evaluations), fallback_considered: false }
  }
  for (const entry of held) {
    if (entry.chain_id === preferred.chain_id) continue
    const next = decide(entry)
    if (next.ok && next.result) {
      return {
        selected: true,
        chain_id: entry.chain_id,
        result: next.result,
        evaluations,
        switched_from: preferred.chain_id,
        fallback_ref: fallbackRef,
        fallback_considered: true,
      }
    }
  }
  return { ...fail(failureFor(evaluations), evaluations), fallback_considered: true }
}
