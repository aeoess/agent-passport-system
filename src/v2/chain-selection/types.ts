// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Chain selection for one action, over the set of chains an agent holds.
//
// draft-pidlisnyi-aps-03 section 3.3, lines 594-596, verbatim:
//
//   Each action selects one root-to-leaf authority chain.  A verifier
//   MUST NOT union scopes or budgets from multiple chains.  Cross-
//   principal composition requires a separate profile.
//
// Every other entry point in this SDK takes exactly one chain, so the first
// sentence has had no surface: a caller could obey it, and a caller could evaluate
// an action against three chains and pool the answers, and nothing in the SDK could
// tell the two apart. This module is that surface. It receives the whole held set and
// returns the identifier of the ONE chain it decided against, so an implementation
// built on it is observably single-selecting.
//
// The second sentence is enforced structurally rather than by a check: no function
// here ever holds two chains' scope grants or spend ceilings in one comparison. Each
// held chain is verified, scope-checked and budget-checked alone, and the result names
// one `chain_id`, never a set.

import type {
  AuthorityChainVerificationOptions,
  AuthorityDelegationV1,
  AuthorityValidationResult,
  AuthorityValidationState,
  BudgetOperationResult,
} from '../authority-delegation/types.js'

/**
 * One chain an agent holds, under a caller-chosen name.
 *
 * `chain_id` is the caller's own label for this chain, not a protocol field and not
 * derived from the records: nothing in draft-03 names a chain. It exists so a selection
 * result can say which chain it decided against, which is what makes a selection, and a
 * later switch away from it, visible. Two held entries carrying the same `chain_id` are
 * refused rather than disambiguated, because a result naming an ambiguous label would
 * not identify a chain.
 *
 * `chain` is root-to-leaf and untrusted, the same shape and the same trust level
 * `verifyAuthorityDelegationChain` takes.
 */
export interface HeldChain {
  chain_id: string
  chain: readonly unknown[]
}

/**
 * The spend an action requires, if any.
 *
 * `action_ref` keys the reservation in the ledger, exactly as
 * `InMemoryAuthorityBudgetLedger.reserve` requires: 64 lowercase hexadecimal
 * characters. One action reserves against one chain, so a single `action_ref` is
 * reserved at most once here, against the chain that was selected.
 */
export interface RequiredSpendV1 {
  unit: string
  /** Canonical unsigned decimal integer, the same grammar the spend facet uses. */
  amount: string
  action_ref: string
}

/**
 * The reservation boundary this module calls, satisfied structurally by
 * `InMemoryAuthorityBudgetLedger`.
 *
 * Injected rather than constructed here: a selection that minted its own ledger would
 * report `RESERVED` against counters nobody else can see, and a real deployment's ledger
 * is a store, not an object in this process.
 */
export interface AuthorityBudgetReserver {
  reserve(
    verifiedChain: readonly AuthorityDelegationV1[],
    actionRef: string,
    unit: string,
    amountString: string,
  ): BudgetOperationResult
}

/**
 * What one held chain said about one action.
 *
 * `authorizes` means this chain alone covers the action. `refuses` means this chain
 * alone establishes that it does not. `undecided` means no conclusion was reached about
 * this chain, which is not the negation of one: an indeterminate revocation answer, an
 * unsupported facet profile, or a missing ledger all land here, and none of them is a
 * statement that the chain does not authorize the action. draft-03 section 3.3 line 592
 * forbids collapsing indeterminate or unsupported into valid, and this keeps them out
 * of `refuses` as well, so a caller that reports a denial reason does not report one the
 * evidence does not support.
 */
export type ChainEvaluationOutcome = 'authorizes' | 'refuses' | 'undecided'

/** One held chain's evaluation, kept per chain so a caller can show its work. */
export interface ChainEvaluation {
  chain_id: string
  outcome: ChainEvaluationOutcome
  /**
   * The check that decided this chain. One of: an `AuthorityFailureCode` from chain
   * verification, a `BudgetOperationResult` code from the reserver, or one of
   * `CHAIN_SELECTION_EVALUATION_CODES` below. Codes from the other two sources are
   * passed through unchanged rather than remapped, so a caller reading this field sees
   * the name the deciding component used.
   */
  code: string
  /** The chain's own four-valued verification state, or null when verification did not run. */
  chain_state: AuthorityValidationState | null
}

/**
 * This module's own evaluation codes, the ones that come from neither chain
 * verification nor the reserver.
 *
 * - `scope_covered`: the chain covers every needed grant and the action required no spend.
 * - `scope_not_covered`: some needed grant is covered by no grant on this chain's leaf.
 * - `chain_set_presented_as_one`: this held entry is not one root-to-leaf chain. A
 *   member after the first carries a null `parent_delegation_id`, so the entry is two or
 *   more chains concatenated. Refused before verification rather than being reported as
 *   the broken parent link chain verification would otherwise call it, because the fault
 *   is the presentation, not the records: this is the shape a caller would reach for to
 *   have two chains evaluated as one.
 * - `spend_ledger_unavailable`: the action requires spend and no reserver was supplied,
 *   so the spend half could not be decided. Undecided, never a refusal.
 */
export const CHAIN_SELECTION_EVALUATION_CODES = [
  'scope_covered',
  'scope_not_covered',
  'chain_set_presented_as_one',
  'spend_ledger_unavailable',
] as const

export type ChainSelectionEvaluationCode = (typeof CHAIN_SELECTION_EVALUATION_CODES)[number]

/**
 * Why no chain was selected.
 *
 * - `held_set_empty`: the held set is not a readable array of at least one entry.
 * - `held_set_over_ceiling`: more held entries than this implementation will judge.
 *   draft-03 states no such ceiling, so this says this implementation declined, never
 *   that the input is bad.
 * - `held_chain_malformed`: a held entry carries no non-empty string `chain_id`, or no
 *   `chain` member at all. About the entry's own envelope, not about the records in it.
 * - `duplicate_chain_id`: two held entries share a `chain_id`.
 * - `invalid_action_requirement`: the needed grants are not a readable list of valid
 *   scope grants, or the required spend's shape is not usable. A request fault, kept
 *   apart from `scope_not_covered`, which is a statement about a chain.
 * - `preferred_chain_not_held`: `selectWithFallback` was given a `preferred_chain_id`
 *   that names no held entry.
 * - `no_valid_chain`: every candidate refused, and none of them verified `valid`.
 * - `no_chain_covers_action`: every candidate refused, and at least one of them verified
 *   `valid` and then failed to cover the action.
 * - `selection_undecided`: at least one candidate was `undecided`, so nothing was
 *   established about it and nothing is established about the set. Not established is
 *   kept apart from refused here deliberately: draft-03 section 3.3 line 592 forbids
 *   collapsing indeterminate or unsupported into valid, and collapsing them into a
 *   refusal would be the opposite error, a denial reason the evidence does not support.
 */
export const CHAIN_SELECTION_FAILURE_CODES = [
  'held_set_empty',
  'held_set_over_ceiling',
  'held_chain_malformed',
  'duplicate_chain_id',
  'invalid_action_requirement',
  'preferred_chain_not_held',
  'no_valid_chain',
  'no_chain_covers_action',
  'selection_undecided',
] as const

export type ChainSelectionFailureCode = (typeof CHAIN_SELECTION_FAILURE_CODES)[number]

/**
 * Explicit authorization for switching away from the chain an action selected.
 *
 * PROPOSED, not draft-03. draft-03 says nothing about what an implementation does after
 * the chain it selected turns out to be unusable: `fallback`, `fall back`, `resurrect`
 * and `reselect` occur zero times in the published text. The invariant candidate this
 * shape serves is L11, "No silent authority resurrection", in
 * `AUTHORITY-LIFECYCLE.md` of the aeoess/agent-authority-lifecycle concept document,
 * whose own status there is `proposed`: when the authority path an implementation
 * selected becomes invalid, it should not quietly fall back to another stored grant
 * unless that fallback was itself explicitly authorized.
 *
 * That document does not define what makes a fallback "explicitly authorized", and this
 * SDK does not invent a definition. `authorization_ref` is an OPAQUE reference the
 * caller supplies and this module records and never interprets: it is not resolved, not
 * verified, not required to name any record type, and its presence is not a claim that
 * the fallback was authorized. What the presence of this object does is make the switch
 * a decision the caller had to take deliberately and that the result then reports.
 */
export interface FallbackAuthorizationV0 {
  authorization_ref: string
}

interface SelectionOutcomeCommon {
  /** Every candidate this call evaluated, in the order it evaluated them. */
  evaluations: readonly ChainEvaluation[]
  /**
   * PROPOSED (L11). Present only on a `selectWithFallback` result. True when the call
   * was allowed to look past the chain the action selected. False means no other held
   * chain was read at all, which is the observable difference between a refusal and a
   * silent switch.
   */
  fallback_considered?: boolean
}

/**
 * The result of a selection. `chain_id` is one string or null, never a list: there is no
 * representable outcome in which two chains were combined.
 */
export type SelectionOutcome =
  | (SelectionOutcomeCommon & {
      selected: true
      chain_id: string
      /** The selected chain's own verification result, unchanged from `verifyAuthorityDelegationChain`. */
      result: AuthorityValidationResult
      /** PROPOSED (L11). The chain the action had selected, when this call switched away from it. */
      switched_from?: string
      /** PROPOSED (L11). The opaque reference the caller gave for that switch, recorded, not interpreted. */
      fallback_ref?: string
    })
  | (SelectionOutcomeCommon & {
      selected: false
      chain_id: null
      code: ChainSelectionFailureCode
    })

/** Shared input: the held set, the action, and the chain-verification callbacks. */
export interface ChainSelectionInput {
  held: readonly HeldChain[]
  /** Scope grants the action needs. Every one must be covered by the selected chain's leaf. */
  requiredGrants: readonly string[]
  /** Omitted or null means the action reserves nothing and no ledger is needed. */
  requiredSpend?: RequiredSpendV1 | null
  /** The same options object `verifyAuthorityDelegationChain` takes, unchanged. */
  options: AuthorityChainVerificationOptions
  /** Required when `requiredSpend` is present. Without it the spend half is undecided. */
  reserveBudget?: AuthorityBudgetReserver | null
}

export interface ChainSelectionWithFallbackInput extends ChainSelectionInput {
  /** The chain the action selected. Must name a held entry. */
  preferred_chain_id: string
  /**
   * PROPOSED (L11). `null` refuses to switch: no chain other than the preferred one is
   * read. An object permits the switch and is recorded on the result.
   */
  fallback: FallbackAuthorizationV0 | null
}

/** This implementation's own ceiling on held entries. draft-03 states none. */
export const HELD_SET_CEILING = 256
