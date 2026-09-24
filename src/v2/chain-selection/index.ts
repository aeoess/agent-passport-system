// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Chain selection over the set of chains an agent holds. draft-pidlisnyi-aps-03
// section 3.3 ("Chain Verification") states the rule this module gives an interface:
// "Each action selects one root-to-leaf authority chain.  A verifier MUST NOT union
// scopes or budgets from multiple chains."  That half is required behaviour and ships
// as a stable root export. The fallback surface in selectWithFallback is PROPOSED and
// has no counterpart in draft-03; every symbol carrying it says so.
export {
  CHAIN_SELECTION_EVALUATION_CODES,
  CHAIN_SELECTION_FAILURE_CODES,
  HELD_SET_CEILING,
} from './types.js'
export type {
  AuthorityBudgetReserver,
  ChainEvaluation,
  ChainEvaluationOutcome,
  ChainSelectionEvaluationCode,
  ChainSelectionFailureCode,
  ChainSelectionInput,
  ChainSelectionWithFallbackInput,
  FallbackAuthorizationV0,
  HeldChain,
  RequiredSpendV1,
  SelectionOutcome,
} from './types.js'
export { selectChainForAction, selectWithFallback } from './select.js'
