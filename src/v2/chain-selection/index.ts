// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Chain selection over the set of chains an agent holds: draft-03 section 3.3's
// "each action selects one root-to-leaf authority chain" given an interface, plus the
// PROPOSED L11 fallback surface, marked as such at every symbol that carries it.
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
