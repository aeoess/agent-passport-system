// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// @aeoess/composio-governance — APS governance layer for tool execution

export { governComposioAction, governComposioToolkit } from './adapter.js'

export type {
  ComposioAction,
  GovernedAction,
  GovernedResult,
  ToolGovernanceConfig,
  DenialEvent,
} from './types.js'
