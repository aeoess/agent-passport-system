// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

import type {
  SignedPassport,
  Delegation,
  ActionReceipt,
  ValuesFloor,
  RecoveryPolicy,
} from 'agent-passport-system'

/** Any tool object with name, description, and execute(). Works with Composio, MCP, LangChain, or custom. */
export interface ComposioAction {
  name: string
  description: string
  execute: (params: Record<string, unknown>) => Promise<unknown>
}

/** Denial event emitted when a governance gate blocks an action */
export interface DenialEvent {
  tool: string
  reason: string
  scope: string
  timestamp: string
}

/** Configuration for tool governance */
export interface ToolGovernanceConfig {
  /** Agent's signed passport */
  passport: SignedPassport
  /** Standard APS delegation from human principal */
  delegation: Delegation
  /** Agent's private key for signing receipts */
  privateKey: string
  /** Optional values floor for compliance checks */
  valuesFloor?: ValuesFloor
  /** Optional recovery policy for failed tool calls */
  recoveryPolicy?: RecoveryPolicy
  /** Callback when an action is denied */
  onDenied?: (event: DenialEvent) => void
  /** Callback for every receipt (audit logging) */
  onReceipt?: (receipt: ActionReceipt) => void
}

/** Result of a governed action execution */
export type GovernedResult = {
  result: unknown
  receipt: ActionReceipt
} | {
  denied: true
  reason: string
  denialReceipt: ActionReceipt
}

/** A tool wrapped with APS governance */
export interface GovernedAction {
  name: string
  description: string
  execute: (params: Record<string, unknown>) => Promise<GovernedResult>
}
