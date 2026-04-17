// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — `DataGateway` has moved to the AEOESS Gateway.
 *
 * This class was product intelligence (composable enforcement + terms
 * acceptance runtime), not a protocol primitive. It lives at @aeoess/gateway
 * (src/sdk-migrated/core/data-gateway.ts).
 *
 * Interface types remain here for compatibility with `ProxyGateway` config.
 * See MIGRATION.md#data-lifecycle.
 */

import type { SourceReceipt } from '../types/data-source.js'
import type { DataAccessRequest, DataAccessDecision } from './data-enforcement.js'

const MOVED = 'DataGateway has moved to @aeoess/gateway. See MIGRATION.md#data-lifecycle'

// ── Interface types (preserved for SDK gateway.ts type compatibility) ──

export interface TermsAcceptance {
  agentId: string
  agentPublicKey: string
  sourceReceiptId: string
  acceptedAt: string
  compensationAcknowledged: boolean
  signature?: string
}

export interface DataGatewayConfig {
  gatewayId: string
  gatewayPublicKey: string
  gatewayPrivateKey: string
  enforcementMode: 'enforce' | 'audit' | 'off'
  requireTermsAcceptance: boolean
  onAccessBlocked?: (agentId: string, source: string, reason: string) => void
  onAccessGranted?: (agentId: string, source: string, receiptId: string) => void
  onTermsAccepted?: (acceptance: TermsAcceptance) => void
}

// ── Stub class (throws on instantiation; shape preserved for type-only imports) ──

export class DataGateway {
  constructor(_config?: unknown, _ledger?: unknown) {
    throw new Error(MOVED)
  }
  registerSource(_receipt: SourceReceipt, _descriptor: string): void { throw new Error(MOVED) }
  acceptTerms(_opts: {
    agentId: string
    agentPublicKey: string
    sourceReceiptId: string
    signature?: string
  }): TermsAcceptance { throw new Error(MOVED) }
  hasAcceptedTerms(_agentId: string, _sourceReceiptId: string): boolean { throw new Error(MOVED) }
  requestAccess(_request: DataAccessRequest): DataAccessDecision { throw new Error(MOVED) }
  preflightAccess(_requests: DataAccessRequest[]): { allAllowed: boolean; decisions: DataAccessDecision[] } { throw new Error(MOVED) }
  getEnforcementGate(): never { throw new Error(MOVED) }
  getLedger(): never { throw new Error(MOVED) }
  getAcceptances(): TermsAcceptance[] { throw new Error(MOVED) }
  revokeAcceptance(_agentId: string, _sourceReceiptId: string): boolean { throw new Error(MOVED) }
  revokeAllAcceptancesForSource(_sourceReceiptId: string): number { throw new Error(MOVED) }
}
