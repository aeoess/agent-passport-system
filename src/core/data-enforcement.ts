// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — `DataEnforcementGate` has moved to the AEOESS Gateway.
 *
 * This class was product intelligence (stateful enforcement + contribution
 * ledger feed), not a protocol primitive. It lives at @aeoess/gateway
 * (src/sdk-migrated/core/data-enforcement.ts).
 *
 * Interface types remain here for compatibility with gateway wiring in
 * `ProxyGateway` config. See MIGRATION.md#data-lifecycle.
 */

import type {
  DataAccessReceipt, SourceReceipt, DataPurpose, AccessMethod,
} from '../types/data-source.js'

const MOVED = 'DataEnforcementGate has moved to @aeoess/gateway. See MIGRATION.md#data-lifecycle'

// ── Interface types (preserved for SDK gateway.ts type compatibility) ──

export interface DataEnforcementConfig {
  gatewayId: string
  gatewayPublicKey: string
  gatewayPrivateKey: string
  mode: 'enforce' | 'audit' | 'off'
  onAccessBlocked?: (agentId: string, sourceId: string, violations: string[]) => void
  onAccessRecorded?: (receipt: DataAccessReceipt) => void
  onTermsWarning?: (agentId: string, sourceId: string, warnings: string[]) => void
}

export interface DataAccessRequest {
  agentId: string
  agentPublicKey: string
  principalId: string
  delegationId?: string
  sourceReceiptId: string
  declaredPurpose: DataPurpose
  accessMethod: AccessMethod
  accessScope: string
  executionFrameId: string
  dataHash?: string
}

export interface DataAccessDecision {
  allowed: boolean
  sourceReceiptId: string
  hardViolations: string[]
  advisoryWarnings: string[]
  receipt?: DataAccessReceipt
  accessesRemaining?: number
}

// ── Stub class (throws on instantiation) ──

export class DataEnforcementGate {
  constructor(_config?: unknown, _ledger?: unknown) {
    throw new Error(MOVED)
  }
  registerSource(_receipt: SourceReceipt, _descriptor: string): void { throw new Error(MOVED) }
  getLedger(): never { throw new Error(MOVED) }
  getReceipts(): DataAccessReceipt[] { throw new Error(MOVED) }
  getMerkleRoot(): string { throw new Error(MOVED) }
  checkAccess(_request: DataAccessRequest): DataAccessDecision { throw new Error(MOVED) }
  preflightCheck(_requests: DataAccessRequest[]): { allAllowed: boolean; decisions: DataAccessDecision[] } { throw new Error(MOVED) }
}
