// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Migration v2 — primitive shapes only (types + version-compat predicate).
// ══════════════════════════════════════════════════════════════════════
// The fork-and-sunset lifecycle workflow (request store, migration store,
// approval state machine, probation tracking, lineage queries) has been
// split out to migration-workflow.ts in @aeoess/gateway
// (src/sdk-migrated/v2/). This module keeps ONLY:
//
//   MigrationRequest / MigrationRecord   (types — in src/v2/types.ts)
//   isV2MigrationFactorCompatible        (pure version-compat predicate)
//
// Stateful helpers (requestV2Migration, approveV2Migration,
// executeV2Migration, rollbackV2Migration, processV2CompletedProbations,
// isV2InProbation, computeV2MigrationDiscount, traceV2MigrationLineage,
// getV2MigrationRequest, getV2MigrationRecord, getV2MigrationsForAgent,
// getV2ActiveProbations, clearV2MigrationStores) remain exported as
// deprecation stubs that throw and point callers to the gateway module.
// ══════════════════════════════════════════════════════════════════════

import type {
  PolicyContext, ReputationInheritance,
  MigrationRequest, MigrationRecord,
} from './types.js'

const MOVED =
  'This function has moved to migration-workflow in @aeoess/gateway ' +
  '(src/sdk-migrated/v2/migration-workflow.ts). ' +
  'Migration types stay in src/v2/types.ts; SDK retains only the ' +
  'version-compatibility predicate.'

// ══════════════════════════════════════
// PURE VERSION-COMPATIBILITY PREDICATE
// ══════════════════════════════════════

/**
 * Pure: a migration factor is valid iff in [0, 1]. Callers use this to
 * check migration receipts before honoring them.
 */
export function isV2MigrationFactorCompatible(factor: number): boolean {
  return Number.isFinite(factor) && factor >= 0 && factor <= 1
}

// ══════════════════════════════════════════════════════════════════════
// STATEFUL HELPERS — moved to @aeoess/gateway
// ══════════════════════════════════════════════════════════════════════

export function requestV2Migration(_params: {
  source_agent: string
  source_delegation: string
  limitation: string
  requested_scope_change: string
  justification: string
  agent_private_key: string
  policy_context: PolicyContext
}): MigrationRequest { throw new Error(MOVED) }

export function approveV2Migration(_params: {
  request_id: string; approver: string; approved: boolean
  response: string; approver_private_key: string
}): MigrationRequest { throw new Error(MOVED) }

export function executeV2Migration(_params: {
  request_id: string
  target_agent: string
  target_delegation: string
  state_data: string
  reputation_inheritance: ReputationInheritance
  migration_factor?: number
  probation_duration?: string
  approver: string
  approver_private_key: string
  source_private_key: string
  target_private_key: string
  policy_context: PolicyContext
}): MigrationRecord { throw new Error(MOVED) }

export function isV2InProbation(_agentId: string): boolean { throw new Error(MOVED) }

export function computeV2MigrationDiscount(_rawRep: number, _agentId: string): number {
  throw new Error(MOVED)
}

export function traceV2MigrationLineage(_agentId: string): MigrationRecord[] {
  throw new Error(MOVED)
}

export function rollbackV2Migration(_migrationId: string, _reason: string): MigrationRecord {
  throw new Error(MOVED)
}

export function processV2CompletedProbations(): string[] { throw new Error(MOVED) }

export function getV2MigrationRequest(_id: string): MigrationRequest | undefined {
  throw new Error(MOVED)
}

export function getV2MigrationRecord(_id: string): MigrationRecord | undefined {
  throw new Error(MOVED)
}

export function getV2MigrationsForAgent(_agentId: string): MigrationRecord[] {
  throw new Error(MOVED)
}

export function getV2ActiveProbations(): MigrationRecord[] { throw new Error(MOVED) }

export function clearV2MigrationStores(): void {
  // No-op: SDK no longer holds state. Gateway owns the stores.
}
