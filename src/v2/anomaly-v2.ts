// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Anomaly v2 — pure primitives (types + uncertainty-compliance predicate).
// ══════════════════════════════════════════════════════════════════════
// The action-history ledger, first-max-authority detector, and
// delegation-concentration (Monolith) scoring have been split out to
// anomaly-detection.ts in @aeoess/gateway (src/sdk-migrated/v2/). This
// module keeps ONLY:
//
//   validateV2UncertaintyCompliance  — pure predicate over attestation shape
//
// Stateful helpers (recordV2Action, getV2ActionHistory,
// checkV2FirstMaxAuthority, computeV2ConcentrationMetrics,
// getV2AnomalyFlags, getV2UnreviewedFlags, reviewV2AnomalyFlag,
// clearV2AnomalyStores) remain exported as deprecation stubs that throw
// and point callers to the gateway module.
// ══════════════════════════════════════════════════════════════════════

import type {
  ActionRecord, AnomalyFlag, SemanticUncertainty, ConcentrationMetrics,
} from './types.js'

const MOVED =
  'This function has moved to anomaly-detection in @aeoess/gateway ' +
  '(src/sdk-migrated/v2/anomaly-detection.ts). ' +
  'Pure primitive validateV2UncertaintyCompliance stays in the SDK. See MIGRATION.md.'

// ═══════════════════════════════════════════════
// SEMANTIC UNCERTAINTY VALIDATION (pure)
// ═══════════════════════════════════════════════

export function validateV2UncertaintyCompliance(
  level: SemanticUncertainty,
  has_attestation: boolean,
  has_outcome_registration: boolean,
  has_external_cosign: boolean,
): string[] {
  const violations: string[] = []
  if ((level === 'medium' || level === 'high' || level === 'critical') && !has_attestation) {
    violations.push(`${level} requires contextual attestation`)
  }
  if ((level === 'medium' || level === 'high' || level === 'critical') && !has_outcome_registration) {
    violations.push(`${level} requires outcome registration`)
  }
  if ((level === 'high' || level === 'critical') && !has_external_cosign) {
    violations.push(`${level} requires external co-signing`)
  }
  return violations
}

// ══════════════════════════════════════════════════════════════════════
// STATEFUL HELPERS — moved to @aeoess/gateway
// ══════════════════════════════════════════════════════════════════════

export function recordV2Action(_record: ActionRecord): void { throw new Error(MOVED) }

export function getV2ActionHistory(_agentId: string): ActionRecord[] {
  throw new Error(MOVED)
}

export function getV2AnomalyFlags(_agentId?: string): AnomalyFlag[] {
  throw new Error(MOVED)
}

export function getV2UnreviewedFlags(_agentId?: string): AnomalyFlag[] {
  throw new Error(MOVED)
}

export function checkV2FirstMaxAuthority(_record: ActionRecord): AnomalyFlag | null {
  throw new Error(MOVED)
}

export function computeV2ConcentrationMetrics(
  _agentId: string, _flagThreshold?: number,
): ConcentrationMetrics { throw new Error(MOVED) }

export function reviewV2AnomalyFlag(_flagId: string, _outcome: string): AnomalyFlag | undefined {
  throw new Error(MOVED)
}

export function clearV2AnomalyStores(): void {
  // No-op: SDK no longer holds state. Gateway owns the store.
}
