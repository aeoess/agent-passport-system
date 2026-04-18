// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Semantic Scoping — pure constraint-check primitive.
// ══════════════════════════════════════════════════════════════════════
// The scope registry and violation ledger that used to live here have
// been split out to scope-violations.ts in @aeoess/gateway
// (src/sdk-migrated/v2/). This module keeps ONLY:
//
//   SemanticConstraint, SemanticScope, ScopeViolation   (types)
//   evaluateSemanticConstraints                         (pure check)
//
// Stateful helpers (defineSemanticScope, checkSemanticCompliance,
// getScopeViolations, clearSemanticScopingStores) remain exported as
// deprecation stubs that throw and point callers to the gateway module.
// ══════════════════════════════════════════════════════════════════════

export interface SemanticConstraint {
  field: string
  operator: 'must_include' | 'must_exclude' | 'must_match' | 'must_not_match'
  value: string | string[]
}

export interface SemanticScope {
  id: string
  delegation_id: string
  base_action: string
  constraints: SemanticConstraint[]
  created_at: string
}

export interface ScopeViolation {
  id: string
  scope_id: string
  agent_id: string
  action_description: string
  violated_constraint: SemanticConstraint
  violation_detail: string
  created_at: string
}

const MOVED =
  'This function has moved to scope-violations in @aeoess/gateway ' +
  '(src/sdk-migrated/v2/scope-violations.ts). ' +
  'Pure primitive evaluateSemanticConstraints stays in the SDK. See MIGRATION.md.'

// ══════════════════════════════════════
// PURE CONSTRAINT EVALUATION
// ══════════════════════════════════════

/**
 * Evaluates a SemanticScope's constraints against an action's metadata.
 * Pure: does not read from or write to any registry. Callers own the
 * scope lookup and the violation ledger.
 */
export function evaluateSemanticConstraints(
  scope: SemanticScope, agentId: string, actionMetadata: Record<string, string>,
): { compliant: boolean; violations: ScopeViolation[] } {
  const found: ScopeViolation[] = []

  for (const c of scope.constraints) {
    const fieldValue = actionMetadata[c.field] || ''
    const values = Array.isArray(c.value) ? c.value : [c.value]
    let violated = false
    let detail = ''

    switch (c.operator) {
      case 'must_include':
        if (!values.some(v => fieldValue.toLowerCase().includes(v.toLowerCase()))) {
          violated = true; detail = `Field "${c.field}" must include one of [${values.join(', ')}]`
        }
        break
      case 'must_exclude': {
        const excludeMatch = values.find(v => fieldValue.toLowerCase().includes(v.toLowerCase()))
        if (excludeMatch) {
          violated = true; detail = `Field "${c.field}" must not contain "${excludeMatch}"`
        }
        break
      }
      case 'must_match':
        if (!values.includes(fieldValue)) {
          violated = true; detail = `Field "${c.field}" must be one of [${values.join(', ')}], got "${fieldValue}"`
        }
        break
      case 'must_not_match':
        if (values.includes(fieldValue)) {
          violated = true; detail = `Field "${c.field}" must not be "${fieldValue}"`
        }
        break
    }

    if (violated) {
      found.push({
        id: `scopeviol-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        scope_id: scope.id, agent_id: agentId,
        action_description: JSON.stringify(actionMetadata),
        violated_constraint: c, violation_detail: detail,
        created_at: new Date().toISOString(),
      })
    }
  }
  return { compliant: found.length === 0, violations: found }
}

// ══════════════════════════════════════════════════════════════════════
// STATEFUL HELPERS — moved to @aeoess/gateway
// ══════════════════════════════════════════════════════════════════════

export function defineSemanticScope(_params: {
  delegation_id: string; base_action: string; constraints: SemanticConstraint[];
}): SemanticScope { throw new Error(MOVED) }

export function checkSemanticCompliance(
  _scopeId: string, _agentId: string, _actionMetadata: Record<string, string>,
): { compliant: boolean; violations: ScopeViolation[] } { throw new Error(MOVED) }

export function getScopeViolations(_agentId?: string): ScopeViolation[] {
  throw new Error(MOVED)
}

export function clearSemanticScopingStores(): void {
  // No-op: SDK no longer holds state. Gateway owns the store.
}
