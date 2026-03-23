/**
 * APS v2 Semantic Scoping (Section 4)
 *
 * V2ScopeDefinition has semantic_boundaries but nothing enforces them.
 * This module validates actions against semantic constraints at runtime.
 * Not just "may send emails" but "may send emails that don't contain
 * financial projections and don't contact anyone outside approved list."
 */


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

const scopes: Map<string, SemanticScope> = new Map()
const violations: ScopeViolation[] = []

export function defineSemanticScope(params: {
  delegation_id: string; base_action: string; constraints: SemanticConstraint[];
}): SemanticScope {
  const s: SemanticScope = {
    id: `semscope-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    delegation_id: params.delegation_id,
    base_action: params.base_action,
    constraints: params.constraints,
    created_at: new Date().toISOString(),
  }
  scopes.set(s.id, s)
  return s
}

export function checkSemanticCompliance(
  scopeId: string, agentId: string, actionMetadata: Record<string, string>
): { compliant: boolean; violations: ScopeViolation[] } {
  const scope = scopes.get(scopeId)
  if (!scope) throw new Error(`Scope ${scopeId} not found`)
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
      case 'must_exclude':
        const excludeMatch = values.find(v => fieldValue.toLowerCase().includes(v.toLowerCase()))
        if (excludeMatch) {
          violated = true; detail = `Field "${c.field}" must not contain "${excludeMatch}"`
        }
        break
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
      const v: ScopeViolation = {
        id: `scopeviol-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        scope_id: scopeId, agent_id: agentId,
        action_description: JSON.stringify(actionMetadata),
        violated_constraint: c, violation_detail: detail,
        created_at: new Date().toISOString(),
      }
      found.push(v)
      violations.push(v)
    }
  }
  return { compliant: found.length === 0, violations: found }
}

export function getScopeViolations(agentId?: string): ScopeViolation[] {
  return agentId ? violations.filter(v => v.agent_id === agentId) : [...violations]
}

export function clearSemanticScopingStores(): void {
  scopes.clear(); violations.length = 0
}
