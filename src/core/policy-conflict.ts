// ══════════════════════════════════════════════════════════════════
// Policy Conflict Detection — Module 30
// ══════════════════════════════════════════════════════════════════
// Problem: When multiple valid policies apply to the same action,
// they can conflict (circular dependency, mutual exclusion) or
// one can shadow another (making rules unreachable).
//
// Solution: Model policy rules as a directed graph. Use DFS to
// detect cycles (deadlock). Detect shadowed rules (unreachable).
// Detect contradictions (same action, opposite verdicts).
// ══════════════════════════════════════════════════════════════════

// ── Types ──

export type PolicyVerdict = 'permit' | 'deny'

/** A single policy rule: if conditions match, produce verdict for action */
export interface PolicyRule {
  ruleId: string
  /** What action scope this rule governs */
  actionScope: string
  /** Verdict when this rule fires */
  verdict: PolicyVerdict
  /** Priority (higher = evaluated first) */
  priority: number
  /** Other rule IDs that must be evaluated before this one (dependencies) */
  dependsOn: string[]
  /** Conditions as key-value (simplified — real impl would use predicate logic) */
  conditions: Record<string, string>
}

/** Result of analyzing a policy rule set */
export interface PolicyConflictReport {
  /** Circular dependencies found (each array is a cycle path) */
  cycles: string[][]
  /** Rules that can never fire because a higher-priority rule always shadows them */
  shadowedRules: ShadowedRule[]
  /** Rules that produce opposite verdicts for the same action scope */
  contradictions: PolicyContradiction[]
  /** Actions that no rule covers */
  unreachableActions: string[]
  /** Overall health: clean if no cycles, contradictions */
  healthy: boolean
}

export interface ShadowedRule {
  shadowedRuleId: string
  shadowedByRuleId: string
  reason: string
}

export interface PolicyContradiction {
  action: string
  permitRuleId: string
  denyRuleId: string
}

// ══════════════════════════════════════
// CYCLE DETECTION — DFS
// ══════════════════════════════════════

/**
 * Detect cycles in the policy dependency graph using DFS.
 * Each rule's dependsOn forms edges: rule → dependency.
 * A cycle means deadlock — rule A needs B which needs A.
 */
export function detectCycles(rules: PolicyRule[]): string[][] {
  const ruleMap = new Map(rules.map(r => [r.ruleId, r]))
  const cycles: string[][] = []
  const visited = new Set<string>()
  const inStack = new Set<string>()

  function dfs(nodeId: string, path: string[]): void {
    if (inStack.has(nodeId)) {
      // Found a cycle — extract the cycle portion from path
      const cycleStart = path.indexOf(nodeId)
      if (cycleStart >= 0) {
        cycles.push(path.slice(cycleStart).concat(nodeId))
      }
      return
    }
    if (visited.has(nodeId)) return

    visited.add(nodeId)
    inStack.add(nodeId)
    path.push(nodeId)

    const rule = ruleMap.get(nodeId)
    if (rule) {
      for (const dep of rule.dependsOn) {
        dfs(dep, [...path])
      }
    }

    inStack.delete(nodeId)
  }

  for (const rule of rules) {
    if (!visited.has(rule.ruleId)) {
      dfs(rule.ruleId, [])
    }
  }

  return cycles
}

// ══════════════════════════════════════
// SHADOWED RULE DETECTION
// ══════════════════════════════════════

/**
 * A rule is "shadowed" if another rule with higher priority
 * covers the same action scope with identical or superset conditions.
 * The shadowed rule can never fire.
 */
export function detectShadowedRules(rules: PolicyRule[]): ShadowedRule[] {
  const shadowed: ShadowedRule[] = []

  // Sort by priority descending
  const sorted = [...rules].sort((a, b) => b.priority - a.priority)

  for (let i = 0; i < sorted.length; i++) {
    const candidate = sorted[i]
    for (let j = 0; j < i; j++) {
      const higher = sorted[j]
      // Same action scope (or higher covers candidate via hierarchy)
      if (scopeCovers(higher.actionScope, candidate.actionScope)) {
        // Check if higher's conditions are a subset of candidate's (meaning higher always fires first)
        if (conditionsSubset(higher.conditions, candidate.conditions)) {
          shadowed.push({
            shadowedRuleId: candidate.ruleId,
            shadowedByRuleId: higher.ruleId,
            reason: `Rule ${higher.ruleId} (priority ${higher.priority}) covers same scope "${candidate.actionScope}" with equal or broader conditions`,
          })
          break  // Only report first shadowing rule
        }
      }
    }
  }

  return shadowed
}

/** Check if scopeA covers scopeB (same logic as delegation.ts) */
function scopeCovers(scopeA: string, scopeB: string): boolean {
  if (scopeA === '*') return true
  if (scopeA === scopeB) return true
  if (scopeA.endsWith(':*')) {
    const prefix = scopeA.slice(0, -1)  // "data:*" → "data:"
    return scopeB.startsWith(prefix)
  }
  // Hierarchical: "data" covers "data:read"
  return scopeB.startsWith(scopeA + ':')
}

/** Check if conditionsA is a subset of conditionsB (A is broader or equal) */
function conditionsSubset(condA: Record<string, string>, condB: Record<string, string>): boolean {
  // If A has fewer conditions, it's broader (fires in more cases)
  // Every condition in A must also exist with same value in B
  for (const [key, value] of Object.entries(condA)) {
    if (condB[key] !== value) return false
  }
  return true
}

// ══════════════════════════════════════
// CONTRADICTION DETECTION
// ══════════════════════════════════════

/**
 * Find pairs of rules that produce opposite verdicts for overlapping scopes
 * at the same priority level (true conflict — no priority tiebreak).
 */
export function detectContradictions(rules: PolicyRule[]): PolicyContradiction[] {
  const contradictions: PolicyContradiction[] = []
  const seen = new Set<string>()

  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      const a = rules[i], b = rules[j]
      if (a.verdict === b.verdict) continue
      if (a.priority !== b.priority) continue

      // Check if scopes overlap
      const overlaps = scopeCovers(a.actionScope, b.actionScope) ||
                        scopeCovers(b.actionScope, a.actionScope)
      if (!overlaps) continue

      const key = [a.ruleId, b.ruleId].sort().join(':')
      if (seen.has(key)) continue
      seen.add(key)

      const [permitRule, denyRule] = a.verdict === 'permit' ? [a, b] : [b, a]
      contradictions.push({
        action: a.actionScope,
        permitRuleId: permitRule.ruleId,
        denyRuleId: denyRule.ruleId,
      })
    }
  }
  return contradictions
}

// ══════════════════════════════════════
// UNREACHABLE ACTIONS
// ══════════════════════════════════════

/**
 * Given a set of known action scopes, find which ones no rule covers.
 */
export function detectUnreachableActions(rules: PolicyRule[], knownActions: string[]): string[] {
  return knownActions.filter(action => {
    return !rules.some(r => scopeCovers(r.actionScope, action))
  })
}

// ══════════════════════════════════════
// FULL ANALYSIS
// ══════════════════════════════════════

/**
 * Run all conflict detection analyses on a set of policy rules.
 */
export function analyzePolicyRules(
  rules: PolicyRule[],
  knownActions?: string[],
): PolicyConflictReport {
  const cycles = detectCycles(rules)
  const shadowedRules = detectShadowedRules(rules)
  const contradictions = detectContradictions(rules)
  const unreachableActions = knownActions
    ? detectUnreachableActions(rules, knownActions)
    : []

  return {
    cycles,
    shadowedRules,
    contradictions,
    unreachableActions,
    healthy: cycles.length === 0 && contradictions.length === 0,
  }
}
