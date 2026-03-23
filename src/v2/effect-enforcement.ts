/**
 * APS v2 Effect Enforcement (Authorization-Effect Gap)
 *
 * Crypto proves what was authorized (the locution), not what happened
 * (the perlocution). This module closes that gap by requiring agents to:
 * 1. Declare expected effects before action
 * 2. Report actual effects after action
 * 3. Detect systematic divergence patterns over time
 *
 * The gateway can block agents with high divergence scores.
 */

import type {
  EffectDeclaration, EffectVerification, EffectPattern,
  PolicyContext,
} from './types.js'

// ── Stores ──
const declarations: Map<string, EffectDeclaration> = new Map()
const verifications: Map<string, EffectVerification> = new Map()
const patterns: Map<string, EffectPattern[]> = new Map()

// ── Declare Expected Effects ──

export function declareEffects(params: {
  intent_id: string; agent_id: string;
  expected_effects: string[];
  acceptable_divergence: number;
  verification_method: EffectDeclaration['verification_method'];
  policy_context: PolicyContext;
  signature: string;
}): EffectDeclaration {
  const decl: EffectDeclaration = {
    id: `decl-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    intent_id: params.intent_id,
    agent_id: params.agent_id,
    expected_effects: params.expected_effects,
    acceptable_divergence: params.acceptable_divergence,
    verification_method: params.verification_method,
    policy_context: params.policy_context,
    signature: params.signature,
    created_at: new Date().toISOString(),
  }
  declarations.set(decl.id, decl)
  return decl
}

export function getDeclaration(id: string): EffectDeclaration | undefined {
  return declarations.get(id)
}

export function getDeclarationsForAgent(agentId: string): EffectDeclaration[] {
  return [...declarations.values()].filter(d => d.agent_id === agentId)
}

// ── Verify Actual Effects ──

export function verifyEffects(params: {
  declaration_id: string; intent_id: string; agent_id: string;
  actual_effects: string[]; verifier: string; signature: string;
}): EffectVerification {
  const decl = declarations.get(params.declaration_id)
  if (!decl) throw new Error(`Declaration ${params.declaration_id} not found`)

  const declaredSet = new Set(decl.expected_effects)
  const actualSet = new Set(params.actual_effects)
  const matched = params.actual_effects.filter(e => declaredSet.has(e))
  const unmatchedDeclared = decl.expected_effects.filter(e => !actualSet.has(e))
  const undeclaredActual = params.actual_effects.filter(e => !declaredSet.has(e))

  const totalUnique = new Set([...decl.expected_effects, ...params.actual_effects]).size
  const divergence = totalUnique > 0 ? 1 - (matched.length / totalUnique) : 0

  const verdict: EffectVerification['verdict'] =
    divergence <= decl.acceptable_divergence ? 'within_tolerance' :
    divergence > 0.8 ? 'blocked' : 'divergent'

  const v: EffectVerification = {
    id: `verify-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    declaration_id: params.declaration_id,
    intent_id: params.intent_id,
    agent_id: params.agent_id,
    actual_effects: params.actual_effects,
    matched_effects: matched,
    unmatched_declared: unmatchedDeclared,
    undeclared_actual: undeclaredActual,
    divergence_score: Math.round(divergence * 1000) / 1000,
    verdict, verifier: params.verifier, signature: params.signature,
    created_at: new Date().toISOString(),
  }
  verifications.set(v.id, v)

  // Auto-detect patterns on divergent verifications
  if (verdict !== 'within_tolerance') {
    detectPattern(params.agent_id, v)
  }
  return v
}

export function getVerification(id: string): EffectVerification | undefined {
  return verifications.get(id)
}

export function getVerificationsForAgent(agentId: string): EffectVerification[] {
  return [...verifications.values()].filter(v => v.agent_id === agentId)
}

export function getAgentDivergenceAvg(agentId: string): number {
  const vs = getVerificationsForAgent(agentId)
  if (vs.length === 0) return 0
  return vs.reduce((s, v) => s + v.divergence_score, 0) / vs.length
}

export function isAgentBlockedByEffects(agentId: string, threshold?: number): boolean {
  const avg = getAgentDivergenceAvg(agentId)
  return avg > (threshold || 0.6)
}

// ── Pattern Detection ──

function detectPattern(agentId: string, v: EffectVerification): void {
  const existing = patterns.get(agentId) || []
  const now = new Date().toISOString()

  // Check for systematic underdeclaring (always has undeclared actual effects)
  if (v.undeclared_actual.length > 0) {
    const p = existing.find(p => p.pattern_type === 'systematic_underdeclare')
    if (p) {
      p.frequency++
      p.examples.push(v.undeclared_actual[0])
      if (p.examples.length > 10) p.examples = p.examples.slice(-10)
      p.last_seen = now
    } else {
      existing.push({
        agent_id: agentId, pattern_type: 'systematic_underdeclare',
        frequency: 1, examples: [v.undeclared_actual[0]],
        first_seen: now, last_seen: now,
      })
    }
  }

  // Check for systematic side effects (same undeclared effect repeating)
  const allVerifications = getVerificationsForAgent(agentId)
  const undeclaredCounts: Record<string, number> = {}
  for (const ver of allVerifications) {
    for (const ue of ver.undeclared_actual) {
      undeclaredCounts[ue] = (undeclaredCounts[ue] || 0) + 1
    }
  }
  for (const [effect, count] of Object.entries(undeclaredCounts)) {
    if (count >= 3) {
      const p = existing.find(p => p.pattern_type === 'systematic_side_effect')
      if (!p) {
        existing.push({
          agent_id: agentId, pattern_type: 'systematic_side_effect',
          frequency: count, examples: [effect],
          first_seen: allVerifications[0].created_at, last_seen: now,
        })
      } else {
        p.frequency = count
        if (!p.examples.includes(effect)) p.examples.push(effect)
        p.last_seen = now
      }
    }
  }

  patterns.set(agentId, existing)
}

export function getEffectPatterns(agentId: string): EffectPattern[] {
  return patterns.get(agentId) || []
}

export function clearEffectStores(): void {
  declarations.clear()
  verifications.clear()
  patterns.clear()
}
