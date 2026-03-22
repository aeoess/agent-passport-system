/**
 * APS v2 Collective Circuit Breakers (Emergence Defense)
 *
 * When population metrics indicate dangerous convergence, temporarily
 * suspend action categories. Like financial circuit breakers that halt
 * trading when markets drop too fast.
 */

export type BreakerState = 'armed' | 'tripped' | 'reset'

export interface CircuitBreaker {
  id: string
  action_category: string
  metric_name: string
  threshold: number          // trip when metric exceeds this
  comparison: 'gt' | 'lt' | 'gte' | 'lte'
  cooldown_ms: number        // how long the breaker stays tripped
  state: BreakerState
  tripped_at: string | null
  reset_at: string | null
  trip_count: number
  created_at: string
}

const breakers: Map<string, CircuitBreaker> = new Map()
const blockedActions: Set<string> = new Set() // action categories currently blocked

export function defineBreaker(params: {
  action_category: string; metric_name: string;
  threshold: number; comparison: CircuitBreaker['comparison'];
  cooldown_ms: number;
}): CircuitBreaker {
  const b: CircuitBreaker = {
    id: `breaker-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    action_category: params.action_category,
    metric_name: params.metric_name,
    threshold: params.threshold,
    comparison: params.comparison,
    cooldown_ms: params.cooldown_ms,
    state: 'armed', tripped_at: null, reset_at: null, trip_count: 0,
    created_at: new Date().toISOString(),
  }
  breakers.set(b.id, b)
  return b
}

function meetsThreshold(value: number, threshold: number, cmp: CircuitBreaker['comparison']): boolean {
  switch (cmp) {
    case 'gt': return value > threshold
    case 'lt': return value < threshold
    case 'gte': return value >= threshold
    case 'lte': return value <= threshold
  }
}

export function evaluateBreaker(breakerId: string, currentMetricValue: number): CircuitBreaker {
  const b = breakers.get(breakerId)
  if (!b) throw new Error(`Breaker ${breakerId} not found`)
  if (b.state === 'tripped') {
    // Check if cooldown expired
    if (b.tripped_at && Date.now() - new Date(b.tripped_at).getTime() > b.cooldown_ms) {
      b.state = 'reset'
      b.reset_at = new Date().toISOString()
      blockedActions.delete(b.action_category)
    }
    return b
  }
  if (meetsThreshold(currentMetricValue, b.threshold, b.comparison)) {
    return tripBreaker(breakerId)
  }
  return b
}

export function tripBreaker(breakerId: string): CircuitBreaker {
  const b = breakers.get(breakerId)
  if (!b) throw new Error(`Breaker ${breakerId} not found`)
  b.state = 'tripped'
  b.tripped_at = new Date().toISOString()
  b.trip_count++
  blockedActions.add(b.action_category)
  return b
}

export function resetBreaker(breakerId: string): CircuitBreaker {
  const b = breakers.get(breakerId)
  if (!b) throw new Error(`Breaker ${breakerId} not found`)
  b.state = 'armed'
  b.reset_at = new Date().toISOString()
  blockedActions.delete(b.action_category)
  return b
}

export function isActionBlocked(actionCategory: string): boolean {
  return blockedActions.has(actionCategory)
}

export function getBreaker(id: string): CircuitBreaker | undefined { return breakers.get(id) }
export function getAllBreakers(): CircuitBreaker[] { return [...breakers.values()] }
export function getBlockedCategories(): string[] { return [...blockedActions] }

export function clearCircuitBreakerStores(): void {
  breakers.clear(); blockedActions.clear()
}
