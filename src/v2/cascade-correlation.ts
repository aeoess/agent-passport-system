/**
 * APS v2 Cascade Correlation (Temporal Convergence — Section 7)
 *
 * Agents acting on each other's outputs create feedback loops amplifying
 * small signals into large movements. No single agent sees the loop.
 * This module tracks output dependencies and detects cycles.
 */

export interface OutputDependency {
  id: string
  producer_agent: string
  consumer_agent: string
  output_ref: string
  consumed_at: string
}

export interface FeedbackLoop {
  id: string
  agents: string[]
  loop_length: number
  detection_confidence: number
  first_detected: string
}

export interface CorrelationMetrics {
  total_dependencies: number
  unique_pairs: number
  max_chain_depth: number
  loops_detected: number
  computed_at: string
}

const dependencies: OutputDependency[] = []
const detectedLoops: FeedbackLoop[] = []

export function recordOutputDependency(producer: string, consumer: string, outputRef: string): OutputDependency {
  const d: OutputDependency = {
    id: `dep-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    producer_agent: producer, consumer_agent: consumer,
    output_ref: outputRef, consumed_at: new Date().toISOString(),
  }
  dependencies.push(d)
  return d
}

export function detectFeedbackLoops(): FeedbackLoop[] {
  // Build adjacency list: producer → [consumers]
  const graph: Map<string, Set<string>> = new Map()
  for (const d of dependencies) {
    if (!graph.has(d.producer_agent)) graph.set(d.producer_agent, new Set())
    graph.get(d.producer_agent)!.add(d.consumer_agent)
  }

  const newLoops: FeedbackLoop[] = []
  const visited = new Set<string>()
  const stack = new Set<string>()

  function dfs(node: string, path: string[]): void {
    if (stack.has(node)) {
      // Found cycle — extract it
      const cycleStart = path.indexOf(node)
      if (cycleStart >= 0) {
        const cycle = path.slice(cycleStart)
        const key = [...cycle].sort().join(',')
        if (!detectedLoops.some(l => [...l.agents].sort().join(',') === key)) {
          const loop: FeedbackLoop = {
            id: `loop-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            agents: cycle, loop_length: cycle.length,
            detection_confidence: Math.min(1, cycle.length <= 3 ? 0.9 : 0.7),
            first_detected: new Date().toISOString(),
          }
          detectedLoops.push(loop)
          newLoops.push(loop)
        }
      }
      return
    }
    if (visited.has(node)) return
    visited.add(node)
    stack.add(node)
    for (const neighbor of (graph.get(node) || [])) {
      dfs(neighbor, [...path, node])
    }
    stack.delete(node)
  }

  for (const node of graph.keys()) {
    visited.clear(); stack.clear()
    dfs(node, [])
  }
  return newLoops
}

export function computeCorrelationMetrics(): CorrelationMetrics {
  const pairs = new Set(dependencies.map(d => `${d.producer_agent}->${d.consumer_agent}`))
  // Compute max chain depth via BFS
  const graph: Map<string, Set<string>> = new Map()
  for (const d of dependencies) {
    if (!graph.has(d.producer_agent)) graph.set(d.producer_agent, new Set())
    graph.get(d.producer_agent)!.add(d.consumer_agent)
  }
  let maxDepth = 0
  for (const start of graph.keys()) {
    const q: Array<[string, number]> = [[start, 0]]
    const seen = new Set<string>()
    while (q.length > 0) {
      const [node, depth] = q.shift()!
      if (seen.has(node)) continue
      seen.add(node)
      if (depth > maxDepth) maxDepth = depth
      for (const n of (graph.get(node) || [])) q.push([n, depth + 1])
    }
  }
  return {
    total_dependencies: dependencies.length, unique_pairs: pairs.size,
    max_chain_depth: maxDepth, loops_detected: detectedLoops.length,
    computed_at: new Date().toISOString(),
  }
}

export function getDependenciesForAgent(agentId: string): OutputDependency[] {
  return dependencies.filter(d => d.producer_agent === agentId || d.consumer_agent === agentId)
}

export function getDetectedLoops(): FeedbackLoop[] { return [...detectedLoops] }
export function clearCascadeCorrelationStores(): void { dependencies.length = 0; detectedLoops.length = 0 }
