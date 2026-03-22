/**
 * APS v2 End-to-End Intent Binding (Distributed Responsibility Defense)
 *
 * In multi-agent pipelines, each agent says "I only performed my bounded task."
 * The original purpose gets lost in the delegation chain. This module carries
 * the original intent through the entire chain and checks for drift at each hop.
 */

export interface ChainedIntent {
  original_intent: string
  original_principal: string
  chain: Array<{ agent_id: string; local_intent: string; hop: number; timestamp: string }>
}

const intentChains: Map<string, ChainedIntent> = new Map()

export function createIntentChain(chainId: string, originalIntent: string, principalId: string): ChainedIntent {
  const chain: ChainedIntent = {
    original_intent: originalIntent,
    original_principal: principalId,
    chain: [],
  }
  intentChains.set(chainId, chain)
  return chain
}

export function extendChain(chainId: string, agentId: string, localIntent: string): ChainedIntent {
  const chain = intentChains.get(chainId)
  if (!chain) throw new Error(`Chain ${chainId} not found`)
  chain.chain.push({
    agent_id: agentId, local_intent: localIntent,
    hop: chain.chain.length + 1, timestamp: new Date().toISOString(),
  })
  return chain
}

// Check if local intent at each hop drifts from original
export function validateChainIntegrity(chainId: string): {
  chain_id: string; original_intent: string; hops: number;
  drift_scores: Array<{ agent_id: string; hop: number; drift: number }>;
  max_drift: number; integrity_ok: boolean;
} {
  const chain = intentChains.get(chainId)
  if (!chain) throw new Error(`Chain ${chainId} not found`)

  const origWords = new Set(extractWords(chain.original_intent))
  const drifts = chain.chain.map(hop => {
    const localWords = new Set(extractWords(hop.local_intent))
    const intersection = [...origWords].filter(w => localWords.has(w)).length
    const union = new Set([...origWords, ...localWords]).size
    const similarity = union > 0 ? intersection / union : 1
    return { agent_id: hop.agent_id, hop: hop.hop, drift: Math.round((1 - similarity) * 1000) / 1000 }
  })

  const maxDrift = drifts.length > 0 ? Math.max(...drifts.map(d => d.drift)) : 0
  return {
    chain_id: chainId, original_intent: chain.original_intent,
    hops: chain.chain.length, drift_scores: drifts,
    max_drift: maxDrift, integrity_ok: maxDrift < 0.7,
  }
}

function extractWords(text: string): string[] {
  return text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(w => w.length > 2)
}

export function getIntentChain(chainId: string): ChainedIntent | undefined { return intentChains.get(chainId) }
export function clearIntentBindingStores(): void { intentChains.clear() }
