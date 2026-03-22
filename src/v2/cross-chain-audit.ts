/**
 * APS v2 Cross-Chain Audit (Section 7)
 *
 * Existing cross-chain.ts tracks taint within chains. This module
 * monitors data flows BETWEEN independent delegation chains and
 * flags unauthorized cross-chain bridging.
 */

export interface CrossChainFlow {
  id: string
  source_chain: string
  target_chain: string
  data_category: string
  agent_id: string
  authorized: boolean
  timestamp: string
}

export interface FlowAuditResult {
  total_flows: number
  unauthorized_flows: number
  unique_chain_pairs: number
  flagged_flows: CrossChainFlow[]
  computed_at: string
}

const flows: CrossChainFlow[] = []

export function recordCrossChainFlow(params: {
  source_chain: string; target_chain: string; data_category: string;
  agent_id: string; authorized: boolean;
}): CrossChainFlow {
  const f: CrossChainFlow = {
    id: `xchain-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    source_chain: params.source_chain, target_chain: params.target_chain,
    data_category: params.data_category, agent_id: params.agent_id,
    authorized: params.authorized, timestamp: new Date().toISOString(),
  }
  flows.push(f)
  return f
}

export function auditCrossChainFlows(): FlowAuditResult {
  const unauthorized = flows.filter(f => !f.authorized)
  const pairs = new Set(flows.map(f => `${f.source_chain}->${f.target_chain}`))
  return {
    total_flows: flows.length, unauthorized_flows: unauthorized.length,
    unique_chain_pairs: pairs.size, flagged_flows: unauthorized,
    computed_at: new Date().toISOString(),
  }
}

export function detectUnauthorizedBridging(): CrossChainFlow[] {
  return flows.filter(f => !f.authorized)
}

export function clearCrossChainAuditStores(): void { flows.length = 0 }
