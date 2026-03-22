/**
 * APS v2 Effect Sampling (Random Deep Auditing)
 *
 * Statistical governance: agents don't know which actions will be sampled.
 * A percentage of authorized actions get full outcome review. Critical
 * actions always sampled. Low-risk sampled probabilistically.
 */

export interface SamplingPolicy {
  id: string
  name: string
  base_rate: number          // 0-1, probability of sampling low-risk actions
  critical_rate: number      // 0-1, probability for critical (typically 1.0)
  high_rate: number          // 0-1, probability for high-risk
  medium_rate: number
  created_at: string
}

export interface AuditSample {
  id: string
  policy_id: string
  agent_id: string
  action_id: string
  risk_class: string
  sampled: boolean           // was this action selected for audit?
  audit_result: string | null
  auditor: string | null
  created_at: string
}

const policies: Map<string, SamplingPolicy> = new Map()
const samples: AuditSample[] = []
let deterministicRng: (() => number) | null = null

export function setSamplingRng(fn: () => number): void { deterministicRng = fn }

export function createSamplingPolicy(params: {
  name: string; base_rate: number;
  critical_rate?: number; high_rate?: number; medium_rate?: number;
}): SamplingPolicy {
  const p: SamplingPolicy = {
    id: `policy-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name: params.name,
    base_rate: params.base_rate,
    critical_rate: params.critical_rate ?? 1.0,
    high_rate: params.high_rate ?? 0.5,
    medium_rate: params.medium_rate ?? params.base_rate,
    created_at: new Date().toISOString(),
  }
  policies.set(p.id, p)
  return p
}

export function shouldSample(policyId: string, riskClass: string): boolean {
  const p = policies.get(policyId)
  if (!p) throw new Error(`Policy ${policyId} not found`)
  const rate = riskClass === 'critical' ? p.critical_rate
    : riskClass === 'high' ? p.high_rate
    : riskClass === 'medium' ? p.medium_rate : p.base_rate
  const rng = deterministicRng || Math.random
  return rng() < rate
}

export function recordSample(params: {
  policy_id: string; agent_id: string; action_id: string;
  risk_class: string; sampled: boolean;
}): AuditSample {
  const s: AuditSample = {
    id: `sample-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    policy_id: params.policy_id, agent_id: params.agent_id,
    action_id: params.action_id, risk_class: params.risk_class,
    sampled: params.sampled,
    audit_result: null, auditor: null,
    created_at: new Date().toISOString(),
  }
  samples.push(s)
  return s
}

export function completeAudit(sampleId: string, auditorId: string, result: string): AuditSample {
  const s = samples.find(x => x.id === sampleId)
  if (!s) throw new Error(`Sample ${sampleId} not found`)
  if (!s.sampled) throw new Error('Cannot audit a non-sampled action')
  s.auditor = auditorId
  s.audit_result = result
  return s
}

export function getSamplingStats(policyId?: string): {
  total: number; sampled: number; audited: number; sample_rate: number;
} {
  const filtered = policyId ? samples.filter(s => s.policy_id === policyId) : samples
  const sampled = filtered.filter(s => s.sampled).length
  const audited = filtered.filter(s => s.audit_result !== null).length
  return {
    total: filtered.length, sampled, audited,
    sample_rate: filtered.length > 0 ? Math.round((sampled / filtered.length) * 1000) / 1000 : 0,
  }
}

export function getPendingAudits(): AuditSample[] {
  return samples.filter(s => s.sampled && s.audit_result === null)
}

export function clearEffectSamplingStores(): void {
  policies.clear(); samples.length = 0; deterministicRng = null
}
