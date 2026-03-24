// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Constitutional Amendment Process (Section 9.11)
 *
 * Hard enough to prevent casual modification. Accessible enough to
 * prevent rigidity. Structural changes require human ratification.
 */

export type AmendmentStatus = 'proposed' | 'deliberation' | 'voting' | 'ratifying' | 'enacted' | 'rejected'

export interface Amendment {
  id: string; title: string; description: string;
  proposed_by: string; affects: string[];
  is_structural: boolean;
  status: AmendmentStatus;
  votes_for: string[]; votes_against: string[];
  required_supermajority: number;
  human_ratification_required: boolean;
  human_ratified: boolean;
  created_at: string;
}

const amendments: Map<string, Amendment> = new Map()

export function proposeAmendment(params: {
  title: string; description: string; proposed_by: string;
  affects: string[]; is_structural: boolean;
  required_supermajority?: number;
}): Amendment {
  const a: Amendment = {
    id: `amendment-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    title: params.title, description: params.description,
    proposed_by: params.proposed_by, affects: params.affects,
    is_structural: params.is_structural,
    status: 'proposed', votes_for: [], votes_against: [],
    required_supermajority: params.required_supermajority ?? 0.67,
    human_ratification_required: params.is_structural,
    human_ratified: false,
    created_at: new Date().toISOString(),
  }
  amendments.set(a.id, a)
  return a
}

export function voteOnAmendment(amendmentId: string, voterId: string, vote: 'for' | 'against'): Amendment {
  const a = amendments.get(amendmentId)
  if (!a) throw new Error(`Amendment ${amendmentId} not found`)
  if (a.votes_for.includes(voterId) || a.votes_against.includes(voterId)) {
    throw new Error(`${voterId} already voted`)
  }
  if (vote === 'for') a.votes_for.push(voterId)
  else a.votes_against.push(voterId)
  a.status = 'voting'
  return a
}

export function checkSupermajority(amendmentId: string): { reached: boolean; forPct: number } {
  const a = amendments.get(amendmentId)
  if (!a) throw new Error(`Amendment ${amendmentId} not found`)
  const total = a.votes_for.length + a.votes_against.length
  if (total === 0) return { reached: false, forPct: 0 }
  const pct = a.votes_for.length / total
  return { reached: pct >= a.required_supermajority, forPct: Math.round(pct * 1000) / 1000 }
}

export function ratifyAmendment(amendmentId: string, humanId: string): Amendment {
  const a = amendments.get(amendmentId)
  if (!a) throw new Error(`Amendment ${amendmentId} not found`)
  const sm = checkSupermajority(amendmentId)
  if (!sm.reached) throw new Error('Supermajority not reached')
  if (a.human_ratification_required && !humanId) throw new Error('Human ratification required')
  if (a.human_ratification_required) a.human_ratified = true
  a.status = 'enacted'
  return a
}

export function requiresHumanRatification(amendmentId: string): boolean {
  const a = amendments.get(amendmentId)
  if (!a) throw new Error(`Amendment ${amendmentId} not found`)
  return a.human_ratification_required
}

export function getAmendmentHistory(): Amendment[] { return [...amendments.values()] }
export function clearAmendmentStores(): void { amendments.clear() }
