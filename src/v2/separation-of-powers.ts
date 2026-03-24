// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Separation of Powers (Section 9.1)
 *
 * No entity holds roles in multiple branches simultaneously.
 * Legislative defines rules, Executive acts, Judicial interprets.
 */

export type GovernanceBranch = 'legislative' | 'executive' | 'judicial'

export interface BranchAssignment {
  agent_id: string; branch: GovernanceBranch;
  assigned_at: string; assigned_by: string;
}

export interface PowerConflict {
  agent_id: string; branches: GovernanceBranch[];
  description: string; detected_at: string;
}

const assignments: BranchAssignment[] = []
const conflicts: PowerConflict[] = []

export function assignBranch(agentId: string, branch: GovernanceBranch, assignedBy: string): BranchAssignment {
  const a: BranchAssignment = {
    agent_id: agentId, branch, assigned_at: new Date().toISOString(), assigned_by: assignedBy,
  }
  assignments.push(a)
  return a
}

export function getAgentBranches(agentId: string): GovernanceBranch[] {
  return [...new Set(assignments.filter(a => a.agent_id === agentId).map(a => a.branch))]
}

export function checkSeparation(agentId: string): { separated: boolean; conflicts: PowerConflict[] } {
  const branches = getAgentBranches(agentId)
  if (branches.length <= 1) return { separated: true, conflicts: [] }
  const c: PowerConflict = {
    agent_id: agentId, branches,
    description: `Agent holds roles in ${branches.join(' + ')} — separation violated`,
    detected_at: new Date().toISOString(),
  }
  conflicts.push(c)
  return { separated: false, conflicts: [c] }
}

export function preventBranchConflict(agentId: string, proposedBranch: GovernanceBranch): {
  allowed: boolean; reason?: string
} {
  const existing = getAgentBranches(agentId)
  if (existing.length > 0 && !existing.includes(proposedBranch)) {
    return {
      allowed: false,
      reason: `Agent already in ${existing.join(', ')} — cannot also hold ${proposedBranch}`,
    }
  }
  return { allowed: true }
}

export function getBranchMembers(branch: GovernanceBranch): string[] {
  return [...new Set(assignments.filter(a => a.branch === branch).map(a => a.agent_id))]
}

export function clearSeparationOfPowersStores(): void { assignments.length = 0; conflicts.length = 0 }
