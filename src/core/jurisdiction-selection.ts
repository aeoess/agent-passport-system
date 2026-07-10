// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Jurisdiction Selection Provenance
// ══════════════════════════════════════════════════════════════════
// Given jurisdiction facts and opaque policy pack references, record
// which packs apply and where they disagree. Disagreements are
// surfaced, never auto-resolved; explicit operator precedence is the
// only resolution path, and its use is recorded.
// ══════════════════════════════════════════════════════════════════

import type {
  JurisdictionFacts, PolicyPackRef, PackConflict,
  SelectionOptions, SelectionRecord,
} from '../types/jurisdiction-selection.js'

/** Resolver version stamped into every SelectionRecord */
export const RESOLVER_VERSION = '0.1.0' as const

/** Count how many fact dimensions a pack's jurisdiction matches */
function matchCount(pack: PolicyPackRef, facts: JurisdictionFacts): number {
  const dims = [
    facts.principal_jurisdiction,
    facts.execution_jurisdiction,
    facts.resource_jurisdiction,
    ...(facts.subject_jurisdiction ? [facts.subject_jurisdiction] : []),
  ]
  return dims.filter(d => d === pack.jurisdiction).length
}

/** Stable pack label used in conflict records */
function packLabel(pack: PolicyPackRef): string {
  return `${pack.id}@${pack.version}`
}

/**
 * Select the policy packs applicable to a set of jurisdiction facts
 * and produce a provenance record of that selection.
 *
 * Invariants:
 * - Pure and deterministic given the same inputs; the only impure
 *   default is selected_at, which callers should pin via
 *   opts.selected_at for reproducible records.
 * - A pack is selected when its jurisdiction matches ANY fact
 *   dimension. selected_packs is ordered by match count descending,
 *   then id, then version.
 * - When two selected packs declare different values for the same
 *   constraints key, a PackConflict is emitted and resolution becomes
 *   'conflict-surfaced'. There is no automatic resolution.
 * - opts.precedence resolves a key only when every pack declaring
 *   that key is listed in it; the record then carries precedence_used
 *   so the override is auditable.
 */
export function selectJurisdictionPacks(
  facts: JurisdictionFacts,
  packs: PolicyPackRef[],
  opts?: SelectionOptions
): SelectionRecord {
  const selected = packs
    .filter(p => matchCount(p, facts) > 0)
    .sort((a, b) => {
      const byCount = matchCount(b, facts) - matchCount(a, facts)
      if (byCount !== 0) return byCount
      if (a.id !== b.id) return a.id < b.id ? -1 : 1
      if (a.version !== b.version) return a.version < b.version ? -1 : 1
      return 0
    })

  // Gather declared values per constraints key, in selected order.
  const byKey = new Map<string, { pack: PolicyPackRef; value: string }[]>()
  for (const pack of selected) {
    for (const key of Object.keys(pack.constraints ?? {}).sort()) {
      const value = (pack.constraints as Record<string, string>)[key]
      const list = byKey.get(key) ?? []
      list.push({ pack, value })
      byKey.set(key, list)
    }
  }

  const precedence = opts?.precedence ?? []
  const conflicts: PackConflict[] = []
  for (const key of [...byKey.keys()].sort()) {
    const declared = byKey.get(key) as { pack: PolicyPackRef; value: string }[]
    const distinct = new Set(declared.map(d => d.value))
    if (distinct.size <= 1) continue
    const resolvedByPrecedence =
      precedence.length > 0 &&
      declared.every(d => precedence.includes(d.pack.id))
    if (resolvedByPrecedence) continue
    conflicts.push({
      dimension: key,
      packs: declared.map(d => packLabel(d.pack)),
      values: declared.map(d => d.value),
      note: `selected packs declare different values for "${key}"; surfaced, not auto-resolved`,
    })
  }

  return {
    facts,
    selected_packs: selected,
    conflicts,
    resolution: conflicts.length > 0 ? 'conflict-surfaced' : 'selected',
    resolver_version: RESOLVER_VERSION,
    ...(opts?.precedence ? { precedence_used: [...opts.precedence] } : {}),
    selected_at: opts?.selected_at ?? new Date().toISOString(),
  }
}
