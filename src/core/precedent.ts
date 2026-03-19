// Precedent Control — Module 25 (Gap 6)
// Prevents precedent drift by curating normative precedents.
// New evaluations must align with normative precedents or explicitly distinguish.
// F-001–F-005: deterministic enforcement (FloorValidatorV1, never LLM)
// F-006, F-007: advisory layer with precedent library and structured verdicts.

import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type { Precedent } from '../types/intent.js'

// ══════════════════════════════════════
// TYPES
// ══════════════════════════════════════

export interface NormativePrecedent extends Precedent {
  status: 'normative' | 'informational' | 'superseded'
  approvedBy: string
  approvedAt: string
  approvalSignature: string
  category: string
  supersededBy?: string
  distinguishingNote?: string
}

export interface PrecedentAlignment {
  aligned: boolean
  closestPrecedent: NormativePrecedent | null
  similarityScore: number       // 0 = no match, 1 = perfect match
  requiresDistinguishing: boolean
  reason: string
}

export interface PrecedentLibrary {
  precedents: NormativePrecedent[]
  categories: string[]
  createdAt: string
  lastUpdatedAt: string
}

export interface DriftAnalysis {
  driftDetected: boolean
  driftScore: number            // 0 = no drift, 1 = complete drift
  evaluationCount: number
  alignedCount: number
  divergentCount: number
  divergentIds: string[]
}

// ══════════════════════════════════════
// CREATE LIBRARY
// ══════════════════════════════════════

export function createPrecedentLibrary(): PrecedentLibrary {
  const now = new Date().toISOString()
  return { precedents: [], categories: [], createdAt: now, lastUpdatedAt: now }
}

// ══════════════════════════════════════
// MARK AS NORMATIVE
// ══════════════════════════════════════

export function markAsNormative(opts: {
  precedent: Precedent
  approverPrivateKey: string
  approverPublicKey: string
  category: string
}): NormativePrecedent {
  const { precedent, approverPrivateKey, approverPublicKey, category } = opts
  const now = new Date().toISOString()

  const signable = canonicalize({
    precedentId: precedent.precedentId,
    subject: precedent.subject,
    decision: precedent.decision,
    category,
    approvedBy: approverPublicKey,
    approvedAt: now,
  })
  const approvalSignature = sign(signable, approverPrivateKey)

  return {
    ...precedent,
    status: 'normative',
    approvedBy: approverPublicKey,
    approvedAt: now,
    approvalSignature,
    category,
  }
}

// ══════════════════════════════════════
// VERIFY NORMATIVE PRECEDENT
// ══════════════════════════════════════

export function verifyNormativePrecedent(precedent: NormativePrecedent): boolean {
  try {
    const signable = canonicalize({
      precedentId: precedent.precedentId,
      subject: precedent.subject,
      decision: precedent.decision,
      category: precedent.category,
      approvedBy: precedent.approvedBy,
      approvedAt: precedent.approvedAt,
    })
    return verify(signable, precedent.approvalSignature, precedent.approvedBy)
  } catch { return false }
}

// ══════════════════════════════════════
// ADD TO LIBRARY
// ══════════════════════════════════════

export function addToLibrary(library: PrecedentLibrary, precedent: NormativePrecedent): PrecedentLibrary {
  if (!library.categories.includes(precedent.category)) {
    library.categories = [...library.categories, precedent.category]
  }
  return {
    ...library,
    precedents: [...library.precedents, precedent],
    categories: library.categories,
    lastUpdatedAt: new Date().toISOString(),
  }
}

// ══════════════════════════════════════
// CHECK ALIGNMENT
// ══════════════════════════════════════
// Simple word-overlap similarity for subject+context matching.
// Production would use embeddings; this is the structural contract.

function tokenize(text: string): Set<string> {
  return new Set(text.toLowerCase().split(/\W+/).filter(w => w.length > 2))
}

function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0
  const intersection = new Set([...a].filter(x => b.has(x)))
  const union = new Set([...a, ...b])
  return intersection.size / union.size
}

export function checkAlignment(
  library: PrecedentLibrary,
  decision: { subject: string; context: string; outcome: string },
  category?: string
): PrecedentAlignment {
  const candidates = category
    ? library.precedents.filter(p => p.status === 'normative' && p.category === category)
    : library.precedents.filter(p => p.status === 'normative')

  if (candidates.length === 0) {
    return { aligned: true, closestPrecedent: null, similarityScore: 0, requiresDistinguishing: false, reason: 'No normative precedents in library' }
  }

  const decisionTokens = tokenize(`${decision.subject} ${decision.context}`)
  let bestMatch: NormativePrecedent | null = null
  let bestScore = 0

  for (const p of candidates) {
    const pTokens = tokenize(`${p.subject} ${p.context}`)
    const score = jaccardSimilarity(decisionTokens, pTokens)
    if (score > bestScore) { bestScore = score; bestMatch = p }
  }

  // Threshold: >0.3 similarity means similar enough to warrant comparison
  const SIMILARITY_THRESHOLD = 0.3
  if (bestScore < SIMILARITY_THRESHOLD || !bestMatch) {
    return { aligned: true, closestPrecedent: bestMatch, similarityScore: bestScore, requiresDistinguishing: false, reason: 'No sufficiently similar precedent found' }
  }

  // Same outcome = aligned; different outcome = requires distinguishing
  const outcomeMatch = decision.outcome.toLowerCase().includes(bestMatch.decision.toLowerCase())
    || bestMatch.decision.toLowerCase().includes(decision.outcome.toLowerCase())

  return {
    aligned: outcomeMatch,
    closestPrecedent: bestMatch,
    similarityScore: bestScore,
    requiresDistinguishing: !outcomeMatch,
    reason: outcomeMatch
      ? `Aligned with precedent ${bestMatch.precedentId}: similar situation, consistent outcome`
      : `Diverges from precedent ${bestMatch.precedentId}: similar situation (${(bestScore * 100).toFixed(0)}% match), different outcome. Must distinguish.`,
  }
}

// ══════════════════════════════════════
// SUPERSEDE PRECEDENT
// ══════════════════════════════════════

export function supersedePrecedent(opts: {
  library: PrecedentLibrary
  oldPrecedentId: string
  newPrecedent: NormativePrecedent
  distinguishingNote: string
}): PrecedentLibrary {
  const { library, oldPrecedentId, newPrecedent, distinguishingNote } = opts
  const updated = library.precedents.map(p => {
    if (p.precedentId === oldPrecedentId && p.status === 'normative') {
      return { ...p, status: 'superseded' as const, supersededBy: newPrecedent.precedentId, distinguishingNote }
    }
    return p
  })
  return {
    ...library,
    precedents: [...updated, newPrecedent],
    lastUpdatedAt: new Date().toISOString(),
  }
}

// ══════════════════════════════════════
// ANALYZE DRIFT
// ══════════════════════════════════════

export function analyzeDrift(
  library: PrecedentLibrary,
  recentDecisions: Array<{ subject: string; context: string; outcome: string; id: string }>,
  category?: string
): DriftAnalysis {
  let alignedCount = 0
  let divergentCount = 0
  const divergentIds: string[] = []

  for (const decision of recentDecisions) {
    const alignment = checkAlignment(library, decision, category)
    if (alignment.closestPrecedent === null) continue // no precedent to compare against
    if (alignment.aligned) { alignedCount++ }
    else { divergentCount++; divergentIds.push(decision.id) }
  }

  const total = alignedCount + divergentCount
  const driftScore = total === 0 ? 0 : divergentCount / total

  return {
    driftDetected: driftScore > 0.2, // >20% divergence = drift detected
    driftScore,
    evaluationCount: recentDecisions.length,
    alignedCount,
    divergentCount,
    divergentIds,
  }
}
