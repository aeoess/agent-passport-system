// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Semantic Drift — pure primitives (keyword extraction + drift math).
// ══════════════════════════════════════════════════════════════════════
// The intent-record ledger and aggregate drift queries that used to live
// here have been split out to semantic-drift-tracker.ts in @aeoess/gateway
// (src/sdk-migrated/v2/). This module keeps ONLY the pure primitives:
//
//   extractKeywords       — tokenize + stopword filter
//   computeSemanticDrift  — pure drift analysis over a SemanticIntentRecord
//
// Stateful helpers (recordSemanticIntent, analyzeSemanticDrift (by id),
// getDriftResults, getAgentDriftAverage, isAgentSemanticRisk,
// getSemanticRecord, clearSemanticDriftStores) remain exported as
// deprecation stubs that throw and point callers to the gateway module.
// ══════════════════════════════════════════════════════════════════════

import type { SemanticIntentRecord, SemanticDriftResult } from './types.js'

const MOVED =
  'This function has moved to semantic-drift-tracker in @aeoess/gateway ' +
  '(src/sdk-migrated/v2/semantic-drift-tracker.ts). ' +
  'Pure primitives extractKeywords + computeSemanticDrift stay in the SDK. See MIGRATION.md.'

// ── Stopwords ──

const STOPWORDS = new Set([
  'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
  'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
  'should', 'may', 'might', 'shall', 'can', 'to', 'of', 'in', 'for',
  'on', 'at', 'by', 'with', 'from', 'and', 'or', 'not', 'no', 'but',
  'if', 'then', 'else', 'when', 'up', 'out', 'so', 'than', 'too',
  'very', 'just', 'about', 'into', 'through', 'during', 'before',
  'after', 'above', 'below', 'between', 'under', 'again', 'further',
  'once', 'here', 'there', 'all', 'each', 'every', 'both', 'few',
  'more', 'most', 'other', 'some', 'such', 'only', 'own', 'same',
  'this', 'that', 'these', 'those', 'it', 'its',
])

export function extractKeywords(text: string): string[] {
  return text.toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2 && !STOPWORDS.has(w))
}

// ── Similarity primitives ──

function jaccard(a: string[], b: string[]): number {
  const setA = new Set(a)
  const setB = new Set(b)
  const intersection = [...setA].filter(x => setB.has(x)).length
  const union = new Set([...setA, ...setB]).size
  return union === 0 ? 1 : intersection / union
}

function wordOverlap(text1: string, text2: string): number {
  const words1 = extractKeywords(text1)
  const words2 = extractKeywords(text2)
  if (words1.length === 0 && words2.length === 0) return 1
  if (words1.length === 0 || words2.length === 0) return 0
  const set2 = new Set(words2)
  const overlap = words1.filter(w => set2.has(w)).length
  return overlap / Math.max(words1.length, words2.length)
}

// ── Pure drift analysis over an already-built SemanticIntentRecord ──

export function computeSemanticDrift(record: SemanticIntentRecord): SemanticDriftResult {
  const keywordOverlap = jaccard(record.declared_keywords, record.action_keywords)
  const purposeActionSim = wordOverlap(record.declared_purpose, record.action_description)

  const declaredSet = new Set(record.declared_keywords)
  const mismatched = record.action_keywords.filter(k => !declaredSet.has(k))

  const driftScore = 1 - (keywordOverlap * 0.5 + purposeActionSim * 0.5)

  const verdict: SemanticDriftResult['verdict'] =
    driftScore < 0.3 ? 'aligned' :
    driftScore < 0.6 ? 'drifted' : 'subverted'

  return {
    intent_id: record.intent_id,
    agent_id: record.agent_id,
    keyword_overlap: Math.round(keywordOverlap * 1000) / 1000,
    purpose_action_similarity: Math.round(purposeActionSim * 1000) / 1000,
    drift_score: Math.round(driftScore * 1000) / 1000,
    verdict,
    mismatched_keywords: mismatched,
  }
}

// ══════════════════════════════════════════════════════════════════════
// STATEFUL HELPERS — moved to @aeoess/gateway
// ══════════════════════════════════════════════════════════════════════
// Public signatures preserved so downstream TypeScript compiles. Calls at
// runtime throw a MOVED error pointing to the gateway replacement.

export function recordSemanticIntent(_params: {
  agent_id: string; intent_id: string;
  declared_purpose: string; action_description: string;
  scope_ref: string;
}): SemanticIntentRecord { throw new Error(MOVED) }

export function analyzeSemanticDrift(_recordId: string): SemanticDriftResult {
  throw new Error(MOVED)
}

export function getDriftResults(_agentId?: string): SemanticDriftResult[] {
  throw new Error(MOVED)
}

export function getAgentDriftAverage(_agentId: string): number {
  throw new Error(MOVED)
}

export function isAgentSemanticRisk(_agentId: string, _threshold?: number): boolean {
  throw new Error(MOVED)
}

export function getSemanticRecord(_id: string): SemanticIntentRecord | undefined {
  throw new Error(MOVED)
}

export function clearSemanticDriftStores(): void {
  // No-op: SDK no longer holds state. Gateway owns the store.
}
