// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Semantic Drift Detection (Intent Subversion)
 *
 * An agent can be technically within its delegation scope but semantically
 * doing something completely different from what it declared. Scope says
 * "customer:*", intent says "notify customer", action is "delete customer data."
 *
 * This module compares declared intent semantics against actual action
 * semantics using keyword extraction and overlap analysis. Not ML — 
 * structural text comparison that catches obvious mismatches.
 */

import type {
  SemanticIntentRecord, SemanticDriftResult,
} from './types.js'

// ── Stores ──
const intentRecords: Map<string, SemanticIntentRecord> = new Map()
const driftResults: SemanticDriftResult[] = []

// ── Keyword Extraction ──
// Simple but effective: lowercase, split on non-alpha, filter stopwords

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

// ── Jaccard Similarity ──

function jaccard(a: string[], b: string[]): number {
  const setA = new Set(a)
  const setB = new Set(b)
  const intersection = [...setA].filter(x => setB.has(x)).length
  const union = new Set([...setA, ...setB]).size
  return union === 0 ? 1 : intersection / union
}

// ── Word Overlap (looser than Jaccard) ──

function wordOverlap(text1: string, text2: string): number {
  const words1 = extractKeywords(text1)
  const words2 = extractKeywords(text2)
  if (words1.length === 0 && words2.length === 0) return 1
  if (words1.length === 0 || words2.length === 0) return 0
  const set2 = new Set(words2)
  const overlap = words1.filter(w => set2.has(w)).length
  return overlap / Math.max(words1.length, words2.length)
}

// ── Record & Analyze ──

export function recordSemanticIntent(params: {
  agent_id: string; intent_id: string;
  declared_purpose: string; action_description: string;
  scope_ref: string;
}): SemanticIntentRecord {
  const declared_keywords = extractKeywords(params.declared_purpose)
  const action_keywords = extractKeywords(params.action_description)
  const record: SemanticIntentRecord = {
    id: `sem-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    agent_id: params.agent_id,
    intent_id: params.intent_id,
    declared_purpose: params.declared_purpose,
    declared_keywords,
    action_description: params.action_description,
    action_keywords,
    scope_ref: params.scope_ref,
    timestamp: new Date().toISOString(),
  }
  intentRecords.set(record.id, record)
  return record
}

export function analyzeSemanticDrift(recordId: string): SemanticDriftResult {
  const record = intentRecords.get(recordId)
  if (!record) throw new Error(`Record ${recordId} not found`)

  const keywordOverlap = jaccard(record.declared_keywords, record.action_keywords)
  const purposeActionSim = wordOverlap(record.declared_purpose, record.action_description)

  // Mismatched: action keywords not in declared intent
  const declaredSet = new Set(record.declared_keywords)
  const mismatched = record.action_keywords.filter(k => !declaredSet.has(k))

  // Composite drift score: low overlap = high drift
  const driftScore = 1 - (keywordOverlap * 0.5 + purposeActionSim * 0.5)

  const verdict: SemanticDriftResult['verdict'] =
    driftScore < 0.3 ? 'aligned' :
    driftScore < 0.6 ? 'drifted' : 'subverted'

  const result: SemanticDriftResult = {
    intent_id: record.intent_id,
    agent_id: record.agent_id,
    keyword_overlap: Math.round(keywordOverlap * 1000) / 1000,
    purpose_action_similarity: Math.round(purposeActionSim * 1000) / 1000,
    drift_score: Math.round(driftScore * 1000) / 1000,
    verdict,
    mismatched_keywords: mismatched,
  }
  driftResults.push(result)
  return result
}

export function getDriftResults(agentId?: string): SemanticDriftResult[] {
  if (agentId) return driftResults.filter(r => r.agent_id === agentId)
  return [...driftResults]
}

export function getAgentDriftAverage(agentId: string): number {
  const results = getDriftResults(agentId)
  if (results.length === 0) return 0
  return results.reduce((s, r) => s + r.drift_score, 0) / results.length
}

export function isAgentSemanticRisk(agentId: string, threshold?: number): boolean {
  return getAgentDriftAverage(agentId) > (threshold || 0.5)
}

export function getSemanticRecord(id: string): SemanticIntentRecord | undefined {
  return intentRecords.get(id)
}

export function clearSemanticDriftStores(): void {
  intentRecords.clear()
  driftResults.length = 0
}
