// ══════════════════════════════════════════════════════════════════
// Intent Network — Implementation
// Agent-mediated matching: publish intents, discover matches,
// request introductions, get digests
// ══════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  IntentCard, IntentItem, IntentNetwork, NeedOfferMatch,
  RelevanceMatch, IntroRequest, IntroResponse, Digest, SearchOptions
} from '../types/intent-network.js'

// ── Network Lifecycle ──

export function createIntentNetwork(): IntentNetwork {
  return { cards: new Map(), matches: new Map(), intros: new Map() }
}

// ── IntentCard ──

export function createIntentCard(opts: {
  agentId: string
  principalAlias: string
  publicKey: string
  privateKey: string
  needs: IntentItem[]
  offers: IntentItem[]
  openTo?: string[]
  notOpenTo?: string[]
  approvalRequired?: string[]
  autonomy?: IntentCard['autonomy']
  ttlSeconds?: number
}): IntentCard {
  const now = new Date()
  const ttl = opts.ttlSeconds ?? 86400 // 24h default
  const unsigned: Omit<IntentCard, 'signature'> = {
    cardId: `card_${uuidv4().slice(0, 12)}`,
    agentId: opts.agentId,
    principalAlias: opts.principalAlias,
    publicKey: opts.publicKey,
    needs: opts.needs,
    offers: opts.offers,
    openTo: opts.openTo ?? [],
    notOpenTo: opts.notOpenTo ?? [],
    approvalRequired: opts.approvalRequired ?? ['disclose-budget', 'share-contact'],
    autonomy: opts.autonomy ?? 'propose-intros',
    ttlSeconds: ttl,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttl * 1000).toISOString()
  }
  const signature = sign(canonicalize(unsigned), opts.privateKey)
  return { ...unsigned, signature }
}

export function verifyIntentCard(card: IntentCard): boolean {
  const { signature, ...unsigned } = card
  return verify(canonicalize(unsigned), signature, card.publicKey)
}

export function isCardExpired(card: IntentCard): boolean {
  return new Date(card.expiresAt) < new Date()
}

export function publishCard(network: IntentNetwork, card: IntentCard): { published: boolean; error?: string } {
  if (!verifyIntentCard(card)) return { published: false, error: 'Invalid card signature' }
  if (isCardExpired(card)) return { published: false, error: 'Card already expired' }
  if (card.needs.length === 0 && card.offers.length === 0) return { published: false, error: 'Card must have at least one need or offer' }
  network.cards.set(card.cardId, card)
  return { published: true }
}

export function removeCard(network: IntentNetwork, cardId: string): boolean {
  return network.cards.delete(cardId)
}

// ── Matching Engine ──

function computeTagOverlap(tagsA: string[], tagsB: string[]): number {
  const setA = new Set(tagsA.map(t => t.toLowerCase()))
  const setB = new Set(tagsB.map(t => t.toLowerCase()))
  let overlap = 0
  for (const t of setA) { if (setB.has(t)) overlap++ }
  const union = new Set([...setA, ...setB]).size
  return union === 0 ? 0 : (overlap / union) * 100  // Jaccard similarity
}

function categoriesMatch(catA: string, catB: string): boolean {
  const a = catA.toLowerCase(), b = catB.toLowerCase()
  return a === b || a.startsWith(b + ':') || b.startsWith(a + ':')
}

function matchNeedToOffer(need: IntentItem, offer: IntentItem): NeedOfferMatch | null {
  // Category must match
  if (!categoriesMatch(need.category, offer.category)) return null

  const tagScore = computeTagOverlap(need.tags, offer.tags)

  // Budget compatibility: if both specified, offer should be within need budget
  let budgetCompatible = true
  if (need.budget && offer.budget && need.budget.currency === offer.budget.currency) {
    budgetCompatible = offer.budget.amount <= need.budget.amount
  }
  if (!budgetCompatible) return null

  // Determine match type
  let matchType: NeedOfferMatch['matchType']
  if (tagScore >= 50) matchType = 'exact'
  else if (tagScore >= 20) matchType = 'adjacent'
  else if (tagScore > 0) matchType = 'partial'
  else matchType = 'partial'

  // Score: category match = 40pts base, tag overlap scales 0-60
  const score = Math.min(100, 40 + Math.round(tagScore * 0.6))
  if (score < 20) return null  // too weak

  const explanation = `${need.category} need matches ${offer.category} offer (${matchType}, tags: ${Math.round(tagScore)}% overlap)`

  return { needFrom: '', need, offerFrom: '', offer, relevanceScore: score, matchType, explanation }
}

export function computeRelevance(cardA: IntentCard, cardB: IntentCard): RelevanceMatch | null {
  // Check exclusions: if A is notOpenTo something B is in, skip
  for (const tag of cardA.notOpenTo) {
    if (cardB.openTo.some(o => o.toLowerCase() === tag.toLowerCase())) return null
  }
  for (const tag of cardB.notOpenTo) {
    if (cardA.openTo.some(o => o.toLowerCase() === tag.toLowerCase())) return null
  }

  const needOfferMatches: NeedOfferMatch[] = []

  // A's needs vs B's offers
  for (const need of cardA.needs) {
    for (const offer of cardB.offers) {
      const m = matchNeedToOffer(need, offer)
      if (m) {
        m.needFrom = cardA.agentId
        m.offerFrom = cardB.agentId
        needOfferMatches.push(m)
      }
    }
  }

  // B's needs vs A's offers (mutual check)
  for (const need of cardB.needs) {
    for (const offer of cardA.offers) {
      const m = matchNeedToOffer(need, offer)
      if (m) {
        m.needFrom = cardB.agentId
        m.offerFrom = cardA.agentId
        needOfferMatches.push(m)
      }
    }
  }

  if (needOfferMatches.length === 0) return null

  // Aggregate score: best match dominates, mutual gets a bonus
  const scores = needOfferMatches.map(m => m.relevanceScore)
  const maxScore = Math.max(...scores)
  const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length
  const aNeedsMatched = needOfferMatches.some(m => m.needFrom === cardA.agentId)
  const bNeedsMatched = needOfferMatches.some(m => m.needFrom === cardB.agentId)
  const mutual = aNeedsMatched && bNeedsMatched
  const mutualBonus = mutual ? 15 : 0

  const score = Math.min(100, Math.round(maxScore * 0.6 + avgScore * 0.4 + mutualBonus))

  const explanationParts = needOfferMatches.map(m => m.explanation)
  if (mutual) explanationParts.push('Mutual match: both sides have needs that match the other\'s offers')

  return {
    matchId: `match_${uuidv4().slice(0, 12)}`,
    cardA: cardA.cardId, cardB: cardB.cardId,
    agentA: cardA.agentId, agentB: cardB.agentId,
    score, needOfferMatches, mutual,
    explanation: explanationParts.join('. '),
    matchedAt: new Date().toISOString()
  }
}

export function searchMatches(network: IntentNetwork, agentId: string, opts?: SearchOptions): RelevanceMatch[] {
  const myCard = Array.from(network.cards.values()).find(c => c.agentId === agentId)
  if (!myCard) return []

  const maxResults = opts?.maxResults ?? 10
  const minScore = opts?.minScore ?? 30
  const excludeAgents = new Set(opts?.excludeAgents ?? [])
  excludeAgents.add(agentId) // never match yourself

  const matches: RelevanceMatch[] = []

  for (const [, card] of network.cards) {
    if (card.agentId === agentId) continue
    if (excludeAgents.has(card.agentId)) continue
    if (isCardExpired(card)) continue
    if (opts?.categories?.length) {
      const hasCategory = card.offers.some(o => opts.categories!.some(c => categoriesMatch(c, o.category)))
        || card.needs.some(n => opts.categories!.some(c => categoriesMatch(c, n.category)))
      if (!hasCategory) continue
    }
    const match = computeRelevance(myCard, card)
    if (match && match.score >= minScore) {
      matches.push(match)
      network.matches.set(match.matchId, match)
    }
  }

  matches.sort((a, b) => b.score - a.score)
  return matches.slice(0, maxResults)
}

// ── Introduction Protocol ──

export function requestIntro(network: IntentNetwork, opts: {
  requestedBy: string
  targetAgentId: string
  matchId: string
  message: string
  fieldsToDisclose?: string[]
  privateKey: string
  ttlSeconds?: number
}): IntroRequest | { error: string } {
  const match = network.matches.get(opts.matchId)
  if (!match) return { error: 'Match not found' }

  const targetCard = Array.from(network.cards.values()).find(c => c.agentId === opts.targetAgentId)
  if (!targetCard) return { error: 'Target agent not found in network' }

  // Check if target's autonomy allows receiving intros
  // (discover-only means they can't even receive intro proposals)

  const now = new Date()
  const ttl = opts.ttlSeconds ?? 3600 // 1h default
  const unsigned: Omit<IntroRequest, 'signature'> = {
    introId: `intro_${uuidv4().slice(0, 12)}`,
    requestedBy: opts.requestedBy,
    targetAgentId: opts.targetAgentId,
    matchId: opts.matchId,
    message: opts.message,
    fieldsToDisclose: opts.fieldsToDisclose ?? [],
    status: 'pending',
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttl * 1000).toISOString()
  }
  const signature = sign(canonicalize(unsigned), opts.privateKey)
  const intro: IntroRequest = { ...unsigned, signature }
  network.intros.set(intro.introId, intro)
  return intro
}

export function respondToIntro(network: IntentNetwork, opts: {
  introId: string
  respondedBy: string
  verdict: 'approve' | 'decline'
  message?: string
  disclosedFields?: Record<string, string>
  privateKey: string
}): IntroResponse | { error: string } {
  const intro = network.intros.get(opts.introId)
  if (!intro) return { error: 'Intro not found' }
  if (intro.status !== 'pending') return { error: `Intro already ${intro.status}` }
  if (intro.targetAgentId !== opts.respondedBy) return { error: 'Only the target agent can respond' }
  if (new Date(intro.expiresAt) < new Date()) {
    intro.status = 'expired'
    return { error: 'Intro expired' }
  }

  intro.status = opts.verdict === 'approve' ? 'approved' : 'declined'

  const unsigned: Omit<IntroResponse, 'signature'> = {
    introId: opts.introId,
    respondedBy: opts.respondedBy,
    verdict: opts.verdict,
    message: opts.message,
    disclosedFields: opts.verdict === 'approve' ? opts.disclosedFields : undefined,
    respondedAt: new Date().toISOString()
  }
  const signature = sign(canonicalize(unsigned), opts.privateKey)
  return { ...unsigned, signature }
}

// ── Digest: "What's relevant to me right now?" ──

export function getDigest(network: IntentNetwork, agentId: string): Digest {
  // Find or compute matches for this agent
  const allMatches = Array.from(network.matches.values())
    .filter(m => (m.agentA === agentId || m.agentB === agentId))
    .sort((a, b) => b.score - a.score)
    .slice(0, 10)

  const introsPending = Array.from(network.intros.values())
    .filter(i => i.requestedBy === agentId && i.status === 'pending')

  const introsReceived = Array.from(network.intros.values())
    .filter(i => i.targetAgentId === agentId && i.status === 'pending')

  const mutualCount = allMatches.filter(m => m.mutual).length
  const parts: string[] = []
  if (allMatches.length > 0) parts.push(`${allMatches.length} relevant match${allMatches.length > 1 ? 'es' : ''}`)
  if (mutualCount > 0) parts.push(`${mutualCount} mutual`)
  if (introsPending.length > 0) parts.push(`${introsPending.length} intro${introsPending.length > 1 ? 's' : ''} awaiting response`)
  if (introsReceived.length > 0) parts.push(`${introsReceived.length} intro${introsReceived.length > 1 ? 's' : ''} for you to review`)
  const summary = parts.length > 0 ? parts.join(', ') : 'No activity right now'

  return {
    digestId: `digest_${uuidv4().slice(0, 12)}`,
    agentId,
    matches: allMatches,
    introsPending,
    introsReceived,
    summary,
    generatedAt: new Date().toISOString()
  }
}

// ── Visibility Filter ──

/** Filter an IntentCard's items based on visibility rules */
export function getVisibleItems(card: IntentCard, context: 'public' | 'matched' | 'approved'): {
  needs: IntentItem[]; offers: IntentItem[]
} {
  const filter = (items: IntentItem[]) => items.filter(item => {
    if (item.visibility === 'public') return true
    if (item.visibility === 'on-match' && (context === 'matched' || context === 'approved')) return true
    if (item.visibility === 'on-approval' && context === 'approved') return true
    return false
  })
  return { needs: filter(card.needs), offers: filter(card.offers) }
}
