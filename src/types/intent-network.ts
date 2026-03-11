// ══════════════════════════════════════════════════════════════════
// Intent Network — Types
// Agent-mediated matching: needs, offers, discovery, introductions
// ══════════════════════════════════════════════════════════════════

/** A single need or offer with structured metadata */
export interface IntentItem {
  category: string               // e.g. 'engineering', 'design', 'funding', 'partnership'
  description: string            // human-readable
  priority: 'high' | 'medium' | 'low'
  tags: string[]                 // fine-grained: ['rust', 'protocol', 'backend']
  budget?: { amount: number; currency: string }
  visibility: 'public' | 'on-match' | 'on-approval'  // disclosure level
}

/** The core representation object — what an agent carries on behalf of a human */
export interface IntentCard {
  cardId: string
  agentId: string
  principalAlias: string         // human name or alias
  publicKey: string
  needs: IntentItem[]
  offers: IntentItem[]
  openTo: string[]               // broad categories: ['collaboration', 'hiring', 'investment']
  notOpenTo: string[]            // explicit exclusions: ['cold-sales', 'crypto']
  approvalRequired: string[]     // actions needing human sign-off: ['disclose-budget', 'share-contact']
  autonomy: 'discover-only' | 'propose-intros' | 'auto-intro'
  ttlSeconds: number             // card expires, forcing freshness
  createdAt: string
  expiresAt: string
  signature: string
}

/** A match between a need from one card and an offer from another */
export interface NeedOfferMatch {
  needFrom: string               // agentId of the one who needs
  need: IntentItem
  offerFrom: string              // agentId of the one who offers
  offer: IntentItem
  relevanceScore: number         // 0-100
  matchType: 'exact' | 'adjacent' | 'partial'
  explanation: string
}

/** Result of comparing two IntentCards */
export interface RelevanceMatch {
  matchId: string
  cardA: string                  // cardId
  cardB: string                  // cardId
  agentA: string                 // agentId
  agentB: string                 // agentId
  score: number                  // 0-100 aggregate
  needOfferMatches: NeedOfferMatch[]
  mutual: boolean                // both sides have matching needs↔offers
  explanation: string
  matchedAt: string
}

/** Introduction request — one agent proposes connecting two humans */
export interface IntroRequest {
  introId: string
  requestedBy: string            // agentId
  targetAgentId: string
  matchId: string                // which match triggered this
  message: string                // "My human offers Rust backend work matching your need"
  fieldsToDisclose: string[]     // what the requester is willing to share
  status: 'pending' | 'approved' | 'declined' | 'expired'
  createdAt: string
  expiresAt: string
  signature: string
}

/** Response to an introduction request */
export interface IntroResponse {
  introId: string
  respondedBy: string            // agentId
  verdict: 'approve' | 'decline'
  message?: string
  disclosedFields?: Record<string, string>  // fields shared upon approval
  respondedAt: string
  signature: string
}

/** Digest — "what's relevant to me right now" */
export interface Digest {
  digestId: string
  agentId: string
  matches: RelevanceMatch[]
  introsPending: IntroRequest[]  // intros I sent, awaiting response
  introsReceived: IntroRequest[] // intros others sent me
  summary: string                // human-readable: "3 relevant matches, 1 intro pending"
  generatedAt: string
}

/** In-memory network state */
export interface IntentNetwork {
  cards: Map<string, IntentCard>
  matches: Map<string, RelevanceMatch>
  intros: Map<string, IntroRequest>
}

/** Search options */
export interface SearchOptions {
  maxResults?: number
  minScore?: number
  categories?: string[]
  excludeAgents?: string[]
}
