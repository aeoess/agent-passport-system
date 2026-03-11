// ══════════════════════════════════════════════════════════════════
// Intent Network — Tests
// ══════════════════════════════════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createIntentNetwork, createIntentCard, verifyIntentCard, isCardExpired,
  publishCard, removeCard, computeRelevance, searchMatches,
  requestIntro, respondToIntro, getDigest, getVisibleItems
} from '../src/core/intent-network.js'
import type { IntentNetwork, IntentItem } from '../src/types/intent-network.js'

// ── Helpers ──

function makeItem(overrides: Partial<IntentItem> = {}): IntentItem {
  return {
    category: overrides.category ?? 'engineering',
    description: overrides.description ?? 'Test item',
    priority: overrides.priority ?? 'medium',
    tags: overrides.tags ?? ['typescript', 'protocol'],
    budget: overrides.budget,
    visibility: overrides.visibility ?? 'public'
  }
}

let net: IntentNetwork
const keysA = generateKeyPair()
const keysB = generateKeyPair()
const keysC = generateKeyPair()

function makeCard(keys: { publicKey: string; privateKey: string }, opts: {
  agentId: string, alias: string,
  needs?: IntentItem[], offers?: IntentItem[],
  openTo?: string[], notOpenTo?: string[], ttlSeconds?: number
}) {
  return createIntentCard({
    agentId: opts.agentId, principalAlias: opts.alias,
    publicKey: keys.publicKey, privateKey: keys.privateKey,
    needs: opts.needs ?? [], offers: opts.offers ?? [],
    openTo: opts.openTo, notOpenTo: opts.notOpenTo,
    ttlSeconds: opts.ttlSeconds ?? 86400
  })
}

// ══════════════════════════════════════════════════════════════════
// TEST SUITES
// ══════════════════════════════════════════════════════════════════

describe('IntentCard — Creation & Verification', () => {
  beforeEach(() => { net = createIntentNetwork() })

  it('creates a signed intent card', () => {
    const card = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust', 'backend'] })],
      offers: [makeItem({ category: 'design', tags: ['ui', 'figma'] })]
    })
    assert.ok(card.cardId.startsWith('card_'))
    assert.equal(card.agentId, 'agent-a')
    assert.equal(card.needs.length, 1)
    assert.equal(card.offers.length, 1)
    assert.ok(card.signature)
    assert.ok(verifyIntentCard(card))
  })

  it('rejects tampered card', () => {
    const card = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem()], offers: [makeItem()]
    })
    card.principalAlias = 'Mallory'
    assert.equal(verifyIntentCard(card), false)
  })

  it('detects expired card', () => {
    const card = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem()], offers: [makeItem()], ttlSeconds: 1
    })
    // Manually set expiresAt to the past
    ;(card as any).expiresAt = new Date(Date.now() - 1000).toISOString()
    assert.ok(isCardExpired(card))
  })

  it('publishes valid card to network', () => {
    const card = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem()], offers: [makeItem()]
    })
    const result = publishCard(net, card)
    assert.equal(result.published, true)
    assert.equal(net.cards.size, 1)
  })

  it('rejects card with no needs or offers', () => {
    const card = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice' })
    const result = publishCard(net, card)
    assert.equal(result.published, false)
    assert.match(result.error!, /at least one/)
  })

  it('removes card from network', () => {
    const card = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem()], offers: [makeItem()]
    })
    publishCard(net, card)
    assert.equal(removeCard(net, card.cardId), true)
    assert.equal(net.cards.size, 0)
  })
})

describe('Matching Engine — Relevance Scoring', () => {
  beforeEach(() => { net = createIntentNetwork() })

  it('finds exact match when tags overlap strongly', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust', 'backend', 'protocol'] })],
      offers: []
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [],
      offers: [makeItem({ category: 'engineering', tags: ['rust', 'backend', 'systems'] })]
    })
    const match = computeRelevance(cardA, cardB)
    assert.ok(match)
    assert.ok(match.score > 50)
    assert.equal(match.needOfferMatches.length, 1)
    assert.equal(match.needOfferMatches[0].matchType, 'exact')
  })

  it('finds mutual match and gives bonus', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'design', tags: ['ui', 'figma'] })],
      offers: [makeItem({ category: 'engineering', tags: ['typescript', 'node'] })]
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [makeItem({ category: 'engineering', tags: ['typescript', 'react'] })],
      offers: [makeItem({ category: 'design', tags: ['ui', 'css', 'figma'] })]
    })
    const match = computeRelevance(cardA, cardB)
    assert.ok(match)
    assert.equal(match.mutual, true)
    assert.ok(match.score > 60) // mutual bonus
  })

  it('returns null when categories dont match', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust'] })],
      offers: []
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [],
      offers: [makeItem({ category: 'marketing', tags: ['seo'] })]
    })
    const match = computeRelevance(cardA, cardB)
    assert.equal(match, null)
  })

  it('respects notOpenTo exclusions', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['python'] })],
      offers: [], notOpenTo: ['crypto']
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [],
      offers: [makeItem({ category: 'engineering', tags: ['python', 'django'] })],
      openTo: ['crypto']
    })
    const match = computeRelevance(cardA, cardB)
    assert.equal(match, null)
  })

  it('respects budget compatibility', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust'], budget: { amount: 100, currency: 'USD' } })],
      offers: []
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [],
      offers: [makeItem({ category: 'engineering', tags: ['rust'], budget: { amount: 200, currency: 'USD' } })]
    })
    // offer costs more than need budget → no match
    const match = computeRelevance(cardA, cardB)
    assert.equal(match, null)
  })
})

describe('Search & Discovery', () => {
  beforeEach(() => { net = createIntentNetwork() })

  it('searches network and returns ranked matches', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust', 'backend'] })],
      offers: [makeItem({ category: 'consulting', tags: ['strategy'] })]
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [], offers: [makeItem({ category: 'engineering', tags: ['rust', 'systems'] })]
    })
    const cardC = makeCard(keysC, { agentId: 'agent-c', alias: 'Carol',
      needs: [], offers: [makeItem({ category: 'engineering', tags: ['python', 'ml'] })]
    })
    publishCard(net, cardA)
    publishCard(net, cardB)
    publishCard(net, cardC)

    const matches = searchMatches(net, 'agent-a')
    assert.ok(matches.length >= 1)
    // Bob should rank higher (rust overlap)
    assert.equal(matches[0].agentB, 'agent-b')
  })

  it('never matches yourself', () => {
    const card = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem()], offers: [makeItem()]
    })
    publishCard(net, card)
    const matches = searchMatches(net, 'agent-a')
    assert.equal(matches.length, 0)
  })

  it('filters by category', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust'] }),
              makeItem({ category: 'design', tags: ['ui'] })],
      offers: []
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [], offers: [makeItem({ category: 'design', tags: ['ui', 'figma'] })]
    })
    publishCard(net, cardA)
    publishCard(net, cardB)

    const matches = searchMatches(net, 'agent-a', { categories: ['design'] })
    assert.ok(matches.length >= 1)
  })

  it('respects minScore', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust', 'backend', 'protocol'] })],
      offers: []
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [], offers: [makeItem({ category: 'engineering', tags: ['java'] })]
    })
    publishCard(net, cardA)
    publishCard(net, cardB)

    const strict = searchMatches(net, 'agent-a', { minScore: 80 })
    assert.equal(strict.length, 0) // too weak
  })
})

describe('Introduction Protocol', () => {
  beforeEach(() => { net = createIntentNetwork() })

  it('creates and responds to an intro request', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust', 'backend'] })], offers: []
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [], offers: [makeItem({ category: 'engineering', tags: ['rust', 'systems'] })]
    })
    publishCard(net, cardA)
    publishCard(net, cardB)

    const matches = searchMatches(net, 'agent-a')
    assert.ok(matches.length >= 1)

    const intro = requestIntro(net, {
      requestedBy: 'agent-a', targetAgentId: 'agent-b',
      matchId: matches[0].matchId,
      message: 'My human needs a Rust backend engineer — your human offers that',
      fieldsToDisclose: ['description', 'budget'],
      privateKey: keysA.privateKey
    })
    assert.ok(!('error' in intro))
    assert.equal((intro as any).status, 'pending')

    const response = respondToIntro(net, {
      introId: (intro as any).introId,
      respondedBy: 'agent-b', verdict: 'approve',
      message: 'Interested, here are my details',
      disclosedFields: { email: 'bob@example.com', rate: '$150/hr' },
      privateKey: keysB.privateKey
    })
    assert.ok(!('error' in response))
    assert.equal((response as any).verdict, 'approve')
    assert.ok((response as any).disclosedFields?.email)
  })

  it('rejects intro for nonexistent match', () => {
    const result = requestIntro(net, {
      requestedBy: 'agent-a', targetAgentId: 'agent-b',
      matchId: 'fake-match', message: 'test', privateKey: keysA.privateKey
    })
    assert.ok('error' in result)
    assert.match((result as any).error, /not found/)
  })

  it('only target agent can respond', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust'] })], offers: []
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [], offers: [makeItem({ category: 'engineering', tags: ['rust'] })]
    })
    publishCard(net, cardA)
    publishCard(net, cardB)

    const matches = searchMatches(net, 'agent-a')
    const intro = requestIntro(net, {
      requestedBy: 'agent-a', targetAgentId: 'agent-b',
      matchId: matches[0].matchId, message: 'test', privateKey: keysA.privateKey
    }) as any

    // agent-a tries to respond to their own intro (impersonation)
    const response = respondToIntro(net, {
      introId: intro.introId, respondedBy: 'agent-a',
      verdict: 'approve', privateKey: keysA.privateKey
    })
    assert.ok('error' in response)
    assert.match((response as any).error, /[Oo]nly the target/)
  })

  it('cannot respond to already-handled intro', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust'] })], offers: []
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [], offers: [makeItem({ category: 'engineering', tags: ['rust'] })]
    })
    publishCard(net, cardA)
    publishCard(net, cardB)
    const matches = searchMatches(net, 'agent-a')
    const intro = requestIntro(net, {
      requestedBy: 'agent-a', targetAgentId: 'agent-b',
      matchId: matches[0].matchId, message: 'test', privateKey: keysA.privateKey
    }) as any

    respondToIntro(net, { introId: intro.introId, respondedBy: 'agent-b', verdict: 'decline', privateKey: keysB.privateKey })
    const second = respondToIntro(net, { introId: intro.introId, respondedBy: 'agent-b', verdict: 'approve', privateKey: keysB.privateKey })
    assert.ok('error' in second)
  })
})

describe('Digest — What is relevant to me right now', () => {
  beforeEach(() => { net = createIntentNetwork() })

  it('produces a useful digest with matches and intros', () => {
    const cardA = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'engineering', tags: ['rust', 'backend'] })],
      offers: [makeItem({ category: 'consulting', tags: ['strategy', 'product'] })]
    })
    const cardB = makeCard(keysB, { agentId: 'agent-b', alias: 'Bob',
      needs: [makeItem({ category: 'consulting', tags: ['strategy', 'growth'] })],
      offers: [makeItem({ category: 'engineering', tags: ['rust', 'systems'] })]
    })
    publishCard(net, cardA)
    publishCard(net, cardB)

    searchMatches(net, 'agent-a')
    const digest = getDigest(net, 'agent-a')
    assert.ok(digest.matches.length >= 1)
    assert.ok(digest.summary.includes('match'))
    assert.ok(digest.digestId.startsWith('digest_'))
  })

  it('shows empty digest when no matches', () => {
    const card = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [makeItem({ category: 'rare-category', tags: ['obscure'] })], offers: []
    })
    publishCard(net, card)
    const digest = getDigest(net, 'agent-a')
    assert.equal(digest.matches.length, 0)
    assert.ok(digest.summary.includes('No activity'))
  })
})

describe('Visibility & Disclosure', () => {
  it('filters items by visibility context', () => {
    const card = makeCard(keysA, { agentId: 'agent-a', alias: 'Alice',
      needs: [
        makeItem({ category: 'engineering', tags: ['rust'], visibility: 'public' }),
        makeItem({ category: 'funding', tags: ['seed'], visibility: 'on-match' }),
        makeItem({ category: 'personal', tags: ['contact'], visibility: 'on-approval' })
      ],
      offers: [makeItem({ category: 'design', tags: ['ui'], visibility: 'public' })]
    })

    const pub = getVisibleItems(card, 'public')
    assert.equal(pub.needs.length, 1)
    assert.equal(pub.needs[0].category, 'engineering')

    const matched = getVisibleItems(card, 'matched')
    assert.equal(matched.needs.length, 2) // public + on-match

    const approved = getVisibleItems(card, 'approved')
    assert.equal(approved.needs.length, 3) // all visible
  })
})

describe('Full Lifecycle — Founder finds a Rust engineer', () => {
  it('end-to-end: publish → search → match → intro → approve → digest', () => {
    const net = createIntentNetwork()

    // Alice is a founder looking for a Rust backend engineer
    const alice = makeCard(keysA, { agentId: 'alice-agent', alias: 'Alice (Founder)',
      needs: [makeItem({ category: 'engineering', tags: ['rust', 'backend', 'protocol'],
        priority: 'high', budget: { amount: 150, currency: 'USD' },
        description: 'Senior Rust engineer for protocol work, 3-month contract'
      })],
      offers: [makeItem({ category: 'partnership', tags: ['equity', 'startup', 'ai'],
        description: 'Co-founder equity in AI infrastructure startup'
      })],
      openTo: ['hiring', 'collaboration'], notOpenTo: ['cold-sales']
    })

    // Bob is a Rust engineer looking for protocol work
    const bob = makeCard(keysB, { agentId: 'bob-agent', alias: 'Bob (Engineer)',
      needs: [makeItem({ category: 'partnership', tags: ['startup', 'equity', 'technical'],
        description: 'Looking for early-stage startup with technical co-founder role'
      })],
      offers: [makeItem({ category: 'engineering', tags: ['rust', 'backend', 'systems', 'protocol'],
        priority: 'high', budget: { amount: 140, currency: 'USD' },
        description: '10yr Rust, built 2 protocol stacks, available immediately'
      })],
      openTo: ['hiring', 'collaboration', 'contract']
    })

    // Carol is a designer (shouldn't match Alice's engineering need)
    const carol = makeCard(keysC, { agentId: 'carol-agent', alias: 'Carol (Designer)',
      needs: [],
      offers: [makeItem({ category: 'design', tags: ['ui', 'figma', 'brand'] })],
      openTo: ['freelance']
    })

    // Publish all cards
    assert.equal(publishCard(net, alice).published, true)
    assert.equal(publishCard(net, bob).published, true)
    assert.equal(publishCard(net, carol).published, true)

    // Alice's agent searches the network
    const matches = searchMatches(net, 'alice-agent')
    assert.ok(matches.length >= 1)
    // Bob should be the top match (mutual: Alice needs eng, Bob offers eng; Bob needs partnership, Alice offers partnership)
    const topMatch = matches[0]
    assert.equal(topMatch.agentB, 'bob-agent')
    assert.equal(topMatch.mutual, true)
    assert.ok(topMatch.score >= 60)

    // Alice's agent proposes intro
    const intro = requestIntro(net, {
      requestedBy: 'alice-agent', targetAgentId: 'bob-agent',
      matchId: topMatch.matchId,
      message: 'My human is a founder building AI infra. She needs a Rust protocol engineer. Your human fits perfectly and is looking for a startup.',
      fieldsToDisclose: ['description', 'budget'],
      privateKey: keysA.privateKey
    })
    assert.ok(!('error' in intro))

    // Bob's agent shows digest
    const bobDigest = getDigest(net, 'bob-agent')
    assert.ok(bobDigest.introsReceived.length >= 1)
    assert.ok(bobDigest.summary.includes('intro'))

    // Bob approves
    const response = respondToIntro(net, {
      introId: (intro as any).introId, respondedBy: 'bob-agent',
      verdict: 'approve', message: 'Interested! Here is my info.',
      disclosedFields: { email: 'bob@engineer.dev', availability: 'immediate', rate: '$140/hr' },
      privateKey: keysB.privateKey
    })
    assert.ok(!('error' in response))
    assert.equal((response as any).verdict, 'approve')

    // Alice checks her digest — sees the approved intro
    const aliceDigest = getDigest(net, 'alice-agent')
    assert.ok(aliceDigest.matches.length >= 1)

    console.log('\n  ═══ Intent Network Lifecycle ═══')
    console.log(`  Cards published: 3`)
    console.log(`  Alice searched: ${matches.length} match(es)`)
    console.log(`  Top match: ${topMatch.agentB} (score: ${topMatch.score}, mutual: ${topMatch.mutual})`)
    console.log(`  Intro sent → Bob approved`)
    console.log(`  Bob disclosed: ${Object.keys((response as any).disclosedFields || {}).join(', ')}`)
    console.log(`  Alice digest: ${aliceDigest.summary}`)
    console.log(`  Bob digest: ${bobDigest.summary}`)
    console.log('  ═══ Connection made. Humans decide. ═══\n')
  })
})
