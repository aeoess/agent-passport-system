import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  applyReputationEvent,
  calculateOverallScore,
} from '../src/verification/reputation.ts'
import {
  generateApsTxt,
  resolveTermsForPath,
} from '../src/core/aps-txt.ts'
import {
  generateGovernanceBlock,
} from '../src/core/governance-block.ts'
import {
  createChainedGovernanceBlock,
} from '../src/core/aps-txt.ts'
import {
  isIssuerSigned,
  isIssuerVerified,
} from '../src/core/passport.ts'
import { generateKeyPair } from '../src/crypto/keys.ts'
import type { ReputationScore } from '../src/types/passport.ts'

const keys = generateKeyPair()

function freshScore(): ReputationScore {
  return {
    overall: 1,
    collaborationsCompleted: 0,
    proposalsSubmitted: 0,
    proposalsApproved: 0,
    tokensContributed: 0,
    tasksCompleted: 0,
    lastUpdated: new Date().toISOString(),
  }
}

describe('Audit Fix: Reputation penalties persist', () => {
  it('task_failed reduces overall score', () => {
    let score = freshScore()
    // Build up some score first
    for (let i = 0; i < 5; i++) {
      score = applyReputationEvent(score, { type: 'task_completed' })
    }
    const before = score.overall
    score = applyReputationEvent(score, { type: 'task_failed' })
    assert.ok(score.overall < before, `Expected ${score.overall} < ${before}`)
    assert.equal(score.penaltyDeductions, 0.1)
  })

  it('incident applies larger penalty', () => {
    let score = freshScore()
    for (let i = 0; i < 5; i++) {
      score = applyReputationEvent(score, { type: 'task_completed' })
    }
    const before = score.overall
    score = applyReputationEvent(score, { type: 'incident' })
    assert.ok(score.overall < before, `Expected ${score.overall} < ${before}`)
    assert.equal(score.penaltyDeductions, 0.5)
  })

  it('penalties accumulate across multiple events', () => {
    let score = freshScore()
    for (let i = 0; i < 10; i++) {
      score = applyReputationEvent(score, { type: 'task_completed' })
    }
    const before = score.overall
    score = applyReputationEvent(score, { type: 'task_failed' })
    score = applyReputationEvent(score, { type: 'task_failed' })
    score = applyReputationEvent(score, { type: 'incident' })
    assert.equal(score.penaltyDeductions, 0.7)
    assert.ok(score.overall < before)
  })

  it('score never drops below FLOOR (0.1)', () => {
    let score = freshScore()
    // Apply many incidents
    for (let i = 0; i < 50; i++) {
      score = applyReputationEvent(score, { type: 'incident' })
    }
    assert.ok(score.overall >= 0.1)
  })

  it('calculateOverallScore subtracts penalties', () => {
    const score: ReputationScore = {
      overall: 0,
      collaborationsCompleted: 10,
      proposalsSubmitted: 5,
      proposalsApproved: 5,
      tokensContributed: 100000,
      tasksCompleted: 20,
      penaltyDeductions: 1.0,
      lastUpdated: new Date().toISOString(),
    }
    const withPenalty = calculateOverallScore(score)
    const withoutPenalty = calculateOverallScore({ ...score, penaltyDeductions: 0 })
    assert.ok(withPenalty < withoutPenalty, `${withPenalty} should be < ${withoutPenalty}`)
    assert.equal(withoutPenalty - withPenalty, 1.0)
  })
})

describe('Audit Fix: Chained governance block inherits expires_at', () => {
  it('derivative inherits parent expiry', () => {
    const parent = generateGovernanceBlock({
      content: 'original article',
      publicKey: keys.publicKey,
      privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
      expiresAt: '2026-06-01T00:00:00Z',
    })
    const derivative = createChainedGovernanceBlock({
      content: 'summary of article',
      publicKey: keys.publicKey,
      privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
      parentBlock: parent,
      derivationType: 'summary',
    })
    assert.equal(derivative.expires_at, '2026-06-01T00:00:00Z')
  })

  it('derivative has no expiry if parent has none', () => {
    const parent = generateGovernanceBlock({
      content: 'original article',
      publicKey: keys.publicKey,
      privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
    })
    const derivative = createChainedGovernanceBlock({
      content: 'summary',
      publicKey: keys.publicKey,
      privateKey: keys.privateKey,
      terms: { inference: 'permitted' },
      parentBlock: parent,
      derivationType: 'summary',
    })
    assert.equal(derivative.expires_at, undefined)
  })
})

describe('Audit Fix: matchGlob ReDoS hardening', () => {
  it('still matches simple patterns', () => {
    const doc = generateApsTxt({
      domain: 'example.com',
      publisherName: 'Test',
      publicKey: keys.publicKey,
      privateKey: keys.privateKey,
      defaultTerms: { inference: 'permitted', training: 'prohibited' },
      pathOverrides: [
        { pattern: '/api/*', terms: { inference: 'prohibited', training: 'prohibited' } },
        { pattern: '/blog/**', terms: { inference: 'permitted', training: 'permitted' } },
      ],
    })
    // /api/* should match single segment
    const apiTerms = resolveTermsForPath(doc, '/api/data')
    assert.equal(apiTerms.inference, 'prohibited')

    // /blog/** should match deep paths
    const blogTerms = resolveTermsForPath(doc, '/blog/2026/march/post')
    assert.equal(blogTerms.training, 'permitted')

    // Unmatched path falls back to default
    const defaultTerms = resolveTermsForPath(doc, '/about')
    assert.equal(defaultTerms.inference, 'permitted')
    assert.equal(defaultTerms.training, 'prohibited')
  })

  it('handles complex patterns without hanging', () => {
    // This pattern would cause ReDoS with regex-based matching
    const doc = generateApsTxt({
      domain: 'example.com',
      publisherName: 'Test',
      publicKey: keys.publicKey,
      privateKey: keys.privateKey,
      defaultTerms: { inference: 'permitted' },
      pathOverrides: [
        { pattern: '/a/**/**/**/**/**/**/**', terms: { inference: 'prohibited' } },
      ],
    })
    const start = Date.now()
    const terms = resolveTermsForPath(doc, '/a/' + 'x/'.repeat(20) + 'z')
    const elapsed = Date.now() - start
    // Should complete in < 100ms, not 30+ seconds
    assert.ok(elapsed < 1000, `matchGlob took ${elapsed}ms — possible ReDoS`)
    assert.equal(terms.inference, 'prohibited')
  })
})

describe('Audit Fix: isIssuerSigned alias', () => {
  it('isIssuerSigned is same function as isIssuerVerified', () => {
    assert.equal(isIssuerSigned, isIssuerVerified)
  })
})
