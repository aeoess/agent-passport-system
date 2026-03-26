// ══════════════════════════════════════════════════════════════════
// Evidence Diversity & Confidence Scoring — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: sybil resistance via diversity-weighted confidence,
// computeConfidence scoring, and diversity tracking in reputation updates.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createScopedReputation, updateReputationFromResult,
  computeConfidence, createEvidenceDiversity,
} from '../src/core/reputation-authority.js'
import type { ScopedReputation } from '../src/types/reputation-authority.js'

describe('Evidence Diversity — Confidence Scoring', () => {
  it('fresh reputation has confidence 0', () => {
    const rep = createScopedReputation('principal-1', 'agent-1', 'data_read')
    assert.strictEqual(rep.confidence, 0)
    assert.ok(rep.evidenceDiversity, 'must have diversity metadata')
    assert.strictEqual(rep.evidenceDiversity.distinctPrincipals, 0)
  })

  it('few interactions from one principal = low confidence', () => {
    let rep = createScopedReputation('p1', 'a1', 'scope')
    // 3 successes from same principal, same task type
    for (let i = 0; i < 3; i++) {
      rep = updateReputationFromResult(rep, true, 'standard', {
        principalHash: 'principal-abc123',
        taskType: 'database_query',
      })
    }
    assert.ok(rep.confidence !== undefined)
    assert.ok(rep.confidence < 0.5,
      `3 homogeneous interactions should yield low confidence, got ${rep.confidence}`)
    assert.strictEqual(rep.evidenceDiversity!.distinctPrincipals, 1)
    assert.strictEqual(rep.evidenceDiversity!.distinctTaskTypes, 1)
  })

  it('many diverse interactions = high confidence', () => {
    let rep = createScopedReputation('p1', 'a1', 'scope')
    const principals = ['p-alice', 'p-bob', 'p-carol', 'p-dave', 'p-eve']
    const tools = ['db_query', 'api_call', 'file_write', 'email_send']
    const classes: Array<'trivial' | 'standard' | 'complex' | 'critical'> = ['trivial', 'standard', 'complex', 'critical']

    for (let i = 0; i < 40; i++) {
      const success = i % 8 !== 0 // ~12.5% failure rate (healthy range)
      rep = updateReputationFromResult(rep, success, classes[i % 4], {
        principalHash: principals[i % 5],
        taskType: tools[i % 4],
      })
    }
    assert.ok(rep.confidence! > 0.7,
      `40 diverse interactions should yield high confidence, got ${rep.confidence}`)
    assert.strictEqual(rep.evidenceDiversity!.distinctPrincipals, 5)
    assert.strictEqual(rep.evidenceDiversity!.distinctTaskTypes, 4)
    assert.strictEqual(rep.evidenceDiversity!.distinctEvidenceClasses, 4)
  })

  it('sybil pattern: many interactions but homogeneous = low confidence', () => {
    let rep = createScopedReputation('p1', 'a1', 'scope')
    // 100 trivial successes from ONE principal, ONE task type, ZERO failures
    for (let i = 0; i < 100; i++) {
      rep = updateReputationFromResult(rep, true, 'trivial', {
        principalHash: 'sybil-master',
        taskType: 'trivial_task',
      })
    }
    // High mu (many successes), but confidence should be LOW because:
    // - Only 1 principal (easy to fake)
    // - Only 1 evidence class (trivial)
    // - 0% failure rate with many interactions (suspicious)
    assert.ok(rep.mu > 40, `mu should be high from 100 successes, got ${rep.mu}`)
    assert.ok(rep.confidence! < 0.6,
      `Sybil pattern should yield low confidence despite high mu, got ${rep.confidence}`)
  })

  it('healthy failure rate increases confidence', () => {
    // Agent A: 30 successes, 0 failures (suspicious)
    let repA = createScopedReputation('p1', 'agentA', 'scope')
    for (let i = 0; i < 30; i++) {
      repA = updateReputationFromResult(repA, true, 'standard', {
        principalHash: `p-${i % 5}`, taskType: `tool-${i % 3}`,
      })
    }

    // Agent B: 27 successes, 3 failures (~10%, healthy range)
    let repB = createScopedReputation('p1', 'agentB', 'scope')
    for (let i = 0; i < 30; i++) {
      const success = i % 10 !== 0
      repB = updateReputationFromResult(repB, success, 'standard', {
        principalHash: `p-${i % 5}`, taskType: `tool-${i % 3}`,
      })
    }

    // Agent B should have equal or higher confidence despite lower mu
    assert.ok(repB.confidence! >= repA.confidence!,
      `Healthy failures should increase confidence: A=${repA.confidence}, B=${repB.confidence}`)
  })

  it('backward compatible: no diversityUpdate param still works', () => {
    let rep = createScopedReputation('p1', 'a1', 'scope')
    // Call without diversityUpdate (old behavior)
    rep = updateReputationFromResult(rep, true, 'standard')
    assert.ok(rep.mu > 25, 'mu should increase')
    assert.strictEqual(rep.receiptCount, 1)
    // Diversity should still track evidence class
    assert.strictEqual(rep.evidenceDiversity!.distinctEvidenceClasses, 1)
    assert.strictEqual(rep.evidenceDiversity!.successCount, 1)
    // But principals/tasks stay at 0 since no diversityUpdate provided
    assert.strictEqual(rep.evidenceDiversity!.distinctPrincipals, 0)
  })

  it('confidence increases monotonically with diversity', () => {
    let rep = createScopedReputation('p1', 'a1', 'scope')
    const confidences: number[] = []

    // Add interactions with increasing diversity
    const principals = ['p1', 'p2', 'p3', 'p4', 'p5']
    const tools = ['t1', 't2', 't3']
    const classes: Array<'trivial' | 'standard' | 'complex'> = ['trivial', 'standard', 'complex']

    for (let i = 0; i < 25; i++) {
      const success = i % 7 !== 0
      rep = updateReputationFromResult(rep, success, classes[Math.min(i % 3, 2)], {
        principalHash: principals[Math.min(i, 4)],
        taskType: tools[Math.min(i % 3, 2)],
      })
      if (i % 5 === 4) confidences.push(rep.confidence!)
    }

    // Confidence should trend upward overall (last > first)
    assert.ok(confidences[confidences.length - 1] > confidences[0],
      `Confidence should trend up overall: first=${confidences[0]}, last=${confidences[confidences.length - 1]}`)
    // And final should be meaningfully higher than zero
    assert.ok(confidences[confidences.length - 1] > 0.5,
      `Final confidence should be meaningful: ${confidences[confidences.length - 1]}`)
  })
})
