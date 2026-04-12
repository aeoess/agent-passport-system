// metrics.test.js — Unit tests for complementarity-gain and aggregate metrics.
// Run: node --test experiments/cross-family-harness/metrics.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  scoreResponse,
  complementarityGain,
  ensembleDetectionRate,
  bestSingleFamilyRate,
  ensembleComplementarityGain,
  agreementRate,
  confidenceCalibration,
  buildSummary,
} from './metrics.js';

describe('scoreResponse', () => {
  it('true positive: flagged correctly', () => {
    const r = scoreResponse(
      { parsed: { flag: true, confidence: 0.9 } },
      { should_flag: true },
    );
    assert.equal(r.true_positive, true);
    assert.equal(r.false_positive, false);
    assert.equal(r.correct, true);
  });

  it('false negative: missed a real bug', () => {
    const r = scoreResponse(
      { parsed: { flag: false, confidence: 0.3 } },
      { should_flag: true },
    );
    assert.equal(r.false_negative, true);
    assert.equal(r.correct, false);
  });

  it('false positive: flagged a non-issue', () => {
    const r = scoreResponse(
      { parsed: { flag: true, confidence: 0.7 } },
      { should_flag: false },
    );
    assert.equal(r.false_positive, true);
    assert.equal(r.correct, false);
  });

  it('true negative: correctly passed clean scenario', () => {
    const r = scoreResponse(
      { parsed: { flag: false, confidence: 0.8 } },
      { should_flag: false },
    );
    assert.equal(r.true_negative, true);
    assert.equal(r.correct, true);
  });
});

describe('complementarityGain', () => {
  it('returns 0 when both families catch the same errors', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: true }], ['b', { true_positive: true }]])],
      ['s2', new Map([['a', { true_positive: true }], ['b', { true_positive: true }]])],
    ]);
    assert.equal(complementarityGain(results, 'a', 'b'), 0);
  });

  it('returns 1 when B catches everything A misses and A catches nothing', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: false }], ['b', { true_positive: true }]])],
      ['s2', new Map([['a', { true_positive: false }], ['b', { true_positive: true }]])],
    ]);
    assert.equal(complementarityGain(results, 'a', 'b'), 1.0);
  });

  it('returns 0.5 when B catches one A misses out of two total', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: true }], ['b', { true_positive: true }]])],
      ['s2', new Map([['a', { true_positive: false }], ['b', { true_positive: true }]])],
    ]);
    // B catches s1 and s2. A catches only s1. B-only = 1 (s2). A-or-B = 2.
    assert.equal(complementarityGain(results, 'a', 'b'), 0.5);
  });

  it('returns 0 when neither catches anything', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: false }], ['b', { true_positive: false }]])],
    ]);
    assert.equal(complementarityGain(results, 'a', 'b'), 0);
  });
});

describe('ensembleDetectionRate', () => {
  it('returns 1 when at least one family catches each scenario', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: true }], ['b', { true_positive: false }]])],
      ['s2', new Map([['a', { true_positive: false }], ['b', { true_positive: true }]])],
    ]);
    assert.equal(ensembleDetectionRate(results, ['a', 'b']), 1.0);
  });

  it('returns 0.5 when one scenario is completely missed', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: true }], ['b', { true_positive: false }]])],
      ['s2', new Map([['a', { true_positive: false }], ['b', { true_positive: false }]])],
    ]);
    assert.equal(ensembleDetectionRate(results, ['a', 'b']), 0.5);
  });
});

describe('ensembleComplementarityGain', () => {
  it('gain is always >= 0', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: true }], ['b', { true_positive: true }]])],
    ]);
    const gain = ensembleComplementarityGain(results, ['a', 'b']);
    assert.ok(gain >= 0, `gain should be >= 0, got ${gain}`);
  });

  it('gain is 0 when all families detect the same set', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: true }], ['b', { true_positive: true }]])],
      ['s2', new Map([['a', { true_positive: true }], ['b', { true_positive: true }]])],
    ]);
    assert.equal(ensembleComplementarityGain(results, ['a', 'b']), 0);
  });

  it('gain is positive when ensemble catches more than best single', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: true }], ['b', { true_positive: false }]])],
      ['s2', new Map([['a', { true_positive: false }], ['b', { true_positive: true }]])],
    ]);
    // Best single: 0.5 (each catches 1 of 2). Ensemble: 1.0. Gain: (1-0.5)/0.5 = 1.0
    assert.equal(ensembleComplementarityGain(results, ['a', 'b']), 1.0);
  });
});

describe('agreementRate', () => {
  it('returns 1 when all families always agree', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: true, false_positive: false }], ['b', { true_positive: true, false_positive: false }]])],
    ]);
    assert.equal(agreementRate(results, ['a', 'b']), 1.0);
  });

  it('returns 0 when families never agree', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: true, false_positive: false }], ['b', { true_positive: false, false_positive: false }]])],
    ]);
    assert.equal(agreementRate(results, ['a', 'b']), 0);
  });

  it('agreement rate is always in [0, 1]', () => {
    const results = new Map([
      ['s1', new Map([['a', { true_positive: true }], ['b', { true_positive: false }]])],
      ['s2', new Map([['a', { true_positive: true }], ['b', { true_positive: true }]])],
    ]);
    const rate = agreementRate(results, ['a', 'b']);
    assert.ok(rate >= 0 && rate <= 1, `rate should be in [0,1], got ${rate}`);
  });
});

describe('buildSummary', () => {
  it('produces valid structure from run results', () => {
    const runResults = [
      { scenario_id: 's1', family_id: 'a', score: { true_positive: true, false_positive: false, true_negative: false, false_negative: false, correct: true, confidence: 0.9 }, cost_usd: 0.01, latency_ms: 100 },
      { scenario_id: 's1', family_id: 'b', score: { true_positive: false, false_positive: false, true_negative: false, false_negative: true, correct: false, confidence: 0.4 }, cost_usd: 0.005, latency_ms: 80 },
    ];
    const summary = buildSummary(runResults, ['a', 'b']);
    assert.ok(summary.scenarios.length === 1);
    assert.ok(typeof summary.complementarity.a.b === 'number');
    assert.ok(summary.aggregate.ensemble_detection_rate >= 0);
    assert.ok(summary.aggregate.agreement_rate >= 0);
    assert.ok(summary.aggregate.total_cost_usd > 0);
  });
});
