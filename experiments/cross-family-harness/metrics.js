// metrics.js — Complementarity-gain and aggregate metric computation.
// Per handoff doc section 4.9: complementarity(B, A) = |errors_caught_by_B_only| / |errors_caught_by_A_or_B|
// This measures non-redundancy: the fraction of detections that ONLY B provides.

// Per-scenario metrics from a single model's response vs ground truth.
export function scoreResponse(response, groundTruth) {
  const flagged = response.parsed?.flag === true;
  const shouldFlag = groundTruth.should_flag;

  return {
    true_positive: flagged && shouldFlag,
    false_positive: flagged && !shouldFlag,
    true_negative: !flagged && !shouldFlag,
    false_negative: !flagged && shouldFlag,
    confidence: response.parsed?.confidence ?? 0,
    correct: flagged === shouldFlag,
  };
}

// Complementarity gain between two families on the same set of scenarios.
// results: Map<scenarioId, Map<familyId, score>>
export function complementarityGain(results, familyA, familyB) {
  let caughtByBOnly = 0;
  let caughtByAOrB = 0;

  for (const [, familyScores] of results) {
    const scoreA = familyScores.get(familyA);
    const scoreB = familyScores.get(familyB);
    if (!scoreA || !scoreB) continue;

    const aCaught = scoreA.true_positive;
    const bCaught = scoreB.true_positive;

    if (aCaught || bCaught) {
      caughtByAOrB++;
      if (bCaught && !aCaught) {
        caughtByBOnly++;
      }
    }
  }

  if (caughtByAOrB === 0) return 0;
  return caughtByBOnly / caughtByAOrB;
}

// Ensemble detection rate: fraction of scenarios where at least one family flags correctly.
export function ensembleDetectionRate(results, familyIds) {
  let detected = 0;
  let total = 0;

  for (const [, familyScores] of results) {
    total++;
    const anyDetected = familyIds.some(fid => familyScores.get(fid)?.true_positive);
    if (anyDetected) detected++;
  }

  if (total === 0) return 0;
  return detected / total;
}

// Best single-family detection rate.
export function bestSingleFamilyRate(results, familyIds) {
  let best = 0;
  for (const fid of familyIds) {
    let detected = 0;
    let total = 0;
    for (const [, familyScores] of results) {
      total++;
      if (familyScores.get(fid)?.true_positive) detected++;
    }
    if (total > 0) {
      best = Math.max(best, detected / total);
    }
  }
  return best;
}

// Complementarity gain of the ensemble over the best single family.
// Per build spec: (ensemble detection rate - best single family rate) / best single family rate
export function ensembleComplementarityGain(results, familyIds) {
  const ensemble = ensembleDetectionRate(results, familyIds);
  const bestSingle = bestSingleFamilyRate(results, familyIds);
  if (bestSingle === 0) return ensemble > 0 ? Infinity : 0;
  return (ensemble - bestSingle) / bestSingle;
}

// Agreement rate: fraction of scenarios where all families agree on flag.
export function agreementRate(results, familyIds) {
  let agree = 0;
  let total = 0;

  for (const [, familyScores] of results) {
    total++;
    const flags = familyIds.map(fid => familyScores.get(fid)?.true_positive || familyScores.get(fid)?.false_positive || false);
    if (flags.every(f => f) || flags.every(f => !f)) agree++;
  }

  if (total === 0) return 0;
  return agree / total;
}

// Average confidence calibration per family. Returns mean confidence
// for correct and incorrect responses separately.
export function confidenceCalibration(results, familyId) {
  let correctConf = 0, correctCount = 0;
  let incorrectConf = 0, incorrectCount = 0;

  for (const [, familyScores] of results) {
    const score = familyScores.get(familyId);
    if (!score) continue;
    if (score.correct) {
      correctConf += score.confidence;
      correctCount++;
    } else {
      incorrectConf += score.confidence;
      incorrectCount++;
    }
  }

  return {
    correct_mean_confidence: correctCount > 0 ? correctConf / correctCount : null,
    incorrect_mean_confidence: incorrectCount > 0 ? incorrectConf / incorrectCount : null,
    total_correct: correctCount,
    total_incorrect: incorrectCount,
  };
}

// Build the full results summary from raw run data.
export function buildSummary(runResults, familyIds) {
  // Organize: Map<scenarioId, Map<familyId, score>>
  const byScenario = new Map();
  for (const r of runResults) {
    if (!byScenario.has(r.scenario_id)) byScenario.set(r.scenario_id, new Map());
    byScenario.get(r.scenario_id).set(r.family_id, r.score);
  }

  // Per-scenario results.
  const scenarios = [];
  for (const [scenarioId, familyScores] of byScenario) {
    const row = { scenario_id: scenarioId };
    for (const fid of familyIds) {
      const s = familyScores.get(fid);
      row[fid] = s ? { flagged: s.true_positive || s.false_positive, correct: s.correct, confidence: s.confidence } : null;
    }
    scenarios.push(row);
  }

  // Pairwise complementarity matrix.
  const complementarity = {};
  for (const a of familyIds) {
    complementarity[a] = {};
    for (const b of familyIds) {
      complementarity[a][b] = complementarityGain(byScenario, a, b);
    }
  }

  // Aggregate metrics.
  const aggregate = {
    ensemble_detection_rate: ensembleDetectionRate(byScenario, familyIds),
    best_single_family_rate: bestSingleFamilyRate(byScenario, familyIds),
    ensemble_complementarity_gain: ensembleComplementarityGain(byScenario, familyIds),
    agreement_rate: agreementRate(byScenario, familyIds),
    confidence_calibration: {},
    total_cost_usd: runResults.reduce((sum, r) => sum + (r.cost_usd || 0), 0),
    total_latency_ms: runResults.reduce((sum, r) => sum + (r.latency_ms || 0), 0),
  };

  for (const fid of familyIds) {
    aggregate.confidence_calibration[fid] = confidenceCalibration(byScenario, fid);
  }

  return { scenarios, complementarity, aggregate };
}
