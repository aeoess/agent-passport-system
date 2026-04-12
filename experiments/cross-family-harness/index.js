#!/usr/bin/env node
// index.js — Cross-family oversight experiment harness.
// Runs 15 configurations (5 governance scenarios x 3 model families),
// computes complementarity-gain metrics, outputs results JSON.
//
// Usage:
//   node experiments/cross-family-harness/index.js --dry-run
//   node experiments/cross-family-harness/index.js              # live API calls
//
// Requires: ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_AI_API_KEY in env.

import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { SCENARIOS, MODEL_FAMILIES, buildConfigurations } from './scenarios.js';
import { callModel } from './clients.js';
import { scoreResponse, buildSummary } from './metrics.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');

async function run() {
  const configs = buildConfigurations();
  const familyIds = MODEL_FAMILIES.map(f => f.id);
  const runResults = [];

  console.log(`Cross-Family Oversight Harness`);
  console.log(`Mode: ${dryRun ? 'DRY-RUN (mock responses)' : 'LIVE (API calls)'}`);
  console.log(`Configurations: ${configs.length} (${SCENARIOS.length} scenarios x ${MODEL_FAMILIES.length} families)`);
  console.log('');

  let totalCost = 0;

  for (const config of configs) {
    const label = `${config.scenario.name} / ${config.family.name}`;
    process.stdout.write(`  ${label}...`);

    try {
      const response = await callModel(
        config.family,
        config.scenario.id,
        config.scenario.prompt,
        dryRun,
      );

      const score = scoreResponse(response, config.scenario.ground_truth);
      totalCost += response.cost_usd;

      runResults.push({
        config_id: config.id,
        scenario_id: config.scenario.id,
        family_id: config.family.id,
        family_name: config.family.name,
        score,
        cost_usd: response.cost_usd,
        latency_ms: response.latency_ms,
        input_tokens: response.input_tokens,
        output_tokens: response.output_tokens,
        raw_flag: response.parsed?.flag,
        raw_confidence: response.parsed?.confidence,
        raw_reason: response.parsed?.reason,
      });

      const mark = score.correct ? '\u2713' : '\u2717';
      console.log(` ${mark} flag=${response.parsed?.flag} conf=${response.parsed?.confidence} ${response.latency_ms}ms $${response.cost_usd.toFixed(4)}`);
    } catch (err) {
      console.log(` ERROR: ${err.message}`);
      runResults.push({
        config_id: config.id,
        scenario_id: config.scenario.id,
        family_id: config.family.id,
        family_name: config.family.name,
        score: null,
        error: err.message,
        cost_usd: 0,
        latency_ms: 0,
      });
    }
  }

  // Compute summary.
  const summary = buildSummary(runResults, familyIds);

  // Write results.
  const resultsDir = resolve(__dirname, 'results');
  if (!existsSync(resultsDir)) mkdirSync(resultsDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outPath = resolve(resultsDir, `run-${timestamp}.json`);
  const output = {
    meta: {
      timestamp: new Date().toISOString(),
      mode: dryRun ? 'dry-run' : 'live',
      configurations: configs.length,
      scenarios: SCENARIOS.length,
      families: MODEL_FAMILIES.length,
      total_cost_usd: totalCost,
    },
    raw: runResults,
    summary,
  };

  writeFileSync(outPath, JSON.stringify(output, null, 2));

  // Print summary.
  console.log('');
  console.log('=== Summary ===');
  console.log(`Ensemble detection rate:  ${(summary.aggregate.ensemble_detection_rate * 100).toFixed(1)}%`);
  console.log(`Best single family rate:  ${(summary.aggregate.best_single_family_rate * 100).toFixed(1)}%`);
  console.log(`Ensemble complementarity: ${(summary.aggregate.ensemble_complementarity_gain * 100).toFixed(1)}%`);
  console.log(`Agreement rate:           ${(summary.aggregate.agreement_rate * 100).toFixed(1)}%`);
  console.log(`Total cost:               $${totalCost.toFixed(4)}`);
  console.log('');
  console.log('Complementarity matrix (row = reviewer, col = executor):');
  console.log('       ' + familyIds.map(f => f.padStart(8)).join(''));
  for (const a of familyIds) {
    const row = familyIds.map(b => summary.complementarity[a][b].toFixed(3).padStart(8));
    console.log(`  ${a.padEnd(6)} ${row.join('')}`);
  }
  console.log('');
  console.log(`Results: ${outPath}`);
}

run().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
