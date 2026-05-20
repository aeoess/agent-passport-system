/**
 * L4 gateway-bound enforcement baseline.
 *
 * Measures HTTP round-trip latency to the AEOESS gateway's policy
 * evaluation endpoint (POST /api/v1/evaluate) and compares against
 * the local-enforcement layers (L0/L1 pure Rust, L2/L3 TS+FFI).
 *
 * Methodology mirrors the L0-L3 runners: pre-allocate request,
 * warmup untimed, measure ns per call via process.hrtime.bigint(),
 * write result JSON to results/<env>/L4.json.
 *
 * Spec §16 hypothesis range for L4: 2-50ms (2_000_000-50_000_000 ns).
 *
 * Configuration via env:
 *   L4_GATEWAY_URL    default http://localhost:3200
 *   L4_GATEWAY_LOC    default "local-dogfood"
 *   L4_API_KEY        required; bearer token
 *   L4_AGENT_ID       default "l4-bench-agent"
 *   L4_SCOPE_REQ      default "read:customer"
 *   L4_SAMPLE_COUNT   default 1000
 *   L4_WARMUP_COUNT   default 100
 */

import { captureEnvironment } from '..';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { execSync } from 'node:child_process';

const GATEWAY_URL = process.env.L4_GATEWAY_URL || 'http://localhost:3200';
const GATEWAY_LOC = process.env.L4_GATEWAY_LOC || 'local-dogfood';
const API_KEY = process.env.L4_API_KEY;
const AGENT_ID = process.env.L4_AGENT_ID || 'l4-bench-agent';
const SCOPE_REQ = process.env.L4_SCOPE_REQ || 'read:customer';
const SAMPLE_COUNT = parseInt(process.env.L4_SAMPLE_COUNT || '1000', 10);
const WARMUP_COUNT = parseInt(process.env.L4_WARMUP_COUNT || '100', 10);

if (!API_KEY) {
  console.error('L4_API_KEY env var is required');
  process.exit(1);
}

const ENV_TAG = process.env.APS_RESULTS_ENV_TAG || 'mac-apple-silicon';
const RESULTS_DIR = resolve(
  __dirname,
  '..',
  '..',
  '..',
  'benchmarks',
  'prototype-1',
  'results',
  ENV_TAG
);

const ENDPOINT = `${GATEWAY_URL}/api/v1/evaluate`;
const METHOD = 'POST';
const NETWORK_PATH = GATEWAY_URL.includes('localhost') || GATEWAY_URL.includes('127.0.0.1')
  ? 'loopback'
  : 'internet';

const body = JSON.stringify({
  agent_id: AGENT_ID,
  action_type: 'read',
  action_target: 'customer/12345',
  scope_required: SCOPE_REQ,
});

const headers = {
  'Content-Type': 'application/json',
  Authorization: `Bearer ${API_KEY}`,
};

function computeStats(samples: number[]) {
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  const pct = (p: number) => sorted[Math.min(n - 1, Math.ceil(p * (n - 1)))];
  return {
    n,
    minNs: sorted[0],
    maxNs: sorted[n - 1],
    p50Ns: pct(0.5),
    p95Ns: pct(0.95),
    p99Ns: pct(0.99),
    p99_9Ns: pct(0.999),
  };
}

function gitCommit(): string {
  try {
    return execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

async function callOnce(): Promise<{ elapsedNs: number; verdict: string }> {
  const t0 = process.hrtime.bigint();
  const res = await fetch(ENDPOINT, { method: METHOD, body, headers });
  const json = (await res.json()) as { verdict: string };
  const elapsedNs = Number(process.hrtime.bigint() - t0);
  return { elapsedNs, verdict: json.verdict };
}

async function main() {
  mkdirSync(RESULTS_DIR, { recursive: true });

  process.stderr.write(
    `L4 gateway baseline → ${ENDPOINT} (${GATEWAY_LOC}, ${NETWORK_PATH})\n`
  );
  process.stderr.write(
    `warmup=${WARMUP_COUNT} samples=${SAMPLE_COUNT}\n`
  );

  // Warmup.
  for (let i = 0; i < WARMUP_COUNT; i++) {
    const { verdict } = await callOnce();
    if (verdict !== 'permit') {
      throw new Error(`warmup iter ${i}: verdict=${verdict}`);
    }
  }

  // Measure.
  const samples = new Array<number>(SAMPLE_COUNT);
  const wallStart = process.hrtime.bigint();
  for (let i = 0; i < SAMPLE_COUNT; i++) {
    const { elapsedNs, verdict } = await callOnce();
    if (verdict !== 'permit') {
      throw new Error(`measure iter ${i}: verdict=${verdict}`);
    }
    samples[i] = elapsedNs;
  }
  const wallNs = Number(process.hrtime.bigint() - wallStart);

  const stats = computeStats(samples);
  const throughputOpsPerSec = (SAMPLE_COUNT * 1e9) / wallNs;

  const result = {
    benchmark: 'L4',
    description: 'gateway_bound_authorization_round_trip',
    gateway_endpoint: ENDPOINT,
    gateway_location: GATEWAY_LOC,
    http_method: METHOD,
    network_path: NETWORK_PATH,
    environment: captureEnvironment(),
    methodology: {
      sample_count: SAMPLE_COUNT,
      warmup_count: WARMUP_COUNT,
      single_threaded: true,
      sequential: true,
      timer: 'process.hrtime.bigint()',
      percentile_method:
        'raw sample at index ceil(p * (n-1)), no interpolation',
      includes_durability: true,
      includes_network: NETWORK_PATH === 'internet',
      notes:
        'TS fetch() to gateway /api/v1/evaluate. Each call lands a ' +
        'permit row in policy_evaluations + mints an evaluation ' +
        'receipt. Body is the same on every iteration; cache effects ' +
        'are exercised by warmup.',
    },
    samples: stats,
    throughput_ops_per_sec: throughputOpsPerSec,
    total_wall_time_ns: wallNs,
    run: {
      timestamp_unix_ns: process.hrtime.bigint().toString(),
      node_version: process.version,
      git_commit: gitCommit(),
    },
  };

  const out = resolve(RESULTS_DIR, 'L4.json');
  writeFileSync(out, JSON.stringify(result, null, 2) + '\n');
  process.stderr.write(`  wrote ${out}\n`);

  console.log('');
  console.log(
    `L4 ${GATEWAY_LOC} (${NETWORK_PATH}, single-thread, ${SAMPLE_COUNT} samples)`
  );
  const fmt = (ns: number) => {
    if (ns < 1_000) return `${ns}ns`;
    if (ns < 1_000_000) return `${(ns / 1_000).toFixed(2)}µs`;
    if (ns < 1_000_000_000) return `${(ns / 1_000_000).toFixed(2)}ms`;
    return `${(ns / 1_000_000_000).toFixed(2)}s`;
  };
  console.log(`  p50    = ${fmt(stats.p50Ns)}`);
  console.log(`  p95    = ${fmt(stats.p95Ns)}`);
  console.log(`  p99    = ${fmt(stats.p99Ns)}`);
  console.log(`  p99.9  = ${fmt(stats.p99_9Ns)}`);
  console.log(`  tput   = ${throughputOpsPerSec.toFixed(1)} op/s`);

  const inHypothesis =
    stats.p50Ns >= 2_000_000 && stats.p50Ns <= 50_000_000;
  console.log(
    `  spec §16 hypothesis 2-50ms: ${
      inHypothesis ? '✓ in range' : '✗ OUTSIDE range — flag'
    }`
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
