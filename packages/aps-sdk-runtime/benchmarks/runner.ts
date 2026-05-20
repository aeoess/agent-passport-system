/**
 * L2 / L3a / L3b1 / L3b2 single-thread benchmark runner.
 *
 * Drives the verifier hot path through the full TS -> FFI -> Rust
 * stack and writes per-benchmark JSON to
 * `benchmarks/prototype-1/results/mac-apple-silicon/`. Spec §12
 * benchmark matrix:
 *
 *   L2   TS SDK via N-API, no event           (SinkMode.Null)
 *   L3a  TS SDK + Mode A (memory-buffered)    (SinkMode.ModeA)
 *   L3b1 TS SDK + Mode B1 (blocking commit)   (SinkMode.ModeB1)
 *   L3b2 TS SDK + Mode B2 (queued commit)     (SinkMode.ModeB2)
 *
 * Methodology mirrors the Rust L0/L1 runner: true Allow per call
 * (incrementing sequence_id matches authority.sequence_next),
 * NullSink for L2 and the chunk-9 Mode A/B sinks for L3*. Sample
 * counts scaled per mode to keep wall time bounded.
 */

import {
  authorityInfo,
  captureEnvironment,
  check,
  computeRegistryRoot,
  hashResourcePath,
  loadPassportUnverified,
  shutdownAuthority,
  SinkMode,
} from '..';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execSync } from 'node:child_process';

const TOOL_DESCRIPTOR_HASH_HEX =
  'abcd000000000000000000000000000000000000000000000000000000000000';

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

interface BenchSpec {
  name: 'L2' | 'L3a' | 'L3b1' | 'L3b2';
  description: string;
  sinkMode: SinkMode;
  sampleCount: number;
  warmupCount: number;
  bufferCapacity: number;
  flushIntervalMs: number;
  batchSize: number;
  batchWindowMs: number;
}

const BENCH_SPECS: BenchSpec[] = [
  {
    name: 'L2',
    description: 'ts_sdk_napi_null_sink',
    sinkMode: SinkMode.Null,
    sampleCount: 100_000,
    warmupCount: 2_000,
    bufferCapacity: 0,
    flushIntervalMs: 0,
    batchSize: 0,
    batchWindowMs: 0,
  },
  {
    name: 'L3a',
    description: 'ts_sdk_napi_mode_a_memory_buffered',
    sinkMode: SinkMode.ModeA,
    sampleCount: 50_000,
    warmupCount: 2_000,
    // Buffer must hold the production-vs-flush delta during the run.
    // 50k samples at ~10µs each ≈ 500ms wall; with 25ms flush interval
    // the buffer peaks at ~50k/(500ms/25ms) = ~2.5k events between
    // drains. 128k cap is generous, prevents BufferFull panics.
    bufferCapacity: 131_072,
    flushIntervalMs: 25,
    batchSize: 0,
    batchWindowMs: 0,
  },
  {
    name: 'L3b1',
    description: 'ts_sdk_napi_mode_b1_blocking_group_commit',
    sinkMode: SinkMode.ModeB1,
    sampleCount: 5_000, // ~1ms per call × 5000 = 5s
    warmupCount: 200,
    bufferCapacity: 1_024,
    flushIntervalMs: 0,
    batchSize: 64,
    batchWindowMs: 1,
  },
  {
    name: 'L3b2',
    description: 'ts_sdk_napi_mode_b2_queued_group_commit',
    sinkMode: SinkMode.ModeB2,
    sampleCount: 50_000,
    warmupCount: 2_000,
    // Same buffer-sizing concern as L3a: emits return immediately so
    // the buffer fills if the commit thread can't drain fast enough.
    bufferCapacity: 131_072,
    flushIntervalMs: 0,
    batchSize: 64,
    batchWindowMs: 1,
  },
];

function buildPassport(rootHex: string, sequenceEnd: number): string {
  const now = Date.now();
  const issued = new Date(now - 30_000).toISOString();
  const expires = new Date(now + 600_000).toISOString(); // 10 min window
  return JSON.stringify({
    type: 'aps.runtime_passport',
    version: '0.1',
    passport_id: 'rp_bench_l23_0000000000000000',
    agent_id: 'ag_bench_l23_0000000000000000',
    principal_id: 'pr_bench_l23_0000000000000000',
    beneficiary_id: 'bn_bench_l23_0000000000000000',
    issuer: 'https://gateway.example.test',
    issued_at: issued,
    expires_at: expires,
    max_clock_skew_ms: 1000,
    policy_epoch: 42,
    revocation_epoch: 1842,
    tool_registry_root: `blake3:${rootHex}`,
    delegation_chain_hash:
      'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    effective_authority_hash:
      'blake3:0000000000000000000000000000000000000000000000000000000000000000',
    risk_class: 'R2',
    minimum_tier_required: 'T2',
    tier_attested: 'T2',
    verifier_instance_id: 'vi_bench_l23_0000000000000000',
    verifier_build_hash:
      'blake3:1111111111111111111111111111111111111111111111111111111111111111',
    session_id: 'sn_bench_l23_0000000000000000',
    sequence_start: 1000,
    sequence_end: sequenceEnd,
    budget_lease: {
      lease_id: 'bl_bench_l23_0000000000000000',
      max_actions: 4_294_967_295,
      // u64::MAX overflows JS safe-integer; pick a value large enough
      // to never deplete during a benchmark (1M iters × 1 unit each).
      max_cost_units: 9_007_199_254_740_991, // Number.MAX_SAFE_INTEGER
      sublease_parent: null,
    },
    authority_blob_encoding: 'application/aps-authority+json',
    authority_blob: {
      allowed_tools: [`blake3:${TOOL_DESCRIPTOR_HASH_HEX}`],
      allowed_operations: ['read'],
      resource_scopes: ['customer/*'],
      approval_rules: [],
    },
    receipt_stream_id: 'rs_bench_l23_0000000000000000',
    signature: 'ed25519:' + '0'.repeat(128),
  });
}

interface SampleStats {
  n: number;
  meanNs: number;
  stddevNs: number;
  minNs: number;
  maxNs: number;
  p50Ns: number;
  p95Ns: number;
  p99Ns: number;
  p99_9Ns: number;
}

function computeStats(samples: number[]): SampleStats {
  const n = samples.length;
  if (n === 0) throw new Error('empty samples');
  const sorted = samples.slice().sort((a, b) => a - b);
  let sum = 0;
  for (const s of sorted) sum += s;
  const mean = sum / n;
  let variance = 0;
  for (const s of sorted) {
    const d = s - mean;
    variance += d * d;
  }
  variance /= n;
  const pct = (p: number) =>
    sorted[Math.min(sorted.length - 1, Math.ceil((sorted.length - 1) * p))];
  return {
    n,
    meanNs: Math.round(mean),
    stddevNs: Math.round(Math.sqrt(variance)),
    minNs: sorted[0],
    maxNs: sorted[sorted.length - 1],
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

function runBenchmark(spec: BenchSpec) {
  const tools = [
    { descriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX, localId: 0 },
  ];
  const rootHex = computeRegistryRoot(tools);
  const sequenceEnd = 1000 + spec.sampleCount + spec.warmupCount + 100;
  const passportJson = buildPassport(rootHex, sequenceEnd);

  // Per-mode tmpdir for the log (if applicable).
  let tmpDir: string | null = null;
  let logPath: string | undefined;
  if (spec.sinkMode !== SinkMode.Null) {
    tmpDir = mkdtempSync(join(tmpdir(), `aps-bench-${spec.name}-`));
    logPath = join(tmpDir, 'receipts.log');
  }

  const sinkConfig =
    spec.sinkMode === SinkMode.Null
      ? { mode: SinkMode.Null }
      : {
          mode: spec.sinkMode,
          logPath,
          bufferCapacity: spec.bufferCapacity,
          flushIntervalMs: spec.flushIntervalMs,
          maxBatchSize: spec.batchSize,
          maxBatchWindowMs: spec.batchWindowMs,
        };

  const handle = loadPassportUnverified(passportJson, tools, sinkConfig);
  const info = authorityInfo(handle);
  const resourceHashes = hashResourcePath(['customer', '12345']);

  // Pre-allocate the action object; mutate sequenceId per iteration.
  const action = {
    version: 1,
    passportIdHashHex: info.passportIdHashHex,
    toolDescriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX,
    localToolId: 0,
    operationId: 0,
    resourceType: 0,
    riskClass: 2,
    resourcePathDepth: 2,
    costUnits: 1,
    sequenceId: 0n,
    nonceHex: '00112233445566778899aabbccddeeff',
    resourcePathHashes: resourceHashes,
  };

  // Warmup (untimed).
  let seq = 1000n;
  for (let i = 0; i < spec.warmupCount; i++) {
    action.sequenceId = seq++;
    const d = check(handle, action);
    if (d.decisionType !== 'Allow') {
      throw new Error(`warmup iter ${i}: ${d.reasonName}`);
    }
  }

  // Measure.
  const samples = new Array<number>(spec.sampleCount);
  const wallStart = process.hrtime.bigint();
  for (let i = 0; i < spec.sampleCount; i++) {
    action.sequenceId = seq++;
    const t0 = process.hrtime.bigint();
    const d = check(handle, action);
    const elapsed = Number(process.hrtime.bigint() - t0);
    if (d.decisionType !== 'Allow') {
      throw new Error(`measure iter ${i}: ${d.reasonName}`);
    }
    samples[i] = elapsed;
  }
  const wallNs = Number(process.hrtime.bigint() - wallStart);

  shutdownAuthority(handle);
  if (tmpDir) rmSync(tmpDir, { recursive: true, force: true });

  const stats = computeStats(samples);
  const throughputOpsPerSec = (spec.sampleCount * 1e9) / wallNs;

  return {
    benchmark: spec.name,
    description: spec.description,
    sink_mode: SinkMode[spec.sinkMode] ?? spec.sinkMode,
    environment: captureEnvironment(),
    methodology: {
      sample_count: spec.sampleCount,
      warmup_count: spec.warmupCount,
      single_threaded: true,
      timer: 'process.hrtime.bigint()',
      percentile_method:
        'raw sample at index ceil(p * (n-1)), no interpolation',
      includes_durability: spec.sinkMode !== SinkMode.Null,
      sink_buffer_capacity:
        spec.sinkMode === SinkMode.Null ? null : spec.bufferCapacity,
      sink_flush_interval_ms:
        spec.sinkMode === SinkMode.ModeA ? spec.flushIntervalMs : null,
      sink_batch_size:
        spec.sinkMode === SinkMode.ModeB1 || spec.sinkMode === SinkMode.ModeB2
          ? spec.batchSize
          : null,
      sink_batch_window_ms:
        spec.sinkMode === SinkMode.ModeB1 || spec.sinkMode === SinkMode.ModeB2
          ? spec.batchWindowMs
          : null,
      notes:
        'TS → N-API → Rust full path. True Allow per call: sequence_id ' +
        'increments and matches authority.sequence_next.',
    },
    samples: stats,
    throughput_ops_per_sec: throughputOpsPerSec,
    total_wall_time_ns: wallNs,
    run: {
      timestamp_unix_ns: process
        .hrtime
        .bigint()
        .toString(),
      node_version: process.version,
      git_commit: gitCommit(),
    },
  };
}

function main() {
  mkdirSync(RESULTS_DIR, { recursive: true });

  const summary: Array<{
    name: string;
    p50: number;
    p99_9: number;
    throughput: number;
  }> = [];

  for (const spec of BENCH_SPECS) {
    process.stderr.write(
      `running ${spec.name} (${spec.sampleCount} samples)…\n`
    );
    const result = runBenchmark(spec);
    const out = join(RESULTS_DIR, `${spec.name}.json`);
    writeFileSync(out, JSON.stringify(result, null, 2) + '\n');
    process.stderr.write(`  wrote ${out}\n`);
    summary.push({
      name: spec.name,
      p50: result.samples.p50Ns,
      p99_9: result.samples.p99_9Ns,
      throughput: result.throughput_ops_per_sec,
    });
  }

  console.log('');
  console.log('L2/L3 sweep (Apple Silicon, single-thread)');
  console.log(' Bench |      p50 |    p99.9 |       throughput');
  console.log(' ------+----------+----------+-----------------');
  for (const r of summary) {
    const p50 = formatNs(r.p50);
    const p999 = formatNs(r.p99_9);
    const tp = r.throughput.toFixed(0).padStart(11);
    console.log(` ${r.name.padStart(5)} | ${p50} | ${p999} | ${tp} op/s`);
  }
}

function formatNs(ns: number): string {
  if (ns < 1_000) return `${ns}ns`.padStart(8);
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(2)}µs`.padStart(8);
  return `${(ns / 1_000_000).toFixed(2)}ms`.padStart(8);
}

main();
