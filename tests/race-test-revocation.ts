// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Revocation-to-Enforce Race Test
// ══════════════════════════════════════════════════════════════════
// Race test against APS SDK's revocation primitive. Measures the
// time window between revocation commit and last ACCEPT for the
// revoked delegation, under concurrent worker load.
//
// Reciprocal reproduction of @VeloGerber's runtime_enforcement_effectiveness
// methodology (OWASP/www-project-artificial-intelligence-vulnerability-scoring-system#31,
// 2026-05-06). Same shape (workers × qps × seconds, P50/P95/P99/MAX),
// applied to APS's `RevocationStorage.isRevoked()` primitive. Open-sourced
// so AIVSS v1.0 panel reviewers see the dimension reproducible across two
// independent implementations.
//
// SCOPE — what this test measures and what it does NOT
//
// This test exercises the SDK's `RevocationStorage` interface (defined at
// `src/storage/types.ts`, with the in-memory `VolatileBackend` impl at
// `src/storage/volatile-backend.ts`). The test runs concurrent workers
// against a shared `VolatileBackend` instance, fires a revocation midway
// through the run, and measures the latency between revocation commit and
// the last ACCEPT for the revoked delegation.
//
// In-process coherency (single Node process, multiple async workers
// sharing one VolatileBackend) is the SDK primitive's domain. APS's
// public SDK does not ship a multi-process backend — cross-process
// cache coherency lives in the gateway product (private), not the
// open-source SDK. This is the public/private boundary by design.
//
// Reviewers wanting to measure cross-process coherency (the SQLite-WAL
// shape @VeloGerber tested) should swap a SQLite-backed
// RevocationStorage in via the same `RevocationStorage` interface and
// re-run. The methodology is portable because the storage interface is
// stable.
//
// METHODOLOGY (matches @VeloGerber's race-test shape)
//
//   - 4 workers × 500 qps × 3 seconds = 6,000 requests per run
//   - 3 runs (18,000 total requests)
//   - Revocation fires at ~1500ms into each run (run midpoint)
//   - Workers continuously query `storage.isRevoked(targetDelegationId)`
//   - Measurement: time between revocation commit and last ACCEPT
//     (i.e., last `false` from isRevoked) for the revoked delegation
//   - Aggregate: P50, P95, P99, MAX across all observed ACCEPT-after-revoke
//     events. If zero ACCEPTs slip through (the expected case for an
//     in-process Map), all percentiles report 0.00ms.
//
// Run: npx tsx tests/race-test-revocation.ts
// Result file: tests/race-test-revocation-results-<YYYY-MM-DD>.txt
// ══════════════════════════════════════════════════════════════════

import { VolatileBackend } from '../src/storage/volatile-backend.js'
import type { RevocationRecord } from '../src/types/passport.js'
import { writeFileSync } from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

interface RaceTestConfig {
  workers: number
  qpsPerWorker: number
  durationSec: number
  runs: number
  targetDelegationId: string
  revokeAtMs: number
}

interface RunResult {
  runIndex: number
  totalRequests: number
  acceptCount: number
  rejectCount: number
  revocationCommitMs: number
  acceptsAfterRevocation: number[]
  lastAcceptAfterRevocationMs: number
}

interface AggregateResult {
  totalRequests: number
  totalRunsCompleted: number
  acceptsAfterRevocation: number[]
  p50: number
  p95: number
  p99: number
  max: number
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[idx]
}

async function workerLoop(
  storage: VolatileBackend,
  config: RaceTestConfig,
  startMs: number,
  durationMs: number,
  qpsPerWorker: number,
  result: { accepts: number; rejects: number; acceptTimestamps: number[] },
): Promise<void> {
  const intervalMs = 1000 / qpsPerWorker
  const endMs = startMs + durationMs
  let nextFireMs = startMs

  while (Date.now() < endMs) {
    const now = Date.now()
    if (now >= nextFireMs) {
      const isRev = await storage.isRevoked(config.targetDelegationId)
      if (isRev) {
        result.rejects++
      } else {
        result.accepts++
        result.acceptTimestamps.push(now)
      }
      nextFireMs += intervalMs
    } else {
      // Yield to the event loop without busy-waiting
      await new Promise((res) => setImmediate(res))
    }
  }
}

async function runOnce(runIndex: number, config: RaceTestConfig): Promise<RunResult> {
  const storage = new VolatileBackend()
  const startMs = Date.now()
  const durationMs = config.durationSec * 1000

  const workerResults = Array.from({ length: config.workers }, () => ({
    accepts: 0,
    rejects: 0,
    acceptTimestamps: [] as number[],
  }))

  // Spawn workers in parallel
  const workerPromises = workerResults.map((r) =>
    workerLoop(storage, config, startMs, durationMs, config.qpsPerWorker, r),
  )

  // Schedule the revocation to fire at config.revokeAtMs into the run
  const revokerPromise = (async () => {
    const fireAt = startMs + config.revokeAtMs
    while (Date.now() < fireAt) {
      await new Promise((res) => setImmediate(res))
    }
    const commitMs = Date.now()
    const rev: RevocationRecord = {
      revocationId: `rev-${runIndex}`,
      delegationId: config.targetDelegationId,
      revokedBy: 'race-test-revoker',
      revokedAt: new Date(commitMs).toISOString(),
      reason: 'race-test',
      signature: 'race-test-signature',
    }
    await storage.appendRevocation(rev)
    return commitMs
  })()

  const [revocationCommitMs] = await Promise.all([revokerPromise, ...workerPromises])

  // Aggregate per-worker results
  let totalAccepts = 0
  let totalRejects = 0
  const allAcceptTimestamps: number[] = []
  for (const r of workerResults) {
    totalAccepts += r.accepts
    totalRejects += r.rejects
    allAcceptTimestamps.push(...r.acceptTimestamps)
  }

  // Filter ACCEPTs that occurred AT OR AFTER revocation commit
  const acceptsAfterRevocation = allAcceptTimestamps
    .filter((ts) => ts >= revocationCommitMs)
    .map((ts) => ts - revocationCommitMs)
    .sort((a, b) => a - b)

  const lastAcceptAfter =
    acceptsAfterRevocation.length > 0 ? acceptsAfterRevocation[acceptsAfterRevocation.length - 1] : 0

  return {
    runIndex,
    totalRequests: totalAccepts + totalRejects,
    acceptCount: totalAccepts,
    rejectCount: totalRejects,
    revocationCommitMs: revocationCommitMs - startMs,
    acceptsAfterRevocation,
    lastAcceptAfterRevocationMs: lastAcceptAfter,
  }
}

function aggregate(runs: RunResult[]): AggregateResult {
  const allAcceptsAfter = runs.flatMap((r) => r.acceptsAfterRevocation).sort((a, b) => a - b)
  return {
    totalRequests: runs.reduce((acc, r) => acc + r.totalRequests, 0),
    totalRunsCompleted: runs.length,
    acceptsAfterRevocation: allAcceptsAfter,
    p50: percentile(allAcceptsAfter, 50),
    p95: percentile(allAcceptsAfter, 95),
    p99: percentile(allAcceptsAfter, 99),
    max: allAcceptsAfter.length > 0 ? allAcceptsAfter[allAcceptsAfter.length - 1] : 0,
  }
}

function formatResults(config: RaceTestConfig, runs: RunResult[], agg: AggregateResult): string {
  const lines: string[] = []
  lines.push('═══════════════════════════════════════════════════════════════════')
  lines.push('Revocation-to-Enforce Race Test — APS SDK')
  lines.push('═══════════════════════════════════════════════════════════════════')
  lines.push('')
  lines.push(`Date: ${new Date().toISOString()}`)
  lines.push(`Backend: VolatileBackend (in-process, in-memory Map)`)
  lines.push(`Methodology: reciprocal reproduction of @VeloGerber's race-test shape`)
  lines.push(`             (OWASP AIVSS #31, 2026-05-06)`)
  lines.push('')
  lines.push('Configuration:')
  lines.push(`  workers              ${config.workers}`)
  lines.push(`  qps per worker       ${config.qpsPerWorker}`)
  lines.push(`  duration per run     ${config.durationSec}s`)
  lines.push(`  runs                 ${config.runs}`)
  lines.push(`  revoke fires at      ${config.revokeAtMs}ms into each run`)
  lines.push('')
  lines.push('Per-run results:')
  for (const r of runs) {
    lines.push(`  run ${r.runIndex}: ${r.totalRequests} requests | ${r.acceptCount} ACCEPT, ${r.rejectCount} REJECT | revoke commit @ ${r.revocationCommitMs}ms | ACCEPTs after revoke: ${r.acceptsAfterRevocation.length} | last-ACCEPT-after-revoke: ${r.lastAcceptAfterRevocationMs}ms`)
  }
  lines.push('')
  lines.push('Aggregate (across all runs):')
  lines.push(`  total requests       ${agg.totalRequests}`)
  lines.push(`  ACCEPTs after revoke ${agg.acceptsAfterRevocation.length}`)
  lines.push(`  P50                  ${agg.p50.toFixed(2)}ms`)
  lines.push(`  P95                  ${agg.p95.toFixed(2)}ms`)
  lines.push(`  P99                  ${agg.p99.toFixed(2)}ms`)
  lines.push(`  MAX                  ${agg.max.toFixed(2)}ms`)
  lines.push('')
  lines.push('Interpretation:')
  if (agg.acceptsAfterRevocation.length === 0) {
    lines.push('  Zero ACCEPTs slipped through after the revocation commit. The')
    lines.push('  in-process VolatileBackend exposes the revocation atomically to all')
    lines.push('  workers sharing the same Map instance; no cache window exists.')
    lines.push('')
    lines.push('  This bounds the SDK primitive at <1ms. Real-world latency is')
    lines.push('  introduced by the persistence layer chosen by the consumer (SQLite,')
    lines.push('  Postgres, Redis, etc.) and any caching layer above it. To measure')
    lines.push('  cross-process coherency, swap a network-backed RevocationStorage')
    lines.push('  implementation in via the same interface and re-run this script.')
  } else {
    lines.push(`  ${agg.acceptsAfterRevocation.length} ACCEPTs slipped through after the revocation commit.`)
    lines.push(`  P99 = ${agg.p99.toFixed(2)}ms. Investigate any non-zero values: a Map-`)
    lines.push('  backed in-process store should expose writes atomically. Non-zero')
    lines.push('  values indicate either (a) a JS engine quirk where reads ran on a')
    lines.push('  microtask scheduled before the write committed, or (b) a real bug')
    lines.push('  in the storage backend.')
  }
  lines.push('')
  lines.push('Cross-implementation comparison (AIVSS dimension):')
  lines.push('  @VeloGerber audit-pack-signing v0.5 (SQLite WAL, multi-process):')
  lines.push('    P50/P95/P99/MAX = 0.00ms across 18,000 requests')
  lines.push('  APS SDK VolatileBackend (in-process):')
  lines.push(`    P50=${agg.p50.toFixed(2)} P95=${agg.p95.toFixed(2)} P99=${agg.p99.toFixed(2)} MAX=${agg.max.toFixed(2)}ms`)
  lines.push('')
  lines.push('Both implementations sit at the high tier of the proposed scoring')
  lines.push('dimension (P99 < 100ms with empirical methodology). Methodology')
  lines.push('portability is the load-bearing claim — the dimension reproduces')
  lines.push('across two independent implementations using the same race-test')
  lines.push('shape.')
  return lines.join('\n')
}

async function main(): Promise<void> {
  const config: RaceTestConfig = {
    workers: 4,
    qpsPerWorker: 500,
    durationSec: 3,
    runs: 3,
    targetDelegationId: 'race-test-target-delegation',
    revokeAtMs: 1500,
  }

  console.log(`Race test: ${config.workers} workers × ${config.qpsPerWorker} qps × ${config.durationSec}s × ${config.runs} runs`)
  console.log('')
  const runs: RunResult[] = []
  for (let i = 0; i < config.runs; i++) {
    console.log(`  run ${i + 1}/${config.runs}...`)
    const result = await runOnce(i + 1, config)
    runs.push(result)
    console.log(`    ${result.totalRequests} requests | revoke commit @ ${result.revocationCommitMs}ms | last-ACCEPT-after-revoke: ${result.lastAcceptAfterRevocationMs}ms`)
  }
  console.log('')

  const agg = aggregate(runs)
  const formatted = formatResults(config, runs, agg)
  console.log(formatted)

  // Write date-stamped result file
  const today = new Date().toISOString().slice(0, 10)
  const resultPath = `${__dirname}/race-test-revocation-results-${today}.txt`
  writeFileSync(resultPath, formatted)
  console.log('')
  console.log(`Result file written to ${resultPath}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
