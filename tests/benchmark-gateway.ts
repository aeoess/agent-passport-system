// ══════════════════════════════════════════════════════════════════
// Gateway Latency Benchmark
// ══════════════════════════════════════════════════════════════════
// Consilium Priority 7 — Claude: "2 hours of work, pays dividends
// forever. When a competitor claims faster, you need data."
//
// Measures p50/p95/p99 latency across:
//   - Different delegation chain depths (1, 2, 3)
//   - Different constraint configurations (minimal, standard, full)
//   - Sequential vs burst patterns
//
// Run: npx tsx tests/benchmark-gateway.ts
// ══════════════════════════════════════════════════════════════════

import { createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import { readFileSync } from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'
import type { GatewayConfig } from '../src/types/gateway.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(__dirname + '/../values/floor.yaml', 'utf-8')
const floor = loadFloor(floorYaml)

// ── Percentile calculation ──
function percentile(sorted: number[], p: number): number {
  const idx = Math.ceil((p / 100) * sorted.length) - 1
  return sorted[Math.max(0, idx)]
}

function formatStats(timings: number[]): string {
  const sorted = [...timings].sort((a, b) => a - b)
  const p50 = percentile(sorted, 50)
  const p95 = percentile(sorted, 95)
  const p99 = percentile(sorted, 99)
  const mean = timings.reduce((a, b) => a + b, 0) / timings.length
  const min = sorted[0]
  const max = sorted[sorted.length - 1]
  return `  p50=${p50.toFixed(3)}ms  p95=${p95.toFixed(3)}ms  p99=${p99.toFixed(3)}ms  mean=${mean.toFixed(3)}ms  min=${min.toFixed(3)}ms  max=${max.toFixed(3)}ms`
}

// ── Setup helpers ──
function setupGateway(opts: {
  enableReputation?: boolean
  enableFidelity?: boolean
  enableHLC?: boolean
  enableData?: boolean
}): {
  gateway: ReturnType<typeof createProxyGateway>
  makeRequest: () => any
} {
  clearStores()
  const gwKeys = generateKeyPair()
  const principal = joinSocialContract({
    name: 'bench-principal', mission: 'Benchmark', owner: 'admin',
    capabilities: ['data_read', 'data_write'], platform: 'node', models: ['test'], floor,
  })
  const agent = joinSocialContract({
    name: 'bench-agent', mission: 'Benchmark', owner: 'admin',
    capabilities: ['data_read', 'data_write'], platform: 'node', models: ['test'], floor,
  })
  const del = delegate({
    from: principal, toPublicKey: agent.publicKey,
    scope: ['data_read', 'data_write'], spendLimit: 10000,
    maxDepth: 3, expiresInHours: 1,
  })

  const config: GatewayConfig = {
    gatewayId: 'gw-bench',
    gatewayPublicKey: gwKeys.publicKey,
    gatewayPrivateKey: gwKeys.privateKey,
    floor,
    enableReputationGating: opts.enableReputation,
    enableFidelityGating: opts.enableFidelity,
    enableHybridTimestamps: opts.enableHLC,
    enableDataEnforcement: opts.enableData,
  }

  const gateway = createProxyGateway(config, async () => ({ success: true, result: {} }))
  gateway.registerAgent(agent.passport, agent.attestation, [del])

  let counter = 0
  function makeRequest() {
    const requestId = `bench-${++counter}-${Date.now()}`
    const payload = canonicalize({
      requestId, agentId: agent.agentId, tool: 'data_read',
      params: {}, scopeRequired: 'data_read',
    })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
      tool: 'data_read', params: {}, scopeRequired: 'data_read',
      signature: sign(payload, agent.keyPair.privateKey),
    }
  }

  return { gateway, makeRequest }
}

// ── Benchmark runner ──
async function runBenchmark(
  name: string,
  gateway: ReturnType<typeof createProxyGateway>,
  makeRequest: () => any,
  iterations: number,
): Promise<number[]> {
  // Warmup: 10 iterations
  for (let i = 0; i < 10; i++) {
    await gateway.processToolCall(makeRequest())
  }

  const timings: number[] = []
  for (let i = 0; i < iterations; i++) {
    const start = performance.now()
    await gateway.processToolCall(makeRequest())
    const elapsed = performance.now() - start
    timings.push(elapsed)
  }

  console.log(`\n${name} (${iterations} iterations):`)
  console.log(formatStats(timings))
  return timings
}

// ── Main ──
async function main() {
  const ITERATIONS = 500

  console.log('═══════════════════════════════════════════════════')
  console.log('  APS Gateway Latency Benchmark')
  console.log(`  ${new Date().toISOString()}`)
  console.log(`  ${ITERATIONS} iterations per scenario (+ 10 warmup)`)
  console.log('═══════════════════════════════════════════════════')

  // Scenario 1: Minimal — just signature + scope check
  const s1 = setupGateway({})
  await runBenchmark('Minimal (sig + scope only)', s1.gateway, s1.makeRequest, ITERATIONS)

  // Scenario 2: Standard — sig + scope + reputation + HLC
  const s2 = setupGateway({ enableReputation: true, enableHLC: true })
  await runBenchmark('Standard (sig + scope + rep + HLC)', s2.gateway, s2.makeRequest, ITERATIONS)

  // Scenario 3: Full — all enforcement enabled
  const s3 = setupGateway({
    enableReputation: true, enableHLC: true,
    enableFidelity: true, enableData: true,
  })
  await runBenchmark('Full (all enforcement)', s3.gateway, s3.makeRequest, ITERATIONS)

  // Scenario 4: Burst — 100 rapid sequential calls
  const s4 = setupGateway({ enableReputation: true, enableHLC: true })
  const burstTimings: number[] = []
  const burstStart = performance.now()
  for (let i = 0; i < 100; i++) {
    const t0 = performance.now()
    await s4.gateway.processToolCall(s4.makeRequest())
    burstTimings.push(performance.now() - t0)
  }
  const burstTotal = performance.now() - burstStart
  console.log(`\nBurst (100 rapid sequential):`)
  console.log(formatStats(burstTimings))
  console.log(`  total=${burstTotal.toFixed(1)}ms  throughput=${(100 / (burstTotal / 1000)).toFixed(0)} ops/sec`)

  // Scenario 5: Denied — action that gets blocked (spend exceeded)
  const s5 = setupGateway({ enableReputation: true })
  const deniedTimings: number[] = []
  for (let i = 0; i < 10; i++) {
    await s5.gateway.processToolCall(s5.makeRequest()) // warmup
  }
  for (let i = 0; i < ITERATIONS; i++) {
    // Create a request with excess spend
    const req = s5.makeRequest()
    req.spend = { amount: 99999, currency: 'USD' }
    const t0 = performance.now()
    await s5.gateway.processToolCall(req)
    deniedTimings.push(performance.now() - t0)
  }
  console.log(`\nDenied path (spend exceeded):`)
  console.log(formatStats(deniedTimings))

  console.log('\n═══════════════════════════════════════════════════')
  console.log('  Benchmark complete')
  console.log('═══════════════════════════════════════════════════')
}

main().catch(console.error)
