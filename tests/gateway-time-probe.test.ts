// ══════════════════════════════════════════════════════════════════
// Gateway HLC Time + Fidelity Probe Scheduling — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: hybrid logical clock timestamps on results, turn counting,
// fidelity probe scheduling (turn interval, substrate change detection),
// and probe callback firing.
// Wires time.ts and fidelity-probe scheduling into the gateway.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import { aggregateFidelityScores, createFidelityAttestation } from '../src/core/fidelity-probe.js'
import type { GatewayConfig } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(__dirname + '/../values/floor.yaml', 'utf-8')
const floor = loadFloor(floorYaml)

function createTimeProbeSetup(opts: {
  enableHybridTimestamps?: boolean
  enableFidelityGating?: boolean
  turnInterval?: number
  onProbeRequired?: (agentId: string, reason: string) => void
}) {
  clearStores()
  const gwKeys = generateKeyPair()
  const measurer = generateKeyPair()
  const principal = joinSocialContract({
    name: 'tp-principal', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })
  const agent = joinSocialContract({
    name: 'tp-agent', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })
  const del = delegate({
    from: principal, toPublicKey: agent.publicKey,
    scope: ['data_read'], spendLimit: 1000,
    maxDepth: 2, expiresInHours: 1,
  })

  const config: GatewayConfig = {
    gatewayId: 'gw-tp-test',
    gatewayPublicKey: gwKeys.publicKey,
    gatewayPrivateKey: gwKeys.privateKey,
    floor,
    enableHybridTimestamps: opts.enableHybridTimestamps,
    enableFidelityGating: opts.enableFidelityGating,
    fidelityDefaultPolicy: 'warn',
    probeSchedule: opts.turnInterval !== undefined ? {
      onDelegation: true,
      turnInterval: opts.turnInterval,
      onSubstrateChange: true,
      highStakesTurnInterval: Math.max(1, Math.floor((opts.turnInterval ?? 6) / 2)),
    } : undefined,
    onProbeRequired: opts.onProbeRequired,
  }
  const gateway = createProxyGateway(config, async () => ({ success: true, result: {} }))
  gateway.registerAgent(agent.passport, agent.attestation, [del])

  let reqCounter = 0
  function makeRequest() {
    const requestId = `tp-req-${++reqCounter}-${Date.now()}`
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

  return { gateway, agent, measurer, makeRequest }
}

// ── HLC Timestamp Tests ──

describe('Gateway HLC Time — Hybrid Timestamps', () => {
  it('attaches HLC timestamp to successful result when enabled', async () => {
    const { gateway, makeRequest } = createTimeProbeSetup({
      enableHybridTimestamps: true,
    })
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, true)
    assert.ok(result.hlcTimestamp, 'Should have HLC timestamp')
    assert.ok(result.hlcTimestamp.logicalTime > 0, 'Logical time should be positive')
    assert.ok(result.hlcTimestamp.wallClockEarliest > 0, 'Wall clock earliest should be set')
    assert.ok(result.hlcTimestamp.wallClockLatest >= result.hlcTimestamp.wallClockEarliest)
    assert.strictEqual(result.hlcTimestamp.gatewayId, 'gw-tp-test')
  })

  it('HLC timestamps increase monotonically across calls', async () => {
    const { gateway, makeRequest } = createTimeProbeSetup({
      enableHybridTimestamps: true,
    })
    const r1 = await gateway.processToolCall(makeRequest())
    const r2 = await gateway.processToolCall(makeRequest())
    assert.ok(r1.hlcTimestamp && r2.hlcTimestamp)
    assert.ok(r2.hlcTimestamp.logicalTime > r1.hlcTimestamp.logicalTime,
      'Second call should have higher logical time')
  })

  it('no HLC timestamp when disabled', async () => {
    const { gateway, makeRequest } = createTimeProbeSetup({
      enableHybridTimestamps: false,
    })
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, true)
    assert.strictEqual(result.hlcTimestamp, undefined)
  })
})

// ── Probe Scheduling Tests ──

describe('Gateway Fidelity Probe — Scheduling', () => {
  it('fires probe callback at turn interval', async () => {
    const probes: { agentId: string; reason: string }[] = []
    const { gateway, agent, measurer, makeRequest } = createTimeProbeSetup({
      enableFidelityGating: true,
      turnInterval: 3,
      onProbeRequired: (agentId, reason) => probes.push({ agentId, reason }),
    })
    // Set a fidelity attestation so we don't get denied
    const fidelity = aggregateFidelityScores([
      { challengeId: 'fc-001', outcome: 'hold', score: 1.0, confidence: 0.9, method: 'test' },
    ])
    gateway.setFidelityAttestation(agent.agentId, createFidelityAttestation(
      agent.agentId, fidelity,
      { id: `did:aps:${measurer.publicKey.slice(0, 32)}`, privateKey: measurer.privateKey },
    ))

    // Turns 1, 2: no probe
    await gateway.processToolCall(makeRequest())
    await gateway.processToolCall(makeRequest())
    assert.strictEqual(probes.length, 0, 'No probe before interval')

    // Turn 3: probe fires
    await gateway.processToolCall(makeRequest())
    assert.strictEqual(probes.length, 1, 'Probe should fire at turn 3')
    assert.strictEqual(probes[0].agentId, agent.agentId)
    assert.strictEqual(probes[0].reason, 'turn_interval')
  })

  it('fires probe on substrate change', async () => {
    const probes: { agentId: string; reason: string }[] = []
    const { gateway, agent, measurer, makeRequest } = createTimeProbeSetup({
      enableFidelityGating: true,
      turnInterval: 100,  // high interval so it won't fire on turns
      onProbeRequired: (agentId, reason) => probes.push({ agentId, reason }),
    })

    // Set initial attestation on substrate A
    const fidelityA = aggregateFidelityScores([
      { challengeId: 'fc-001', outcome: 'hold', score: 1.0, confidence: 0.9, method: 'test' },
    ], 'claude-3-opus')
    gateway.setFidelityAttestation(agent.agentId, createFidelityAttestation(
      agent.agentId, fidelityA,
      { id: `did:aps:${measurer.publicKey.slice(0, 32)}`, privateKey: measurer.privateKey },
    ))

    // Turn 1: establishes lastKnownSubstrate
    await gateway.processToolCall(makeRequest())

    // Change substrate
    const fidelityB = aggregateFidelityScores([
      { challengeId: 'fc-001', outcome: 'hold', score: 0.9, confidence: 0.9, method: 'test' },
    ], 'gpt-4o-mini')
    gateway.setFidelityAttestation(agent.agentId, createFidelityAttestation(
      agent.agentId, fidelityB,
      { id: `did:aps:${measurer.publicKey.slice(0, 32)}`, privateKey: measurer.privateKey },
    ))

    // Turn 2: detects substrate change
    await gateway.processToolCall(makeRequest())
    assert.ok(probes.length > 0, 'Probe should fire on substrate change')
    assert.strictEqual(probes[probes.length - 1].reason, 'substrate_change')
  })

  it('does not fire probe when fidelity gating disabled', async () => {
    const probes: string[] = []
    const { gateway, makeRequest } = createTimeProbeSetup({
      enableFidelityGating: false,
      turnInterval: 1,
      onProbeRequired: (agentId) => probes.push(agentId),
    })
    await gateway.processToolCall(makeRequest())
    await gateway.processToolCall(makeRequest())
    assert.strictEqual(probes.length, 0, 'No probes when fidelity gating disabled')
  })

  it('does not fire probe when no callback configured', async () => {
    const { gateway, agent, measurer, makeRequest } = createTimeProbeSetup({
      enableFidelityGating: true,
      turnInterval: 1,
      // onProbeRequired NOT set
    })
    const fidelity = aggregateFidelityScores([
      { challengeId: 'fc-001', outcome: 'hold', score: 1.0, confidence: 0.9, method: 'test' },
    ])
    gateway.setFidelityAttestation(agent.agentId, createFidelityAttestation(
      agent.agentId, fidelity,
      { id: `did:aps:${measurer.publicKey.slice(0, 32)}`, privateKey: measurer.privateKey },
    ))
    // Should not throw even without callback
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, true)
  })
})
