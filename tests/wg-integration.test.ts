// ══════════════════════════════════════════════════════════════════
// WG Cross-Project Integration Test Harness
// ══════════════════════════════════════════════════════════════════
// Proves the 4-spec WG stack works end-to-end across 5+ projects.
//
// APS provides steps 1, 3, 5, 7, 8.
// Steps 2, 4, 6 define interfaces for AgentID, qntm, ArkForge.
// Each project fills in their implementation; stubs included for
// standalone testing.
//
// Run: npx tsx --test tests/wg-integration.test.ts
// ══════════════════════════════════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign, verify } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { createDID } from '../src/core/did.js'
import { createPrincipalIdentity, endorseAgent } from '../src/core/principal.js'
import { createProxyGateway } from '../src/core/gateway.js'
import { classifyEvidence, resolveAuthorityTier, updateReputationFromResult } from '../src/core/reputation-authority.js'
import type { ScopedReputation } from '../src/types/reputation-authority.js'
import { clearStores } from '../src/core/delegation.js'
import type { ToolCallRequest, ToolExecutor, GatewayConfig } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../values/floor.yaml'), 'utf-8')

// ══════════════════════════════════════════════════════════════════
// CROSS-PROJECT INTERFACES
// Each project implements their interface. Stubs provided for
// standalone APS testing.
// ══════════════════════════════════════════════════════════════════

/** Step 2: Runtime verification — OATR / AgentID fills this in */
interface RuntimeVerification {
  agentDID: string
  runtimeId: string
  verified: boolean
  verificationMethod: 'oatr_registry' | 'agentid_trust_level' | 'self_attested'
  trustLevel?: number          // AgentID L0-L4
  oatrIssuerId?: string        // OATR issuer ID
  timestamp: string
  signature: string            // Signed by the verifying party
}

interface RuntimeVerifier {
  verify(agentDID: string, agentPublicKey: string): Promise<RuntimeVerification>
}

/** Step 4: Encrypted channel — qntm fills this in */
interface EncryptedChannel {
  channelId: string
  senderDID: string
  receiverDID: string
  protocol: 'qsp-1' | 'direct'
  encrypted: boolean
  send(payload: unknown): Promise<{ delivered: boolean; relayReceipt?: string }>
  close(): Promise<void>
}

interface ChannelProvider {
  openChannel(senderDID: string, senderKey: string, receiverDID: string, receiverKey: string): Promise<EncryptedChannel>
}

/** Step 6: Execution attestation — ArkForge / desiorac fills this in */
interface ExecutionAttestation {
  attestationId: string
  agentIdentity: string        // DID of the executing agent
  agentIdentityVerified: boolean
  toolName: string
  paramsHash: string           // SHA-256 of canonicalized params
  resultHash: string           // SHA-256 of canonicalized result
  chainHash: string            // Links to previous attestation
  timestamp: string
  proxySignature: string       // Certifying proxy signature
  authorizationRef?: string    // APS delegation chain reference
}

interface AttestationProvider {
  attest(execution: {
    agentDID: string; tool: string; params: unknown;
    result: unknown; delegationId: string; gatewaySignature: string;
  }): Promise<ExecutionAttestation>
}

// ══════════════════════════════════════════════════════════════════
// STUB IMPLEMENTATIONS
// Used when running standalone. Replace with real project code.
// ══════════════════════════════════════════════════════════════════

function createStubVerifier(verifierKeys: { publicKey: string; privateKey: string }): RuntimeVerifier {
  return {
    async verify(agentDID: string, _agentPublicKey: string): Promise<RuntimeVerification> {
      const payload = canonicalize({ agentDID, verified: true, timestamp: new Date().toISOString() })
      return {
        agentDID,
        runtimeId: 'stub-runtime-v1',
        verified: true,
        verificationMethod: 'oatr_registry',
        oatrIssuerId: 'oatr-stub-001',
        timestamp: new Date().toISOString(),
        signature: sign(payload, verifierKeys.privateKey)
      }
    }
  }
}

function createStubChannelProvider(): ChannelProvider {
  return {
    async openChannel(senderDID, _senderKey, receiverDID, _receiverKey): Promise<EncryptedChannel> {
      const messages: unknown[] = []
      return {
        channelId: `qsp1-${Date.now()}`,
        senderDID, receiverDID,
        protocol: 'qsp-1',
        encrypted: true,
        async send(payload) { messages.push(payload); return { delivered: true, relayReceipt: `relay-${Date.now()}` } },
        async close() { /* cleanup */ }
      }
    }
  }
}

function createStubAttestationProvider(proxyKeys: { publicKey: string; privateKey: string }): AttestationProvider {
  let chainHash = '0'.repeat(64) // genesis
  return {
    async attest(exec): Promise<ExecutionAttestation> {
      const paramsHash = Buffer.from(canonicalize(exec.params)).toString('base64').slice(0, 44)
      const resultHash = Buffer.from(canonicalize(exec.result)).toString('base64').slice(0, 44)
      const attestation: ExecutionAttestation = {
        attestationId: `att-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        agentIdentity: exec.agentDID,
        agentIdentityVerified: true,
        toolName: exec.tool,
        paramsHash,
        resultHash,
        chainHash,
        timestamp: new Date().toISOString(),
        proxySignature: sign(canonicalize({ paramsHash, resultHash, chainHash }), proxyKeys.privateKey),
        authorizationRef: exec.delegationId
      }
      chainHash = Buffer.from(canonicalize(attestation)).toString('base64').slice(0, 44)
      return attestation
    }
  }
}

// ══════════════════════════════════════════════════════════════════
// TOOL EXECUTOR — simulates a real service behind the gateway
// ══════════════════════════════════════════════════════════════════

function createServiceExecutor(): ToolExecutor {
  return async (tool: string, params: Record<string, unknown>) => {
    // Simulate a cloud service responding to authorized requests
    if (tool === 'cloud:provision') {
      return { success: true, result: { instanceId: `i-${Date.now()}`, region: params.region || 'us-east-1', cost: 47.50 } }
    }
    if (tool === 'data:query') {
      return { success: true, result: { rows: 142, queryTime: '23ms', dataset: params.dataset } }
    }
    return { success: true, result: { tool, echo: params } }
  }
}

// ══════════════════════════════════════════════════════════════════
// THE INTEGRATION TEST
// 8 steps. 5 projects. 4 specs. One end-to-end flow.
// ══════════════════════════════════════════════════════════════════

describe('WG Cross-Project Integration Test', () => {
  const floor = loadFloor(floorYaml)

  // Configurable: swap stubs with real implementations
  let runtimeVerifier: RuntimeVerifier
  let channelProvider: ChannelProvider
  let attestationProvider: AttestationProvider

  // Keys for all participants
  const principalKeys = generateKeyPair()
  const agentKeys = generateKeyPair()
  const serviceAgentKeys = generateKeyPair()
  const gatewayKeys = generateKeyPair()
  const verifierKeys = generateKeyPair()

  beforeEach(() => {
    clearStores()
    runtimeVerifier = createStubVerifier(verifierKeys)
    channelProvider = createStubChannelProvider()
    attestationProvider = createStubAttestationProvider(gatewayKeys)
  })

  it('full pipeline: identity → delegation → channel → execution → attestation → receipt → reputation', async () => {
    // ════════════════════════════════════════════════════
    // STEP 1: Agent generates identity (APS)
    // Spec: DID Resolution v1.0
    // ════════════════════════════════════════════════════
    const agent = joinSocialContract({
      name: 'Integration Test Agent',
      mission: 'Cross-project WG integration test',
      owner: 'wg-harness',
      capabilities: ['cloud:provision', 'data:query'],
      platform: 'test',
      models: ['test-model'],
      floor
    })
    const agentDID = createDID(agent.keyPair.publicKey)

    assert.ok(agent.passport, 'Step 1: agent passport created')
    assert.ok(agent.agentId, 'Step 1: agent has unique ID')
    assert.ok(agentDID.startsWith('did:'), 'Step 1: DID resolves')

    // Principal identity — links agent to a human
    const principal = joinSocialContract({
      name: 'Test Principal (Human)',
      mission: 'Authorize the test agent',
      owner: 'wg-harness',
      capabilities: ['cloud:provision', 'data:query'],
      platform: 'test',
      models: ['human'],
      floor
    })
    const principalDID = createDID(principal.keyPair.publicKey)

    console.log(`  ✓ Step 1: Identity — agent=${agent.agentId.slice(0,12)}… DID=${agentDID}`)

    // ════════════════════════════════════════════════════
    // STEP 2: Runtime verification (OATR / AgentID)
    // Spec: Entity Verification v1.0
    // ════════════════════════════════════════════════════
    const verification = await runtimeVerifier.verify(agentDID, agent.keyPair.publicKey)

    assert.ok(verification.verified, 'Step 2: runtime verified')
    assert.ok(verification.signature, 'Step 2: verification is signed')
    assert.equal(verification.agentDID, agentDID, 'Step 2: DID matches')

    console.log(`  ✓ Step 2: Runtime verified — method=${verification.verificationMethod}`)

    // ════════════════════════════════════════════════════
    // STEP 3: Principal signs scoped delegation (APS)
    // Spec: Entity Verification v1.0 (delegation binding)
    // ════════════════════════════════════════════════════
    const delegation = delegate({
      from: principal,
      toPublicKey: agent.keyPair.publicKey,
      scope: ['cloud:provision', 'data:query'],
      spendLimit: 200,
      maxDepth: 2
    })

    assert.ok(delegation, 'Step 3: delegation created')
    assert.ok(delegation.delegationId, 'Step 3: delegation has ID')
    assert.deepEqual(delegation.scope, ['cloud:provision', 'data:query'], 'Step 3: scope matches')
    assert.equal(delegation.spendLimit, 200, 'Step 3: spend limit $200')

    console.log(`  ✓ Step 3: Delegation — id=${delegation.delegationId.slice(0,12)}… scope=[cloud:provision,data:query] spend=$200`)

    // ════════════════════════════════════════════════════
    // STEP 4: Encrypted channel to service agent (qntm)
    // Spec: QSP-1 v1.0
    // ════════════════════════════════════════════════════
    const serviceAgent = joinSocialContract({
      name: 'Cloud Service Agent',
      mission: 'Provide cloud provisioning',
      owner: 'service-provider',
      capabilities: ['cloud:provision'],
      platform: 'test',
      models: ['service-model'],
      floor
    })
    const serviceDID = createDID(serviceAgent.keyPair.publicKey)

    const channel = await channelProvider.openChannel(
      agentDID, agent.keyPair.publicKey,
      serviceDID, serviceAgent.keyPair.publicKey
    )

    assert.ok(channel.channelId, 'Step 4: channel opened')
    assert.equal(channel.protocol, 'qsp-1', 'Step 4: QSP-1 protocol')
    assert.equal(channel.encrypted, true, 'Step 4: channel is encrypted')

    // Send the request over the encrypted channel
    const channelResult = await channel.send({
      type: 'tool_call_request',
      tool: 'cloud:provision',
      params: { region: 'us-east-1', instance: 't3.medium' },
      delegationId: delegation.delegationId,
      agentDID
    })
    assert.ok(channelResult.delivered, 'Step 4: request delivered')

    console.log(`  ✓ Step 4: Channel — id=${channel.channelId} protocol=${channel.protocol} encrypted=${channel.encrypted}`)

    // ════════════════════════════════════════════════════
    // STEP 5: Gateway enforcement check (APS)
    // The core enforcement boundary. 6 properties.
    // ════════════════════════════════════════════════════
    const gatewayConfig: GatewayConfig = {
      gatewayId: 'wg-integration-gw-001',
      gatewayPublicKey: gatewayKeys.publicKey,
      gatewayPrivateKey: gatewayKeys.privateKey,
      floor,
      approvalTTLSeconds: 30,
      recheckRevocationOnExecute: true
    }
    const gateway = createProxyGateway(gatewayConfig, createServiceExecutor())
    gateway.registerAgent(agent.passport, agent.attestation, [delegation])

    // Build signed request
    const requestId = `wg-int-${Date.now()}`
    const tool = 'cloud:provision'
    const params = { region: 'us-east-1', instance: 't3.medium' }
    const scopeRequired = 'cloud:provision'
    const spend = { amount: 47.50, currency: 'USD' }

    const requestPayload = canonicalize({
      requestId, agentId: agent.agentId, tool, params, scopeRequired, spend
    })

    const request: ToolCallRequest = {
      requestId,
      agentId: agent.agentId,
      agentPublicKey: agent.keyPair.publicKey,
      signature: sign(requestPayload, agent.keyPair.privateKey),
      tool, params, scopeRequired, spend,
      context: 'WG integration test — cloud provisioning'
    }

    const result = await gateway.processToolCall(request)

    assert.ok(result.executed, 'Step 5: gateway permitted execution')
    assert.ok(result.receipt, 'Step 5: gateway produced receipt')
    assert.ok(result.proof, 'Step 5: gateway produced proof chain')
    assert.ok(!result.denialReason, 'Step 5: no denial')

    console.log(`  ✓ Step 5: Gateway — executed=${result.executed} spend=$${spend.amount} receipt=${!!result.receipt}`)

    // ════════════════════════════════════════════════════
    // STEP 6: Execution attestation (ArkForge)
    // Spec: Execution Attestation v0.1
    // ════════════════════════════════════════════════════
    const attestation = await attestationProvider.attest({
      agentDID,
      tool,
      params,
      result: result.result,
      delegationId: delegation.delegationId,
      gatewaySignature: result.receipt!.signature
    })

    assert.ok(attestation.attestationId, 'Step 6: attestation created')
    assert.equal(attestation.agentIdentity, agentDID, 'Step 6: attestation references agent DID')
    assert.equal(attestation.agentIdentityVerified, true, 'Step 6: identity verified in attestation')
    assert.equal(attestation.toolName, tool, 'Step 6: tool name matches')
    assert.ok(attestation.proxySignature, 'Step 6: proxy signed (not self-reported)')
    assert.ok(attestation.authorizationRef, 'Step 6: authorization_ref present')

    console.log(`  ✓ Step 6: Attestation — id=${attestation.attestationId} tool=${attestation.toolName} chain=${attestation.chainHash.slice(0,12)}…`)

    // ════════════════════════════════════════════════════
    // STEP 7: Gateway-signed receipt verification (APS)
    // Receipt is generated by the enforcement boundary,
    // NOT by the agent. This is the trust anchor.
    // ════════════════════════════════════════════════════
    const receipt = result.receipt!

    assert.ok(receipt.signature, 'Step 7: receipt is signed')
    assert.ok(receipt.timestamp, 'Step 7: receipt has timestamp')
    assert.ok(receipt.receiptId, 'Step 7: receipt has ID')
    assert.ok(receipt.action.type.includes(tool), 'Step 7: receipt action references tool')
    assert.ok(receipt.delegationChain.length > 0, 'Step 7: receipt includes delegation chain')

    // The critical property: receipt is signed by the gateway (enforcement boundary),
    // NOT by the agent. The agent cannot forge or omit receipts.
    assert.ok(receipt.signature.length > 10, 'Step 7: signature is non-trivial')

    console.log(`  ✓ Step 7: Receipt — id=${receipt.receiptId} signed, chain=${receipt.delegationChain.length} keys`)

    // ════════════════════════════════════════════════════
    // STEP 8: Trust score update (APS)
    // Receipt-based evidence → reputation update.
    // authority = min(delegation, earnedTier)
    // ════════════════════════════════════════════════════

    // New agent starts at mu=25, sigma=25 → effective = 25 - 2*25 = -25 → tier 0
    const repBefore: ScopedReputation = {
      principalId: principal.agentId,
      agentId: agent.agentId,
      scope: 'cloud:provision',
      mu: 25, sigma: 25,
      receiptCount: 0,
      lastUpdatedAt: new Date().toISOString()
    }

    const effectiveBefore = repBefore.mu - 2 * repBefore.sigma
    const tierBefore = resolveAuthorityTier(effectiveBefore, 0)

    // Successful execution updates reputation
    const repAfter = updateReputationFromResult(repBefore, true, 'standard')

    assert.ok(repAfter, 'Step 8: reputation updated')
    assert.ok(repAfter.mu > repBefore.mu, 'Step 8: mu increased after success')
    assert.ok(repAfter.sigma < repBefore.sigma, 'Step 8: sigma decreased (less uncertain)')
    assert.equal(repAfter.receiptCount, 1, 'Step 8: receipt count incremented')

    const effectiveAfter = repAfter.mu - 2 * repAfter.sigma
    const tierAfter = resolveAuthorityTier(effectiveAfter, 0)

    console.log(`  ✓ Step 8: Reputation — mu ${repBefore.mu}→${repAfter.mu} sigma ${repBefore.sigma}→${repAfter.sigma} effective ${effectiveBefore.toFixed(1)}→${effectiveAfter.toFixed(1)} tier ${tierBefore.tier}→${tierAfter.tier}`)

    // Close the encrypted channel
    await channel.close()

    console.log('\n  ══════════════════════════════════════════════════')
    console.log('  ✅ FULL PIPELINE PASSED — 8 steps, 4 specs, end-to-end')
    console.log('  ══════════════════════════════════════════════════')
  })

  // ══════════════════════════════════════════════════════════════════
  // NEGATIVE TEST: Gateway denies out-of-scope request
  // Proves enforcement actually blocks unauthorized actions.
  // ══════════════════════════════════════════════════════════════════
  it('denial: gateway rejects action outside delegation scope', async () => {
    clearStores()
    const floor = loadFloor(floorYaml)

    const principal = joinSocialContract({
      name: 'Scope Test Principal', mission: 'Test scope enforcement', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
    })
    const agent = joinSocialContract({
      name: 'Scope Test Agent', mission: 'Attempt unauthorized action', owner: 'tester',
      capabilities: ['data:read', 'admin:delete'], platform: 'test', models: ['test-model'], floor
    })

    // Delegation only grants data:read — NOT admin:delete
    const delegation = delegate({
      from: principal, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:read'], spendLimit: 50, maxDepth: 1
    })

    const gw = createProxyGateway({
      gatewayId: 'deny-test-gw', gatewayPublicKey: generateKeyPair().publicKey,
      gatewayPrivateKey: generateKeyPair().privateKey, floor,
      approvalTTLSeconds: 10, recheckRevocationOnExecute: true
    }, async () => ({ success: true, result: { deleted: true } }))

    gw.registerAgent(agent.passport, agent.attestation, [delegation])

    const reqId = `deny-${Date.now()}`
    const payload = canonicalize({
      requestId: reqId, agentId: agent.agentId,
      tool: 'admin:delete', params: { target: 'all-data' },
      scopeRequired: 'admin:delete', spend: undefined
    })

    const result = await gw.processToolCall({
      requestId: reqId, agentId: agent.agentId,
      agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool: 'admin:delete', params: { target: 'all-data' },
      scopeRequired: 'admin:delete', context: 'Attempt unauthorized delete'
    })

    assert.equal(result.executed, false, 'Denial: action was NOT executed')
    assert.ok(result.denialReason, 'Denial: reason provided')
    assert.ok(!result.receipt, 'Denial: no receipt generated for denied action')

    console.log(`  ✓ Denial test: scope=admin:delete denied. Reason: ${result.denialReason}`)
  })

  // ══════════════════════════════════════════════════════════════════
  // NEGATIVE TEST: Cascade revocation kills mid-pipeline
  // Proves revocation recheck at execution time (not just approval).
  // ══════════════════════════════════════════════════════════════════
  it('revocation: cascade revocation blocks execution after approval', async () => {
    clearStores()
    const floor = loadFloor(floorYaml)
    const { revokeDelegation } = await import('../src/core/delegation.js')

    const principal = joinSocialContract({
      name: 'Revoke Test Principal', mission: 'Test revocation', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
    })
    const agent = joinSocialContract({
      name: 'Revoke Test Agent', mission: 'Lose access mid-flight', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
    })

    const delegation = delegate({
      from: principal, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 1
    })

    const gwKeys = generateKeyPair()
    const gw = createProxyGateway({
      gatewayId: 'revoke-test-gw', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
      approvalTTLSeconds: 30, recheckRevocationOnExecute: true
    }, async () => ({ success: true, result: { rows: 42 } }))

    gw.registerAgent(agent.passport, agent.attestation, [delegation])

    // First call succeeds
    const reqId1 = `rev-ok-${Date.now()}`
    const payload1 = canonicalize({
      requestId: reqId1, agentId: agent.agentId,
      tool: 'data:read', params: { table: 'users' },
      scopeRequired: 'data:read', spend: undefined
    })
    const r1 = await gw.processToolCall({
      requestId: reqId1, agentId: agent.agentId,
      agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload1, agent.keyPair.privateKey),
      tool: 'data:read', params: { table: 'users' },
      scopeRequired: 'data:read', context: 'Before revocation'
    })
    assert.ok(r1.executed, 'Revocation: first call succeeds')

    // Now revoke the delegation
    revokeDelegation(delegation.delegationId, principal.keyPair.publicKey, 'Integration test revocation', principal.keyPair.privateKey)

    // Second call should be denied — revocation recheck at execution time
    const reqId2 = `rev-fail-${Date.now()}`
    const payload2 = canonicalize({
      requestId: reqId2, agentId: agent.agentId,
      tool: 'data:read', params: { table: 'users' },
      scopeRequired: 'data:read', spend: undefined
    })

    const r2 = await gw.processToolCall({
      requestId: reqId2, agentId: agent.agentId,
      agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload2, agent.keyPair.privateKey),
      tool: 'data:read', params: { table: 'users' },
      scopeRequired: 'data:read', context: 'After revocation'
    })

    assert.equal(r2.executed, false, 'Revocation: second call denied after revocation')
    assert.ok(r2.denialReason, 'Revocation: denial reason provided')

    console.log(`  ✓ Revocation test: first call executed=${r1.executed}, after revoke executed=${r2.executed}`)
    console.log(`    Denial reason: ${r2.denialReason}`)
  })

  // ══════════════════════════════════════════════════════════════════
  // SPEND LIMIT TEST: Gateway blocks overspend
  // ══════════════════════════════════════════════════════════════════
  it('spend limit: gateway blocks action exceeding delegation spend cap', async () => {
    clearStores()
    const floor = loadFloor(floorYaml)

    const principal = joinSocialContract({
      name: 'Spend Test Principal', mission: 'Test spend limits', owner: 'tester',
      capabilities: ['cloud:provision'], platform: 'test', models: ['test-model'], floor
    })
    const agent = joinSocialContract({
      name: 'Spend Test Agent', mission: 'Attempt overspend', owner: 'tester',
      capabilities: ['cloud:provision'], platform: 'test', models: ['test-model'], floor
    })

    // Delegation caps spend at $50
    const delegation = delegate({
      from: principal, toPublicKey: agent.keyPair.publicKey,
      scope: ['cloud:provision'], spendLimit: 50, maxDepth: 1
    })

    const gwKeys = generateKeyPair()
    const gw = createProxyGateway({
      gatewayId: 'spend-test-gw', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
      approvalTTLSeconds: 10, recheckRevocationOnExecute: true
    }, async () => ({ success: true, result: { cost: 500 } }))

    gw.registerAgent(agent.passport, agent.attestation, [delegation])

    // Try to spend $500 on a $50 delegation
    const reqId = `spend-${Date.now()}`
    const payload = canonicalize({
      requestId: reqId, agentId: agent.agentId,
      tool: 'cloud:provision', params: { tier: 'enterprise' },
      scopeRequired: 'cloud:provision', spend: { amount: 500, currency: 'USD' }
    })

    const result = await gw.processToolCall({
      requestId: reqId, agentId: agent.agentId,
      agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool: 'cloud:provision', params: { tier: 'enterprise' },
      scopeRequired: 'cloud:provision', spend: { amount: 500, currency: 'USD' },
      context: 'Attempt $500 on $50 delegation'
    })

    assert.equal(result.executed, false, 'Spend: $500 action blocked on $50 delegation')
    assert.ok(result.denialReason, 'Spend: denial reason provided')

    console.log(`  ✓ Spend limit test: $500 on $50 delegation — denied. Reason: ${result.denialReason}`)
  })
})
