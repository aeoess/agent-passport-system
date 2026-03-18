import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createTaintLabel, mergeTaints,
  createSAO, verifySAO, isSAOExpired,
  createExecutionFrame, recordAccess, closeFrame,
  verifyFrameChain, computeStepHash,
  isFrameExpired, rotateFrame,
  verifyEpochChain,
  createCrossChainPermit, countersignPermit,
  verifyCrossChainPermit, revokePermit,
  checkDataFlow,
  deriveSAO,
  createExecutionReceipt, verifyExecutionReceipt,
  createCrossChainViolation
} from '../src/index.js'

// Two principals: Alice (file owner) and Bob (email sender)
const alice = generateKeyPair()
const bob = generateKeyPair()
const monitor = generateKeyPair()

describe('Cross-Chain Data Flow Authorization', () => {

  // ── Taint Labels ──
  describe('Taint Labels', () => {
    it('should create a taint label with default usage', () => {
      const label = createTaintLabel('alice', 'chain-a', 'del-001')
      assert.equal(label.principalId, 'alice')
      assert.equal(label.usage, 'same-context-only')
      assert.ok(label.taintedAt)
    })

    it('should detect cross-chain taint when merging from different principals', () => {
      const labelA = createTaintLabel('alice', 'chain-a', 'del-001')
      const labelB = createTaintLabel('bob', 'chain-b', 'del-002')
      const taintSet = mergeTaints(labelA, labelB)

      assert.equal(taintSet.isCrossChain, true)
      assert.ok(taintSet.principals.includes('alice'))
      assert.ok(taintSet.principals.includes('bob'))
      assert.equal(taintSet.labels.length, 2)
    })

    it('should NOT be cross-chain when all labels from same principal', () => {
      const label1 = createTaintLabel('alice', 'chain-a', 'del-001')
      const label2 = createTaintLabel('alice', 'chain-a', 'del-003')
      const taintSet = mergeTaints(label1, label2)

      assert.equal(taintSet.isCrossChain, false)
      assert.deepStrictEqual(taintSet.principals, ['alice'])
    })
  })

  // ── Signed Authority Objects ──
  describe('Signed Authority Objects', () => {
    it('should create and verify an SAO', () => {
      const taint = createTaintLabel('alice', 'chain-a', 'del-001')
      const sao = createSAO('confidential data', taint, monitor.privateKey, monitor.publicKey)

      assert.equal(sao.data, 'confidential data')
      assert.equal(sao.taint.principalId, 'alice')
      assert.equal(verifySAO(sao), true)
    })

    it('should reject tampered SAO data', () => {
      const taint = createTaintLabel('alice', 'chain-a', 'del-001')
      const sao = createSAO('confidential data', taint, monitor.privateKey, monitor.publicKey)
      const tampered = { ...sao, data: 'modified data' }

      assert.equal(verifySAO(tampered), false)
    })
  })

  // ── Cross-Chain Permits ──
  describe('Cross-Chain Permits', () => {
    it('should create and countersign a permit', () => {
      const partial = createCrossChainPermit({
        sourcePrincipalId: 'alice',
        sourcePrincipalPublicKey: alice.publicKey,
        sourceDataClasses: ['calendar'],
        destPrincipalId: 'bob',
        destPrincipalPublicKey: bob.publicKey,
        destAllowedScopes: ['email:send'],
        purpose: 'Send calendar events via email',
        sourcePrivateKey: alice.privateKey
      })

      assert.ok(partial.sourceSignature)
      assert.equal(partial.destinationSignature, '')

      const permit = countersignPermit(partial, bob.privateKey)
      assert.ok(permit.destinationSignature)
      assert.equal(verifyCrossChainPermit(permit), true)
    })


    it('should reject permit with only source signature (not countersigned)', () => {
      const partial = createCrossChainPermit({
        sourcePrincipalId: 'alice',
        sourcePrincipalPublicKey: alice.publicKey,
        sourceDataClasses: ['files'],
        destPrincipalId: 'bob',
        destPrincipalPublicKey: bob.publicKey,
        destAllowedScopes: ['email:send'],
        purpose: 'Test',
        sourcePrivateKey: alice.privateKey
      })

      // Not countersigned — should be invalid
      assert.equal(verifyCrossChainPermit(partial as any), false)
    })

    it('should reject revoked permit', () => {
      const partial = createCrossChainPermit({
        sourcePrincipalId: 'alice',
        sourcePrincipalPublicKey: alice.publicKey,
        sourceDataClasses: ['files'],
        destPrincipalId: 'bob',
        destPrincipalPublicKey: bob.publicKey,
        destAllowedScopes: ['email:send'],
        purpose: 'Test',
        sourcePrivateKey: alice.privateKey
      })
      const permit = countersignPermit(partial, bob.privateKey)
      const revoked = revokePermit(permit)

      assert.equal(verifyCrossChainPermit(revoked), false)
    })
  })

  // ══════════════════════════════════════════════════════════════
  // CONFUSED DEPUTY ATTACK SCENARIOS
  // These are the core security tests for multi-principal defense
  // ══════════════════════════════════════════════════════════════

  describe('Confused Deputy Prevention', () => {

    it('ATTACK: read from Alice, send via Bob → BLOCKED', () => {
      // Agent reads Alice's file (tainted with Alice's context)
      const aliceTaint = createTaintLabel('alice', 'chain-a', 'del-001')
      const inputTaint = mergeTaints(aliceTaint)

      // Agent tries to send via Bob's email scope
      const result = checkDataFlow({
        inputTaint,
        actionPrincipalId: 'bob',
        actionScope: 'email:send',
        permits: []  // No cross-chain permits exist
      })

      assert.equal(result.verdict, 'blocked')
      assert.equal(result.blockingLabels.length, 1)
      assert.equal(result.blockingLabels![0].principalId, 'alice')
      assert.ok(result.reason.includes('alice'))
      assert.ok(result.reason.includes('bob'))
    })

    it('SAFE: read from Alice, send via Alice → ALLOWED', () => {
      // Same principal, same context — no confused deputy
      const aliceTaint = createTaintLabel('alice', 'chain-a', 'del-001')
      const inputTaint = mergeTaints(aliceTaint)

      const result = checkDataFlow({
        inputTaint,
        actionPrincipalId: 'alice',
        actionScope: 'email:send',
        permits: []
      })

      assert.equal(result.verdict, 'allowed')
    })

    it('PERMITTED: read from Alice, send via Bob WITH valid permit → PERMITTED', () => {
      const aliceTaint = createTaintLabel('alice', 'chain-a', 'del-001', 'export-with-permit')
      const inputTaint = mergeTaints(aliceTaint)

      // Both principals signed a cross-chain permit
      const partial = createCrossChainPermit({
        sourcePrincipalId: 'alice',
        sourcePrincipalPublicKey: alice.publicKey,
        sourceDataClasses: ['files'],
        destPrincipalId: 'bob',
        destPrincipalPublicKey: bob.publicKey,
        destAllowedScopes: ['email:send'],
        purpose: 'Authorized file sharing',
        sourcePrivateKey: alice.privateKey
      })
      const permit = countersignPermit(partial, bob.privateKey)

      const result = checkDataFlow({
        inputTaint,
        actionPrincipalId: 'bob',
        actionScope: 'email:send',
        permits: [permit]
      })

      assert.equal(result.verdict, 'permitted')
      assert.equal(result.permitId, permit.permitId)
    })

    it('ATTACK: permit exists but wrong scope → BLOCKED', () => {
      const aliceTaint = createTaintLabel('alice', 'chain-a', 'del-001')
      const inputTaint = mergeTaints(aliceTaint)

      // Permit only allows calendar:read, not email:send
      const partial = createCrossChainPermit({
        sourcePrincipalId: 'alice',
        sourcePrincipalPublicKey: alice.publicKey,
        sourceDataClasses: ['calendar'],
        destPrincipalId: 'bob',
        destPrincipalPublicKey: bob.publicKey,
        destAllowedScopes: ['calendar:read'],
        purpose: 'Calendar sharing only',
        sourcePrivateKey: alice.privateKey
      })
      const permit = countersignPermit(partial, bob.privateKey)

      const result = checkDataFlow({
        inputTaint,
        actionPrincipalId: 'bob',
        actionScope: 'email:send',  // Not in the permit!
        permits: [permit]
      })

      assert.equal(result.verdict, 'blocked')
    })

    it('ATTACK: read-only data used in outbound action → BLOCKED', () => {
      const aliceTaint = createTaintLabel('alice', 'chain-a', 'del-001', 'read-only')
      const inputTaint = mergeTaints(aliceTaint)

      const result = checkDataFlow({
        inputTaint,
        actionPrincipalId: 'alice',  // Even same principal!
        actionScope: 'email:send',
        permits: []
      })

      assert.equal(result.verdict, 'blocked')
      assert.ok(result.reason.includes('read-only'))
    })
  })

  // ══════════════════════════════════════════════════════════════
  // LAUNDERING PREVENTION — Execution Frame Taint
  // Even if the agent summarizes data, the frame remembers
  // ══════════════════════════════════════════════════════════════

  describe('Laundering Prevention (Execution Frame Taint)', () => {

    it('ATTACK: agent reads Alice data, outputs "clean" string via Bob → BLOCKED by frame taint', () => {
      // Agent starts a reasoning session
      let frame = createExecutionFrame('agent-001')

      // Agent reads Alice's file (frame gets tainted)
      const aliceTaint = createTaintLabel('alice', 'chain-a', 'del-001')
      frame = recordAccess(frame, aliceTaint)

      assert.ok(frame.frameTaint.principals.includes('alice'))

      // Agent "launders" the data by summarizing it
      // The output has NO SAO wrapper — just a raw string
      // But the frame remembers what was accessed

      // Agent tries to send the "clean" output via Bob
      // Input taint is empty (the string has no SAO)
      const cleanInputTaint = mergeTaints()  // No taint labels on the raw string

      const result = checkDataFlow({
        inputTaint: cleanInputTaint,
        actionPrincipalId: 'bob',
        actionScope: 'email:send',
        permits: [],
        frame  // Frame carries alice's taint!
      })

      // Frame taint catches the laundering attempt
      assert.equal(result.verdict, 'blocked')
      assert.equal(result.blockingLabels![0].principalId, 'alice')
    })

    it('SAFE: frame only accessed Bob data, send via Bob → ALLOWED', () => {
      let frame = createExecutionFrame('agent-001')

      const bobTaint = createTaintLabel('bob', 'chain-b', 'del-002')
      frame = recordAccess(frame, bobTaint)

      const result = checkDataFlow({
        inputTaint: mergeTaints(),
        actionPrincipalId: 'bob',
        actionScope: 'email:send',
        permits: [],
        frame
      })

      assert.equal(result.verdict, 'allowed')
    })

    it('ATTACK: multi-principal frame, no permits → BLOCKED', () => {
      let frame = createExecutionFrame('agent-001')

      // Agent reads from both Alice and Bob during same session
      frame = recordAccess(frame, createTaintLabel('alice', 'chain-a', 'del-001'))
      frame = recordAccess(frame, createTaintLabel('bob', 'chain-b', 'del-002'))

      assert.equal(frame.frameTaint.isCrossChain, true)

      // Any outbound action under either principal is blocked
      // because the frame contains data from the OTHER principal
      const result = checkDataFlow({
        inputTaint: mergeTaints(),
        actionPrincipalId: 'alice',
        actionScope: 'file:write',
        permits: [],
        frame
      })

      assert.equal(result.verdict, 'blocked')
      assert.equal(result.blockingLabels![0].principalId, 'bob')
    })

    it('should track frame accumulation correctly', () => {
      let frame = createExecutionFrame('agent-001')
      assert.equal(frame.accessedContexts.length, 0)
      assert.equal(frame.frameTaint.isCrossChain, false)

      frame = recordAccess(frame, createTaintLabel('alice', 'chain-a', 'del-001'))
      assert.equal(frame.accessedContexts.length, 1)
      assert.equal(frame.frameTaint.isCrossChain, false)

      frame = recordAccess(frame, createTaintLabel('bob', 'chain-b', 'del-002'))
      assert.equal(frame.accessedContexts.length, 2)
      assert.equal(frame.frameTaint.isCrossChain, true)
      assert.equal(frame.frameTaint.principals.length, 2)
    })
  })

  // ════════════════════════════════════════
  // DERIVED SAO (taint union on composed data)
  // ════════════════════════════════════════

  describe('deriveSAO', () => {
    it('should inherit taint from all source SAOs', () => {
      const saoAlice = createSAO(
        { from: 'alice-data' },
        createTaintLabel('alice', 'chain-a', 'del-001'),
        monitor.privateKey, monitor.publicKey
      )
      const saoBob = createSAO(
        { from: 'bob-data' },
        createTaintLabel('bob', 'chain-b', 'del-002'),
        monitor.privateKey, monitor.publicKey
      )

      const derived = deriveSAO(
        { combined: true },
        [saoAlice, saoBob],
        monitor.privateKey, monitor.publicKey
      )

      assert.ok(derived.saoId.includes('sao-derived-'))
      assert.equal(derived.taint.principalId, 'MULTI_PRINCIPAL')
      assert.equal(derived.taint.usage, 'export-with-permit')
      assert.equal(verifySAO(derived), true)
    })

    it('same-principal derivation keeps original context', () => {
      const sao1 = createSAO(
        { part: 1 },
        createTaintLabel('alice', 'chain-a', 'del-001'),
        monitor.privateKey, monitor.publicKey
      )
      const sao2 = createSAO(
        { part: 2 },
        createTaintLabel('alice', 'chain-a', 'del-001'),
        monitor.privateKey, monitor.publicKey
      )

      const derived = deriveSAO(
        { merged: true },
        [sao1, sao2],
        monitor.privateKey, monitor.publicKey
      )

      assert.equal(derived.taint.principalId, 'alice')
      assert.equal(derived.taint.usage, 'same-context-only')
    })
  })


  // ════════════════════════════════════════
  // EXECUTION RECEIPT (mediated execution proof)
  // ════════════════════════════════════════

  describe('ExecutionReceipt', () => {
    it('should create and verify a receipt for clean action', () => {
      const frame = createExecutionFrame('agent-001')
      const updatedFrame = recordAccess(frame, createTaintLabel('alice', 'chain-a', 'del-001'))

      const flowResult = checkDataFlow({
        inputTaint: updatedFrame.frameTaint,
        actionPrincipalId: 'alice',
        actionScope: 'data:read',
        permits: []
      })

      const receipt = createExecutionReceipt({
        frame: updatedFrame,
        requestHash: 'req-abc123',
        tool: 'database:read',
        params: { table: 'users' },
        delegationId: 'del-001',
        policyVersion: '1.0.0',
        flowResult,
        gatewayId: 'gateway-001',
        gatewayPrivateKey: monitor.privateKey
      })

      assert.ok(receipt.receiptId.includes('exreceipt-'))
      assert.equal(receipt.crossChainDetected, false)
      assert.equal(receipt.crossChainAuthorized, false)
      assert.ok(receipt.taintPrincipals.includes('alice'))

      const v = verifyExecutionReceipt(receipt, monitor.publicKey)
      assert.equal(v.valid, true)
      assert.equal(v.expired, false)
    })

    it('should reject receipt with wrong gateway key', () => {
      const frame = createExecutionFrame('agent-001')
      const updatedFrame = recordAccess(frame, createTaintLabel('alice', 'chain-a', 'del-001'))

      const flowResult = checkDataFlow({
        inputTaint: updatedFrame.frameTaint,
        actionPrincipalId: 'alice',
        actionScope: 'data:read',
        permits: []
      })

      const receipt = createExecutionReceipt({
        frame: updatedFrame,
        requestHash: 'req-xyz',
        tool: 'api:get',
        params: {},
        delegationId: 'del-001',
        policyVersion: '1.0.0',
        flowResult,
        gatewayId: 'gateway-001',
        gatewayPrivateKey: monitor.privateKey
      })

      const v = verifyExecutionReceipt(receipt, alice.publicKey)
      assert.equal(v.valid, false)
      assert.ok(v.error.includes('Invalid'))
    })

    it('should record cross-chain authorization in receipt', () => {
      let frame = createExecutionFrame('agent-001')
      frame = recordAccess(frame, createTaintLabel('alice', 'chain-a', 'del-001'))
      frame = recordAccess(frame, createTaintLabel('bob', 'chain-b', 'del-002'))

      const partial = createCrossChainPermit({
        sourcePrincipalId: 'alice',
        sourcePrincipalPublicKey: alice.publicKey,
        sourceDataClasses: ['*'],
        destPrincipalId: 'bob',
        destPrincipalPublicKey: bob.publicKey,
        destAllowedScopes: ['email:send'],
        purpose: 'test',
        sourcePrivateKey: alice.privateKey
      })
      const permit = countersignPermit(partial, bob.privateKey)

      const flowResult = checkDataFlow({
        inputTaint: frame.frameTaint,
        actionPrincipalId: 'bob',
        actionScope: 'email:send',
        permits: [permit],
        frame
      })

      const receipt = createExecutionReceipt({
        frame,
        requestHash: 'req-cross',
        tool: 'email:send',
        params: { to: 'cfo@company.com' },
        delegationId: 'del-002',
        policyVersion: '1.0.0',
        flowResult,
        gatewayId: 'gateway-001',
        gatewayPrivateKey: monitor.privateKey
      })

      assert.equal(receipt.crossChainDetected, true)
      assert.equal(receipt.crossChainAuthorized, true)
      assert.equal(receipt.permitId, permit.permitId)
      assert.ok(receipt.taintPrincipals.includes('alice'))
      assert.ok(receipt.taintPrincipals.includes('bob'))
    })
  })

  // ════════════════════════════════════════
  // CROSS-CHAIN VIOLATION (signed audit artifact)
  // ════════════════════════════════════════

  describe('CrossChainViolation', () => {
    it('should produce signed violation report on blocked flow', () => {
      let frame = createExecutionFrame('agent-001')
      frame = recordAccess(frame, createTaintLabel('alice', 'chain-a', 'del-001'))
      frame = recordAccess(frame, createTaintLabel('bob', 'chain-b', 'del-002'))

      const flowResult = checkDataFlow({
        inputTaint: frame.frameTaint,
        actionPrincipalId: 'bob',
        actionScope: 'email:send',
        permits: [],
        frame
      })

      assert.equal(flowResult.verdict, 'blocked')

      const violation = createCrossChainViolation({
        frame,
        agentId: 'agent-001',
        sourcePrincipalId: 'alice',
        destinationPrincipalId: 'bob',
        attemptedTool: 'email:send',
        attemptedScope: 'email:send',
        blockingLabels: flowResult.blockingLabels!,
        gatewayPrivateKey: monitor.privateKey
      })

      assert.equal(violation.frameId, frame.frameId)
      assert.equal(violation.sourcePrincipalId, 'alice')
      assert.equal(violation.destinationPrincipalId, 'bob')
      assert.equal(violation.attemptedTool, 'email:send')
      assert.ok(violation.gatewaySignature)
      assert.ok(violation.blockingLabels.length > 0)
    })
  })

  describe('Causal Hash Chain (<_exec ordering)', () => {
    it('should produce deterministic step hashes', () => {
      const frame1 = createExecutionFrame('agent-1')
      const taint = createTaintLabel('alice', 'chain-1', 'del-1')
      const f1 = recordAccess(frame1, taint)

      const frame2 = createExecutionFrame('agent-2')
      const f2 = recordAccess(frame2, taint)

      // Same taint at same step index with same previous hash → same step hash
      assert.equal(f1.chainHead, f2.chainHead)
      assert.equal(f1.stepCount, 1)
    })

    it('should chain steps causally — reordering produces different hash', () => {
      const taintA = createTaintLabel('alice', 'chain-1', 'del-1')
      const taintB = createTaintLabel('bob', 'chain-2', 'del-2')

      // Order: A then B
      let frameAB = createExecutionFrame('agent-1')
      frameAB = recordAccess(frameAB, taintA)
      frameAB = recordAccess(frameAB, taintB)

      // Order: B then A
      let frameBA = createExecutionFrame('agent-2')
      frameBA = recordAccess(frameBA, taintB)
      frameBA = recordAccess(frameBA, taintA)

      // Different execution order → different chain head
      assert.notEqual(frameAB.chainHead, frameBA.chainHead)
      assert.equal(frameAB.stepCount, 2)
      assert.equal(frameBA.stepCount, 2)
    })

    it('should verify a valid frame chain', () => {
      let frame = createExecutionFrame('agent-1')
      frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
      frame = recordAccess(frame, createTaintLabel('bob', 'c2', 'd2'))
      frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd3'))

      const result = verifyFrameChain(frame)
      assert.equal(result.valid, true)
    })

    it('should detect tampered chain head', () => {
      let frame = createExecutionFrame('agent-1')
      frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
      frame = recordAccess(frame, createTaintLabel('bob', 'c2', 'd2'))

      // Tamper with chain head
      const tampered = { ...frame, chainHead: 'deadbeef' }
      const result = verifyFrameChain(tampered)
      assert.equal(result.valid, false)
      assert.ok(result.error?.includes('Chain head mismatch'))
    })

    it('should detect removed step (step count mismatch)', () => {
      let frame = createExecutionFrame('agent-1')
      frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
      frame = recordAccess(frame, createTaintLabel('bob', 'c2', 'd2'))

      // Remove a step but keep chain head
      const tampered = { ...frame, accessedContexts: [frame.accessedContexts[0]] }
      const result = verifyFrameChain(tampered)
      assert.equal(result.valid, false)
    })

    it('each step hash depends on ALL previous steps (not just immediate predecessor)', () => {
      const taintA = createTaintLabel('alice', 'c1', 'd1')
      const taintB = createTaintLabel('bob', 'c2', 'd2')
      const taintC = createTaintLabel('charlie', 'c3', 'd3')

      // Full chain: A → B → C
      let full = createExecutionFrame('agent-1')
      full = recordAccess(full, taintA)
      full = recordAccess(full, taintB)
      full = recordAccess(full, taintC)

      // Skip B: A → C (attacker tries to hide step B)
      let skipped = createExecutionFrame('agent-2')
      skipped = recordAccess(skipped, taintA)
      skipped = recordAccess(skipped, taintC)

      // Chain heads must differ — proves step B's existence is embedded in the chain
      assert.notEqual(full.chainHead, skipped.chainHead)
    })
  })

  describe('Frame TTL and Epoch Rotation (F-2 fix)', () => {
    it('frame with ttl=0 never expires', () => {
      const frame = createExecutionFrame('agent-1', { ttlMinutes: 0 })
      assert.equal(isFrameExpired(frame), false)
    })

    it('frame with positive ttl expires after duration', () => {
      const frame = createExecutionFrame('agent-1', { ttlMinutes: 1 })
      const old = { ...frame, startedAt: new Date(Date.now() - 120_000).toISOString() }
      assert.equal(isFrameExpired(old), true)
    })

    it('fresh frame with positive ttl is not expired', () => {
      const frame = createExecutionFrame('agent-1', { ttlMinutes: 60 })
      assert.equal(isFrameExpired(frame), false)
    })

    it('rotateFrame seals current and creates fresh with epoch+1', () => {
      let frame = createExecutionFrame('agent-1', { ttlMinutes: 5 })
      frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
      const { sealed, fresh } = rotateFrame(frame)
      assert.equal(sealed.active, false)
      assert.ok(sealed.sealedAt)
      assert.equal(fresh.active, true)
      assert.equal(fresh.epoch, 1)
      assert.equal(fresh.accessedContexts.length, 0)
      assert.equal(fresh.previousFrameChainHead, frame.chainHead)
    })

    it('recordAccess throws on closed frame', () => {
      const frame = closeFrame(createExecutionFrame('agent-1'))
      assert.throws(() => recordAccess(frame, createTaintLabel('a', 'b', 'c')), /closed frame/)
    })

    it('rotated frame has clean taint — no cross-chain flag', () => {
      let frame = createExecutionFrame('agent-1', { ttlMinutes: 5 })
      frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
      frame = recordAccess(frame, createTaintLabel('bob', 'c2', 'd2'))
      assert.equal(frame.frameTaint.isCrossChain, true)
      const { fresh } = rotateFrame(frame)
      assert.equal(fresh.frameTaint.isCrossChain, false)
      assert.equal(fresh.frameTaint.labels.length, 0)
    })

    it('epoch chain links frames via previousFrameChainHead', () => {
      let f0 = createExecutionFrame('agent-1', { ttlMinutes: 5 })
      f0 = recordAccess(f0, createTaintLabel('alice', 'c1', 'd1'))
      const r1 = rotateFrame(f0)
      let f1 = r1.fresh
      f1 = recordAccess(f1, createTaintLabel('bob', 'c2', 'd2'))
      const r2 = rotateFrame(f1)
      assert.equal(r2.fresh.epoch, 2)
      assert.equal(r2.fresh.previousFrameChainHead, f1.chainHead)
      assert.equal(r1.fresh.previousFrameChainHead, f0.chainHead)
    })

    it('TTL inherits across rotations', () => {
      const frame = createExecutionFrame('agent-1', { ttlMinutes: 15 })
      const { fresh } = rotateFrame(frame)
      assert.equal(fresh.ttlMinutes, 15)
    })

    it('residue principals survive rotation (V2-MED-1 fix)', () => {
      let frame = createExecutionFrame('agent-1', { ttlMinutes: 5 })
      frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
      frame = recordAccess(frame, createTaintLabel('bob', 'c2', 'd2'))
      const { fresh } = rotateFrame(frame)
      assert.deepEqual(fresh.residuePrincipals.sort(), ['alice', 'bob'])
      assert.equal(fresh.frameTaint.labels.length, 0, 'labels cleared')
      assert.equal(fresh.residuePrincipals.length, 2, 'principals preserved')
    })

    it('residue accumulates across multiple rotations', () => {
      let f0 = createExecutionFrame('agent-1', { ttlMinutes: 5 })
      f0 = recordAccess(f0, createTaintLabel('alice', 'c1', 'd1'))
      const r1 = rotateFrame(f0)
      let f1 = r1.fresh
      f1 = recordAccess(f1, createTaintLabel('bob', 'c2', 'd2'))
      const r2 = rotateFrame(f1)
      assert.deepEqual(r2.fresh.residuePrincipals.sort(), ['alice', 'bob'])
    })

    it('residue deduplicates repeated principals', () => {
      let f = createExecutionFrame('agent-1', { ttlMinutes: 5 })
      f = recordAccess(f, createTaintLabel('alice', 'c1', 'd1'))
      const r1 = rotateFrame(f)
      let f1 = r1.fresh
      f1 = recordAccess(f1, createTaintLabel('alice', 'c1', 'd2'))
      const r2 = rotateFrame(f1)
      assert.equal(r2.fresh.residuePrincipals.length, 1)
      assert.equal(r2.fresh.residuePrincipals[0], 'alice')
    })
  })

  describe('Epoch Chain Verification (V2-LOW-2 fix)', () => {
    it('verifies valid epoch chain', () => {
      let f0 = createExecutionFrame('agent-1', { ttlMinutes: 5 })
      f0 = recordAccess(f0, createTaintLabel('alice', 'c1', 'd1'))
      const r1 = rotateFrame(f0)
      let f1 = r1.fresh
      f1 = recordAccess(f1, createTaintLabel('bob', 'c2', 'd2'))
      const r2 = rotateFrame(f1)
      const result = verifyEpochChain([r1.sealed, r2.sealed, r2.fresh])
      assert.equal(result.valid, true)
    })

    it('detects tampered epoch link', () => {
      let f0 = createExecutionFrame('agent-1', { ttlMinutes: 5 })
      f0 = recordAccess(f0, createTaintLabel('alice', 'c1', 'd1'))
      const r1 = rotateFrame(f0)
      const tampered = { ...r1.fresh, previousFrameChainHead: 'TAMPERED' }
      const result = verifyEpochChain([r1.sealed, tampered])
      assert.equal(result.valid, false)
      assert.ok(result.error?.includes('link mismatch'))
    })

    it('detects epoch gap', () => {
      const f0 = createExecutionFrame('agent-1', { epoch: 0 })
      const f2 = createExecutionFrame('agent-1', { epoch: 2 })
      const result = verifyEpochChain([f0, f2])
      assert.equal(result.valid, false)
      assert.ok(result.error?.includes('Epoch gap'))
    })

    it('empty chain is valid', () => {
      assert.equal(verifyEpochChain([]).valid, true)
    })
  })

})
