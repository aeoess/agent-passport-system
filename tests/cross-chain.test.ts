import { describe, it, expect } from 'vitest'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createTaintLabel, mergeTaints,
  createSAO, verifySAO, isSAOExpired,
  createExecutionFrame, recordAccess, closeFrame,
  createCrossChainPermit, countersignPermit,
  verifyCrossChainPermit, revokePermit,
  checkDataFlow
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
      expect(label.principalId).toBe('alice')
      expect(label.usage).toBe('same-context-only')
      expect(label.taintedAt).toBeTruthy()
    })

    it('should detect cross-chain taint when merging from different principals', () => {
      const labelA = createTaintLabel('alice', 'chain-a', 'del-001')
      const labelB = createTaintLabel('bob', 'chain-b', 'del-002')
      const taintSet = mergeTaints(labelA, labelB)

      expect(taintSet.isCrossChain).toBe(true)
      expect(taintSet.principals).toContain('alice')
      expect(taintSet.principals).toContain('bob')
      expect(taintSet.labels).toHaveLength(2)
    })

    it('should NOT be cross-chain when all labels from same principal', () => {
      const label1 = createTaintLabel('alice', 'chain-a', 'del-001')
      const label2 = createTaintLabel('alice', 'chain-a', 'del-003')
      const taintSet = mergeTaints(label1, label2)

      expect(taintSet.isCrossChain).toBe(false)
      expect(taintSet.principals).toEqual(['alice'])
    })
  })

  // ── Signed Authority Objects ──
  describe('Signed Authority Objects', () => {
    it('should create and verify an SAO', () => {
      const taint = createTaintLabel('alice', 'chain-a', 'del-001')
      const sao = createSAO('confidential data', taint, monitor.privateKey, monitor.publicKey)

      expect(sao.data).toBe('confidential data')
      expect(sao.taint.principalId).toBe('alice')
      expect(verifySAO(sao)).toBe(true)
    })

    it('should reject tampered SAO data', () => {
      const taint = createTaintLabel('alice', 'chain-a', 'del-001')
      const sao = createSAO('confidential data', taint, monitor.privateKey, monitor.publicKey)
      const tampered = { ...sao, data: 'modified data' }

      expect(verifySAO(tampered)).toBe(false)
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

      expect(partial.sourceSignature).toBeTruthy()
      expect(partial.destinationSignature).toBe('')

      const permit = countersignPermit(partial, bob.privateKey)
      expect(permit.destinationSignature).toBeTruthy()
      expect(verifyCrossChainPermit(permit)).toBe(true)
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
      expect(verifyCrossChainPermit(partial as any)).toBe(false)
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

      expect(verifyCrossChainPermit(revoked)).toBe(false)
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

      expect(result.verdict).toBe('blocked')
      expect(result.blockingLabels).toHaveLength(1)
      expect(result.blockingLabels![0].principalId).toBe('alice')
      expect(result.reason).toContain('alice')
      expect(result.reason).toContain('bob')
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

      expect(result.verdict).toBe('allowed')
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

      expect(result.verdict).toBe('permitted')
      expect(result.permitId).toBe(permit.permitId)
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

      expect(result.verdict).toBe('blocked')
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

      expect(result.verdict).toBe('blocked')
      expect(result.reason).toContain('read-only')
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

      expect(frame.frameTaint.principals).toContain('alice')

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
      expect(result.verdict).toBe('blocked')
      expect(result.blockingLabels![0].principalId).toBe('alice')
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

      expect(result.verdict).toBe('allowed')
    })

    it('ATTACK: multi-principal frame, no permits → BLOCKED', () => {
      let frame = createExecutionFrame('agent-001')

      // Agent reads from both Alice and Bob during same session
      frame = recordAccess(frame, createTaintLabel('alice', 'chain-a', 'del-001'))
      frame = recordAccess(frame, createTaintLabel('bob', 'chain-b', 'del-002'))

      expect(frame.frameTaint.isCrossChain).toBe(true)

      // Any outbound action under either principal is blocked
      // because the frame contains data from the OTHER principal
      const result = checkDataFlow({
        inputTaint: mergeTaints(),
        actionPrincipalId: 'alice',
        actionScope: 'file:write',
        permits: [],
        frame
      })

      expect(result.verdict).toBe('blocked')
      expect(result.blockingLabels![0].principalId).toBe('bob')
    })

    it('should track frame accumulation correctly', () => {
      let frame = createExecutionFrame('agent-001')
      expect(frame.accessedContexts).toHaveLength(0)
      expect(frame.frameTaint.isCrossChain).toBe(false)

      frame = recordAccess(frame, createTaintLabel('alice', 'chain-a', 'del-001'))
      expect(frame.accessedContexts).toHaveLength(1)
      expect(frame.frameTaint.isCrossChain).toBe(false)

      frame = recordAccess(frame, createTaintLabel('bob', 'chain-b', 'del-002'))
      expect(frame.accessedContexts).toHaveLength(2)
      expect(frame.frameTaint.isCrossChain).toBe(true)
      expect(frame.frameTaint.principals).toHaveLength(2)
    })
  })

})
