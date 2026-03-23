import { describe, it } from 'node:test'
import assert from 'node:assert'
import { DataGateway } from '../src/core/data-gateway.js'
import { registerSelfAttestedSource } from '../src/core/data-source.js'
import { generateKeyPair } from '../src/crypto/keys.js'
import type { DataTerms } from '../src/types/data-source.js'

const GW_KP = generateKeyPair()
const AGENT_KP = generateKeyPair()

const TERMS_PAID: DataTerms = {
  allowedPurposes: ['read', 'analyze', 'summarize'],
  requireAttribution: true,
  requireNotification: false,
  compensation: { type: 'per_access', amount: 0.05, currency: 'usd' },
  derivativePolicy: 'attribution_required',
  auditVisibility: 'source_and_principal',
  revocable: false,
}

function makeSource(terms: DataTerms) {
  const kp = generateKeyPair()
  return registerSelfAttestedSource({
    ownerPrincipalId: 'principal_owner',
    ownerPublicKey: kp.publicKey,
    ownerPrivateKey: kp.privateKey,
    contentCommitment: 'hash123',
    contentType: 'document',
    contentDescriptor: 'Test Data Source',
    dataTerms: terms,
  })
}

function makeGateway(requireTerms = true, mode: 'enforce' | 'audit' | 'off' = 'enforce') {
  return new DataGateway({
    gatewayId: 'gw_test',
    gatewayPublicKey: GW_KP.publicKey,
    gatewayPrivateKey: GW_KP.privateKey,
    enforcementMode: mode,
    requireTermsAcceptance: requireTerms,
  })
}

function makeRequest(sourceReceiptId: string) {
  return {
    agentId: 'agent_bot',
    agentPublicKey: AGENT_KP.publicKey,
    principalId: 'principal_tima',
    sourceReceiptId,
    declaredPurpose: 'analyze' as const,
    accessMethod: 'api_call' as const,
    accessScope: 'data:read',
    executionFrameId: 'frame_' + Math.random().toString(36).slice(2),
  }
}

describe('Data Gateway — Terms Acceptance Enforcement', () => {
  it('[ENFORCE] blocks access when terms not accepted', () => {
    const gw = makeGateway(true)
    const source = makeSource(TERMS_PAID)
    gw.registerSource(source, 'Paid Data')
    const decision = gw.requestAccess(makeRequest(source.sourceReceiptId))
    assert.strictEqual(decision.allowed, false)
    assert.ok(decision.hardViolations[0].includes('not accepted'))
  })

  it('[ENFORCE] allows access after terms accepted', () => {
    const gw = makeGateway(true)
    const source = makeSource(TERMS_PAID)
    gw.registerSource(source, 'Paid Data')
    gw.acceptTerms({ agentId: 'agent_bot', agentPublicKey: AGENT_KP.publicKey, sourceReceiptId: source.sourceReceiptId })
    const decision = gw.requestAccess(makeRequest(source.sourceReceiptId))
    assert.strictEqual(decision.allowed, true)
    assert.ok(decision.receipt)
  })

  it('allows access without terms acceptance when not required', () => {
    const gw = makeGateway(false)
    const source = makeSource(TERMS_PAID)
    gw.registerSource(source, 'Paid Data')
    const decision = gw.requestAccess(makeRequest(source.sourceReceiptId))
    assert.strictEqual(decision.allowed, true)
  })

  it('tracks acceptances and feeds contribution ledger', () => {
    const gw = makeGateway(true)
    const source = makeSource(TERMS_PAID)
    gw.registerSource(source, 'Data')
    gw.acceptTerms({ agentId: 'agent_bot', agentPublicKey: AGENT_KP.publicKey, sourceReceiptId: source.sourceReceiptId })
    gw.requestAccess(makeRequest(source.sourceReceiptId))
    gw.requestAccess(makeRequest(source.sourceReceiptId))
    gw.requestAccess(makeRequest(source.sourceReceiptId))
    const ledger = gw.getLedger()
    assert.strictEqual(ledger.records.size, 1)
    const record = Array.from(ledger.records.values())[0]
    assert.strictEqual(record.accessCount, 3)
  })
})

describe('Data Gateway — Terms Revocation', () => {
  it('[ADVERSARIAL] revokes acceptance and blocks subsequent access', () => {
    const gw = makeGateway(true)
    const source = makeSource(TERMS_PAID)
    gw.registerSource(source, 'Data')
    gw.acceptTerms({ agentId: 'agent_bot', agentPublicKey: AGENT_KP.publicKey, sourceReceiptId: source.sourceReceiptId })
    // First access works
    assert.strictEqual(gw.requestAccess(makeRequest(source.sourceReceiptId)).allowed, true)
    // Revoke
    gw.revokeAcceptance('agent_bot', source.sourceReceiptId)
    // Now blocked
    assert.strictEqual(gw.requestAccess(makeRequest(source.sourceReceiptId)).allowed, false)
  })

  it('revokes all acceptances for a source when terms change', () => {
    const gw = makeGateway(true)
    const source = makeSource(TERMS_PAID)
    gw.registerSource(source, 'Data')
    gw.acceptTerms({ agentId: 'agent_1', agentPublicKey: 'a'.repeat(64), sourceReceiptId: source.sourceReceiptId })
    gw.acceptTerms({ agentId: 'agent_2', agentPublicKey: 'b'.repeat(64), sourceReceiptId: source.sourceReceiptId })
    assert.strictEqual(gw.getAcceptances().length, 2)
    const revoked = gw.revokeAllAcceptancesForSource(source.sourceReceiptId)
    assert.strictEqual(revoked, 2)
    assert.strictEqual(gw.getAcceptances().length, 0)
  })
})

describe('Data Gateway — Preflight', () => {
  it('preflight checks terms acceptance + compliance', () => {
    const gw = makeGateway(true)
    const s1 = makeSource(TERMS_PAID)
    const s2 = makeSource(TERMS_PAID)
    gw.registerSource(s1, 'D1')
    gw.registerSource(s2, 'D2')
    gw.acceptTerms({ agentId: 'agent_bot', agentPublicKey: AGENT_KP.publicKey, sourceReceiptId: s1.sourceReceiptId })
    // s2 not accepted
    const result = gw.preflightAccess([makeRequest(s1.sourceReceiptId), makeRequest(s2.sourceReceiptId)])
    assert.strictEqual(result.allAllowed, false)
    assert.strictEqual(result.decisions[0].allowed, true)
    assert.strictEqual(result.decisions[1].allowed, false)
  })

  it('preflight passes when all terms accepted', () => {
    const gw = makeGateway(true)
    const s1 = makeSource(TERMS_PAID)
    const s2 = makeSource(TERMS_PAID)
    gw.registerSource(s1, 'D1')
    gw.registerSource(s2, 'D2')
    gw.acceptTerms({ agentId: 'agent_bot', agentPublicKey: AGENT_KP.publicKey, sourceReceiptId: s1.sourceReceiptId })
    gw.acceptTerms({ agentId: 'agent_bot', agentPublicKey: AGENT_KP.publicKey, sourceReceiptId: s2.sourceReceiptId })
    const result = gw.preflightAccess([makeRequest(s1.sourceReceiptId), makeRequest(s2.sourceReceiptId)])
    assert.strictEqual(result.allAllowed, true)
  })
})
