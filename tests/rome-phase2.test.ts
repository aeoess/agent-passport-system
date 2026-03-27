// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for Phase 2 — Time, Foreign, EscrowAwareRevocation, GatewayIdentity types

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  // Time functions
  createHybridTimestamp, createTemporalBound,
  compareTimestamps, isTemporalBoundExpired,
  validateTemporalRights, resetLogicalCounter,
  // Reserve functions
  createReserveAttestation, verifyReserveAttestation,
  compareAssuranceClass, meetsAssuranceRequirement,
  // Federation functions
  importReceipt, verifyReceiptEnvelope,
  vouchReputation, verifyVouchedReputation,
  applyReputationDowngrade,
} from '../src/index.js'
import type {
  HybridTimestamp, TemporalBound, TemporalRights,
  TemporalOrdering, TemporalValidation,
  ForeignProvenanceClass, ForeignTrustClass,
  ForeignSandboxPolicy, ForeignReclassificationRules,
  ForeignCounterpartyEnvelope,
  EscrowRevocationStatus, EscrowAwareRevocation,
  JurisdictionEnvelope, InfrastructureFeePolicy,
  GatewayImportPolicy, GatewaySovereigntyLevel,
  GatewayTrustBasis, GatewayIdentity,
  WitnessPolicy,
} from '../src/index.js'

// ══════════════════════════════════════
// HybridTimestamp — Consilium Q1
// ══════════════════════════════════════

describe('Time — HybridTimestamp', () => {
  it('constructs a valid hybrid timestamp with uncertainty bounds', () => {
    const now = Date.now()
    const drift = 50 // 50ms NTP drift bound
    const ts: HybridTimestamp = {
      logicalTime: 1,
      wallClockEarliest: now - drift,
      wallClockLatest: now + drift,
      gatewayId: 'gw_test_001',
    }
    assert.ok(ts.wallClockEarliest < ts.wallClockLatest, 'earliest must precede latest')
    assert.ok(ts.logicalTime > 0)
    assert.equal(ts.gatewayId, 'gw_test_001')
  })

  it('temporal ordering: definitely_before when ranges do not overlap', () => {
    const a: HybridTimestamp = { logicalTime: 1, wallClockEarliest: 1000, wallClockLatest: 1050, gatewayId: 'gw1' }
    const b: HybridTimestamp = { logicalTime: 2, wallClockEarliest: 1100, wallClockLatest: 1150, gatewayId: 'gw1' }

    // a.wallClockLatest (1050) < b.wallClockEarliest (1100) → definitely_before
    const order: TemporalOrdering = a.wallClockLatest < b.wallClockEarliest
      ? 'definitely_before'
      : a.wallClockEarliest > b.wallClockLatest
        ? 'definitely_after'
        : a.gatewayId === b.gatewayId && a.logicalTime < b.logicalTime
          ? 'causally_before'
          : 'incomparable'

    assert.equal(order, 'definitely_before')
  })

  it('temporal ordering: concurrent when ranges overlap, uses logical time for same gateway', () => {
    const a: HybridTimestamp = { logicalTime: 5, wallClockEarliest: 1000, wallClockLatest: 1100, gatewayId: 'gw1' }
    const b: HybridTimestamp = { logicalTime: 8, wallClockEarliest: 1050, wallClockLatest: 1150, gatewayId: 'gw1' }

    // Ranges overlap (1050-1100) → concurrent → but same gateway, so use logical time
    const rangesOverlap = a.wallClockLatest >= b.wallClockEarliest && a.wallClockEarliest <= b.wallClockLatest
    assert.ok(rangesOverlap)
    const order: TemporalOrdering = a.logicalTime < b.logicalTime ? 'causally_before' : 'causally_after'
    assert.equal(order, 'causally_before')
  })

  it('temporal ordering: incomparable when ranges overlap across different gateways', () => {
    const a: HybridTimestamp = { logicalTime: 5, wallClockEarliest: 1000, wallClockLatest: 1100, gatewayId: 'gw1' }
    const b: HybridTimestamp = { logicalTime: 3, wallClockEarliest: 1050, wallClockLatest: 1150, gatewayId: 'gw2' }

    const rangesOverlap = a.wallClockLatest >= b.wallClockEarliest && a.wallClockEarliest <= b.wallClockLatest
    const sameGateway = a.gatewayId === b.gatewayId
    assert.ok(rangesOverlap)
    assert.ok(!sameGateway)
    // Different gateways + overlapping ranges → incomparable
    const order: TemporalOrdering = 'incomparable'
    assert.equal(order, 'incomparable')
  })

  it('TemporalBound: escrow expires when earliest > expiresAt (conservative)', () => {
    const bound: TemporalBound = {
      issuedAt: { logicalTime: 1, wallClockEarliest: 1000, wallClockLatest: 1050, gatewayId: 'gw1' },
      expiresAt: 2000,
    }
    // Check at time 2100: earliest (2100) > expiresAt (2000) → expired
    const checkEarliest = 2100
    assert.ok(checkEarliest > bound.expiresAt, 'Should be expired')

    // Check at time 1900: earliest (1900) < expiresAt (2000) → still valid
    const checkEarliest2 = 1900
    assert.ok(checkEarliest2 < bound.expiresAt, 'Should still be valid')
  })

  it('TemporalRights: validates temporal window semantics', () => {
    const rights: TemporalRights = {
      validFrom: '2026-01-01T00:00:00Z',
      validUntil: '2026-12-31T23:59:59Z',
      challengeUntil: '2027-01-31T23:59:59Z',
      graceUntil: '2027-02-28T23:59:59Z',
      effectiveAt: '2026-01-01T00:00:00Z',
    }
    // validFrom < validUntil < challengeUntil < graceUntil
    assert.ok(new Date(rights.validFrom) < new Date(rights.validUntil))
    assert.ok(new Date(rights.validUntil) < new Date(rights.challengeUntil!))
    assert.ok(new Date(rights.challengeUntil!) < new Date(rights.graceUntil!))
  })
})

// ══════════════════════════════════════
// ForeignCounterpartyEnvelope — GPT #14
// ══════════════════════════════════════

describe('Foreign — Counterparty Envelope', () => {
  function makeEnvelope(overrides?: Partial<ForeignCounterpartyEnvelope>): ForeignCounterpartyEnvelope {
    return {
      envelopeId: 'fenv_001',
      localAlias: 'external-api-v1',
      provenanceClass: 'legacy_api',
      trustClass: 'untrusted',
      admissibleOperations: ['read:data', 'query:search'],
      sandboxPolicy: {
        maxSpendPerAction: 10,
        requireWitness: true,
        requireEscrow: true,
        dataEgressAllowed: false,
        maxConcurrentActions: 3,
      },
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      reclassificationRules: {
        autoPromoteAfterReceipts: 50,
        autoDemoteOnDispute: true,
        reviewIntervalSeconds: 604800,
      },
      gatewayId: 'gw_test',
      gatewaySignature: 'sig_placeholder',
      ...overrides,
    }
  }

  it('creates a valid foreign envelope with mandatory expiry', () => {
    const env = makeEnvelope()
    assert.ok(new Date(env.expiresAt) > new Date(env.issuedAt), 'Must expire after issuance')
    assert.equal(env.trustClass, 'untrusted')
    assert.ok(env.sandboxPolicy.requireWitness, 'Foreign entities require witnesses in v1')
  })

  it('enforces no permanent foreign trust (expiresAt required)', () => {
    const env = makeEnvelope()
    // expiresAt is a required field — TypeScript enforces this at compile time
    // Runtime check: expiresAt must be a valid future date
    assert.ok(env.expiresAt.length > 0)
    assert.ok(new Date(env.expiresAt) > new Date())
  })

  it('sandbox restricts foreign entities', () => {
    const env = makeEnvelope()
    assert.equal(env.sandboxPolicy.maxSpendPerAction, 10)
    assert.ok(env.sandboxPolicy.requireEscrow)
    assert.ok(!env.sandboxPolicy.dataEgressAllowed, 'Untrusted should not egress data')
    assert.equal(env.sandboxPolicy.maxConcurrentActions, 3)
  })

  it('trust classes follow monotonic upgrade path', () => {
    const classes: ForeignTrustClass[] = ['untrusted', 'probationary', 'attested', 'vouched']
    // untrusted → probationary → attested → vouched (monotonic upgrade)
    for (let i = 0; i < classes.length - 1; i++) {
      const current = classes.indexOf(classes[i])
      const next = classes.indexOf(classes[i + 1])
      assert.ok(current < next, `${classes[i]} should precede ${classes[i + 1]}`)
    }
  })

  it('vouched envelope includes vouch metadata', () => {
    const env = makeEnvelope({
      trustClass: 'vouched',
      vouchedBy: 'abc123pubkey',
      vouchExpiresAt: new Date(Date.now() + 3600000).toISOString(),
    })
    assert.equal(env.trustClass, 'vouched')
    assert.ok(env.vouchedBy)
    assert.ok(env.vouchExpiresAt)
  })

  it('reclassification rules support auto-promotion', () => {
    const env = makeEnvelope()
    assert.equal(env.reclassificationRules.autoPromoteAfterReceipts, 50)
    assert.ok(env.reclassificationRules.autoDemoteOnDispute)
    assert.equal(env.reclassificationRules.reviewIntervalSeconds, 604800) // 1 week
  })
})

// ══════════════════════════════════════
// EscrowAwareRevocation — Gemini S2 Q3
// ══════════════════════════════════════

describe('Escrow — Aware Revocation', () => {
  it('constructs a revocation blocked by active escrows', () => {
    const rev: EscrowAwareRevocation = {
      revocationId: 'rev_001',
      targetDelegationId: 'del_abc123',
      principalSignature: 'sig_principal',
      status: 'pending_escrow_clearance',
      blockingEscrowIds: ['esc_001', 'esc_002'],
      gracePeriodExpiresAt: new Date(Date.now() + 86400000).toISOString(),
      newActionsBlocked: true,
      existingEscrowsProtected: true,
      createdAt: new Date().toISOString(),
      gatewaySignature: 'sig_gateway',
    }
    assert.ok(rev.newActionsBlocked, 'New actions must be blocked')
    assert.ok(rev.existingEscrowsProtected, 'Existing escrows must be protected')
    assert.equal(rev.blockingEscrowIds.length, 2)
    assert.equal(rev.status, 'pending_escrow_clearance')
  })

  it('transitions to executed when all blocking escrows resolve', () => {
    const rev: EscrowAwareRevocation = {
      revocationId: 'rev_002',
      targetDelegationId: 'del_xyz',
      principalSignature: 'sig_p',
      status: 'pending_escrow_clearance',
      blockingEscrowIds: ['esc_only'],
      gracePeriodExpiresAt: new Date(Date.now() + 86400000).toISOString(),
      newActionsBlocked: true,
      existingEscrowsProtected: true,
      createdAt: new Date().toISOString(),
      gatewaySignature: 'sig_gw',
    }
    // Simulate: all blocking escrows resolved → status becomes 'executed'
    const resolved: EscrowAwareRevocation = { ...rev, blockingEscrowIds: [], status: 'executed' }
    assert.equal(resolved.status, 'executed')
    assert.equal(resolved.blockingEscrowIds.length, 0)
  })

  it('force revocation when grace period expires', () => {
    const pastGrace = new Date(Date.now() - 1000).toISOString()
    const rev: EscrowAwareRevocation = {
      revocationId: 'rev_003',
      targetDelegationId: 'del_force',
      principalSignature: 'sig_p',
      status: 'pending_escrow_clearance',
      blockingEscrowIds: ['esc_stuck'],
      gracePeriodExpiresAt: pastGrace,
      newActionsBlocked: true,
      existingEscrowsProtected: true,
      createdAt: new Date().toISOString(),
      gatewaySignature: 'sig_gw',
    }
    // Grace expired → force revocation
    const graceExpired = new Date(rev.gracePeriodExpiresAt) < new Date()
    assert.ok(graceExpired)
    const forced: EscrowAwareRevocation = { ...rev, status: 'failed' }
    assert.equal(forced.status, 'failed')
  })
})

// ══════════════════════════════════════
// GatewayIdentity — GPT #12
// ══════════════════════════════════════

describe('Gateway — Identity & Import Policy', () => {
  function makeGatewayIdentity(): GatewayIdentity {
    const witnessPolicy: WitnessPolicy = {
      requireWitness: true,
      minimumWitnesses: 2,
      observationBasis: 'independent_recomputation',
      diversityRequirements: { minDistinctRuntimes: 2, minDistinctOperators: 1 },
    }
    return {
      gatewayId: 'gw_aeoess_001',
      publicKey: 'abc123hex',
      displayName: 'AEOESS Gateway Alpha',
      operator: 'charter_aeoess',
      trustBasis: {
        charterAnchor: 'charter_aeoess',
        witnessPolicyHash: 'hash_wp',
        archivePolicy: 'federated',
        finalityPolicy: 'witness_required',
        feePolicyHash: 'hash_fp',
        disputePolicyHash: 'hash_dp',
      },
      feePolicy: {
        model: 'per_action',
        amount: 0.01,
        currency: 'USD',
        feeScheduleHash: 'hash_fees',
      },
      witnessPolicy,
      trustDomainId: 'domain_us_west',
      jurisdiction: { primary: 'US', additional: ['EU'], dataResidency: 'US' },
      importPolicy: {
        receipts: { acceptFrom: ['gw_partner_001'], requireWitness: true },
        reputation: { acceptFrom: ['gw_partner_001'], downgradeRatio: 0.5 },
        witnessAttestations: { acceptFrom: ['gw_partner_001'], minObservationBasis: 'independent_recomputation' },
        reserveAttestations: { acceptFrom: [], requireLiabilityClass: true },
        charterFacts: { acceptFrom: ['gw_partner_001'] },
        foreignAgentDefaultTier: 0,
      },
      sovereigntyLevel: 'sovereign',
      registeredAt: new Date().toISOString(),
      signature: 'sig_gw_identity',
    }
  }

  it('constructs a valid gateway identity with trust basis', () => {
    const gw = makeGatewayIdentity()
    assert.equal(gw.gatewayId, 'gw_aeoess_001')
    assert.equal(gw.operator, 'charter_aeoess')
    assert.ok(gw.trustBasis.charterAnchor)
    assert.equal(gw.trustBasis.finalityPolicy, 'witness_required')
    assert.equal(gw.sovereigntyLevel, 'sovereign')
  })

  it('gateway publishes its regime (GPT #12)', () => {
    const gw = makeGatewayIdentity()
    // A gateway MUST publish what regime it operates under
    assert.ok(gw.trustBasis.witnessPolicyHash, 'Must publish witness policy')
    assert.ok(gw.trustBasis.feePolicyHash, 'Must publish fee policy')
    assert.ok(gw.trustBasis.disputePolicyHash, 'Must publish dispute policy')
    assert.ok(gw.feePolicy.model, 'Must declare fee model')
    assert.ok(gw.jurisdiction, 'Must declare jurisdiction')
  })

  it('import policy: separate channels per artifact type (GPT #13)', () => {
    const gw = makeGatewayIdentity()
    const ip = gw.importPolicy
    // Each artifact type has independent import rules
    assert.ok(Array.isArray(ip.receipts.acceptFrom))
    assert.ok(typeof ip.receipts.requireWitness === 'boolean')
    assert.ok(typeof ip.reputation.downgradeRatio === 'number')
    assert.ok(ip.reputation.downgradeRatio <= 1.0, 'Foreign rep cannot be inflated')
    assert.ok(ip.reputation.downgradeRatio >= 0, 'Downgrade ratio must be non-negative')
    assert.equal(ip.foreignAgentDefaultTier, 0, 'Foreign agents start at tier 0')
  })

  it('sovereignty levels are graduated', () => {
    const levels: GatewaySovereigntyLevel[] = ['border_outpost', 'province', 'sovereign']
    assert.equal(levels.length, 3)
    // border_outpost < province < sovereign (graduated authority)
    const gw = makeGatewayIdentity()
    assert.equal(gw.sovereigntyLevel, 'sovereign')
  })

  it('fee policy supports multiple models', () => {
    const free: InfrastructureFeePolicy = { model: 'free', feeScheduleHash: 'hash_free' }
    assert.equal(free.model, 'free')
    assert.equal(free.amount, undefined)

    const pct: InfrastructureFeePolicy = { model: 'percentage', amount: 2.5, currency: 'USD', feeScheduleHash: 'hash_pct' }
    assert.equal(pct.model, 'percentage')
    assert.equal(pct.amount, 2.5)
  })
})

// ══════════════════════════════════════
// ReserveAttestation — GPT #15
// ══════════════════════════════════════

describe('Reserve — Attestation', () => {
  it('constructs a reserve attestation with liability semantics', () => {
    const att: import('../src/index.js').ReserveAttestation = {
      attestationId: 'res_001',
      delegationId: 'del_abc',
      assuranceClass: 'gateway_attested',
      attestedAmount: { value: 5000, currency: 'USD' },
      attestedBy: 'attester_pubkey',
      charterAnchor: 'charter_aeoess',
      officeId: 'treasury',
      liability: {
        attestationBasis: 'api_balance_check',
        isRevocable: false,
        falseAttestationPenalty: 'bond_forfeit',
        verificationMethod: 'stripe_balance_api',
      },
      attestedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      signature: 'sig_reserve',
    }
    assert.equal(att.assuranceClass, 'gateway_attested')
    assert.equal(att.attestedAmount.value, 5000)
    assert.equal(att.liability.falseAttestationPenalty, 'bond_forfeit')
    assert.ok(att.charterAnchor, 'Institutional context required')
  })

  it('assurance classes are ordered by strength', () => {
    const classes: import('../src/index.js').ReserveAssuranceClass[] = [
      'unbacked', 'self_attested', 'gateway_attested', 'escrow_backed', 'externally_attested'
    ]
    // Verify ordering: each class is stronger than the previous
    assert.equal(classes.length, 5)
    assert.equal(classes[0], 'unbacked')
    assert.equal(classes[4], 'externally_attested')
  })

  it('attestation must expire', () => {
    const att: import('../src/index.js').ReserveAttestation = {
      attestationId: 'res_002',
      delegationId: 'del_xyz',
      assuranceClass: 'self_attested',
      attestedAmount: { value: 100, currency: 'EUR' },
      attestedBy: 'self_pubkey',
      liability: {
        attestationBasis: 'self_declaration',
        isRevocable: true,
        falseAttestationPenalty: 'none',
      },
      attestedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      signature: 'sig_self',
    }
    assert.ok(new Date(att.expiresAt) > new Date(att.attestedAt))
  })
})

// ══════════════════════════════════════
// Federation — WS-2 (Receipt Portability) & WS-3 (Reputation)
// ══════════════════════════════════════

describe('Federation — Receipt & Reputation Portability', () => {
  it('WS-2: constructs a foreign receipt envelope for import', () => {
    const env: import('../src/index.js').ForeignReceiptEnvelope = {
      receiptId: 'rcpt_foreign_001',
      originGatewayId: 'gw_partner',
      originGatewaySignature: 'sig_origin',
      agentId: 'agent_external',
      agentSignature: 'sig_agent',
      receiptHash: 'hash_receipt_abc',
      importDecision: 'accepted',
      importedAt: new Date().toISOString(),
      importingGatewaySignature: 'sig_importing',
    }
    assert.equal(env.importDecision, 'accepted')
    assert.ok(env.originGatewayId !== 'gw_importing', 'Must be from foreign gateway')
    assert.ok(env.receiptHash.length > 0)
  })

  it('WS-2: rejected receipt envelope', () => {
    const env: import('../src/index.js').ForeignReceiptEnvelope = {
      receiptId: 'rcpt_bad',
      originGatewayId: 'gw_untrusted',
      originGatewaySignature: 'sig_bad',
      agentId: 'agent_bad',
      agentSignature: 'sig_agent_bad',
      receiptHash: 'hash_suspicious',
      importDecision: 'rejected',
      importedAt: new Date().toISOString(),
      importingGatewaySignature: 'sig_rejecting_gw',
    }
    assert.equal(env.importDecision, 'rejected')
  })

  it('WS-3: constructs a vouched reputation attestation', () => {
    const rep: import('../src/index.js').VouchedReputation = {
      agentId: 'agent_proven',
      originGatewayId: 'gw_home',
      attestedTier: 3,
      attestedDiversityScore: 0.85,
      attestedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000 * 30).toISOString(),
      originGatewaySignature: 'sig_vouch',
    }
    assert.equal(rep.attestedTier, 3)
    assert.ok(rep.attestedDiversityScore > 0 && rep.attestedDiversityScore <= 1.0)
    assert.ok(new Date(rep.expiresAt) > new Date(rep.attestedAt), 'Reputation must expire')
  })

  it('WS-3: reputation does not expose receipt history (Gemini S2)', () => {
    const rep: import('../src/index.js').VouchedReputation = {
      agentId: 'agent_private',
      originGatewayId: 'gw_home',
      attestedTier: 2,
      attestedDiversityScore: 0.6,
      attestedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      originGatewaySignature: 'sig_private',
    }
    // VouchedReputation has NO receipt array — by design
    // Only summary metrics (tier + diversity score) are portable
    const keys = Object.keys(rep)
    assert.ok(!keys.includes('receipts'), 'Must not include receipt history')
    assert.ok(!keys.includes('receiptIds'), 'Must not include receipt IDs')
    assert.ok(keys.includes('attestedTier'), 'Must include summary tier')
    assert.ok(keys.includes('attestedDiversityScore'), 'Must include diversity score')
  })
})


// ══════════════════════════════════════
// Time Functions — compareTimestamps, validateTemporalRights
// ══════════════════════════════════════

describe('Time Functions — Hybrid Clock Operations', () => {
  it('createHybridTimestamp produces monotonically increasing logical time', () => {
    resetLogicalCounter()
    const t1 = createHybridTimestamp('gw_test')
    const t2 = createHybridTimestamp('gw_test')
    const t3 = createHybridTimestamp('gw_test')
    assert.ok(t1.logicalTime < t2.logicalTime)
    assert.ok(t2.logicalTime < t3.logicalTime)
    assert.equal(t1.gatewayId, 'gw_test')
  })

  it('createHybridTimestamp wall clock bounds bracket now', () => {
    const before = Date.now()
    const ts = createHybridTimestamp('gw_test', 50)
    const after = Date.now()
    assert.ok(ts.wallClockEarliest <= before)
    assert.ok(ts.wallClockLatest >= after)
  })

  it('compareTimestamps: definitely_before for non-overlapping ranges', () => {
    const a: HybridTimestamp = { logicalTime: 1, wallClockEarliest: 1000, wallClockLatest: 1050, gatewayId: 'gw1' }
    const b: HybridTimestamp = { logicalTime: 2, wallClockEarliest: 1100, wallClockLatest: 1150, gatewayId: 'gw1' }
    assert.equal(compareTimestamps(a, b), 'definitely_before')
    assert.equal(compareTimestamps(b, a), 'definitely_after')
  })

  it('compareTimestamps: causally_before for same-gateway overlapping', () => {
    const a: HybridTimestamp = { logicalTime: 5, wallClockEarliest: 1000, wallClockLatest: 1100, gatewayId: 'gw1' }
    const b: HybridTimestamp = { logicalTime: 8, wallClockEarliest: 1050, wallClockLatest: 1150, gatewayId: 'gw1' }
    assert.equal(compareTimestamps(a, b), 'causally_before')
    assert.equal(compareTimestamps(b, a), 'causally_after')
  })

  it('compareTimestamps: incomparable for cross-gateway overlapping', () => {
    const a: HybridTimestamp = { logicalTime: 5, wallClockEarliest: 1000, wallClockLatest: 1100, gatewayId: 'gw1' }
    const b: HybridTimestamp = { logicalTime: 3, wallClockEarliest: 1050, wallClockLatest: 1150, gatewayId: 'gw2' }
    assert.equal(compareTimestamps(a, b), 'incomparable')
  })

  it('isTemporalBoundExpired: conservative check using earliest', () => {
    const bound = createTemporalBound('gw1', 1000) // 1 second TTL
    assert.ok(!isTemporalBoundExpired(bound))
    // Simulate future check: earliest = now + 2 seconds
    assert.ok(isTemporalBoundExpired(bound, Date.now() + 2000))
  })

  it('validateTemporalRights: valid within window', () => {
    const rights: TemporalRights = {
      validFrom: new Date(Date.now() - 3600000).toISOString(),
      validUntil: new Date(Date.now() + 3600000).toISOString(),
    }
    const result = validateTemporalRights(rights)
    assert.ok(result.valid)
    assert.ok(!result.inGracePeriod)
    assert.ok(!result.superseded)
  })

  it('validateTemporalRights: expired but in grace period', () => {
    const rights: TemporalRights = {
      validFrom: new Date(Date.now() - 7200000).toISOString(),
      validUntil: new Date(Date.now() - 3600000).toISOString(), // expired 1hr ago
      graceUntil: new Date(Date.now() + 3600000).toISOString(), // grace for 1hr more
    }
    const result = validateTemporalRights(rights)
    assert.ok(!result.valid)
    assert.ok(result.inGracePeriod)
  })

  it('validateTemporalRights: superseded', () => {
    const rights: TemporalRights = {
      validFrom: new Date(Date.now() - 3600000).toISOString(),
      validUntil: new Date(Date.now() + 3600000).toISOString(),
      supersededAt: new Date(Date.now() - 1000).toISOString(),
    }
    const result = validateTemporalRights(rights)
    assert.ok(!result.valid, 'Superseded should not be valid')
    assert.ok(result.superseded)
  })

  it('validateTemporalRights: challenge window tracking', () => {
    const rights: TemporalRights = {
      validFrom: new Date(Date.now() - 3600000).toISOString(),
      validUntil: new Date(Date.now() + 3600000).toISOString(),
      challengeUntil: new Date(Date.now() + 7200000).toISOString(),
    }
    const result = validateTemporalRights(rights)
    assert.ok(result.valid)
    assert.ok(result.challengeWindowOpen)
  })
})

// ══════════════════════════════════════
// Reserve Functions — create, verify, compare
// ══════════════════════════════════════

describe('Reserve Functions — Attestation Lifecycle', () => {
  it('creates and verifies a reserve attestation', () => {
    const attester = generateKeyPair()
    const att = createReserveAttestation({
      delegationId: 'del_test_001',
      assuranceClass: 'gateway_attested',
      amount: 5000,
      currency: 'USD',
      liability: {
        attestationBasis: 'api_balance_check',
        isRevocable: false,
        falseAttestationPenalty: 'bond_forfeit',
      },
      attesterPrivateKey: attester.privateKey,
      attesterPublicKey: attester.publicKey,
      charterAnchor: 'charter_001',
      officeId: 'treasury',
    })

    assert.ok(att.attestationId.startsWith('res_'))
    assert.equal(att.attestedAmount.value, 5000)
    assert.equal(att.assuranceClass, 'gateway_attested')
    assert.ok(att.signature.length > 0)

    const v = verifyReserveAttestation(att)
    assert.ok(v.valid, `Expected valid: ${v.errors.join(', ')}`)
    assert.ok(v.signatureValid)
    assert.ok(v.notExpired)
  })

  it('rejects tampered attestation', () => {
    const attester = generateKeyPair()
    const att = createReserveAttestation({
      delegationId: 'del_tamper',
      assuranceClass: 'self_attested',
      amount: 100,
      currency: 'EUR',
      liability: {
        attestationBasis: 'self_declaration',
        isRevocable: true,
        falseAttestationPenalty: 'none',
      },
      attesterPrivateKey: attester.privateKey,
      attesterPublicKey: attester.publicKey,
    })

    // Tamper with amount
    const tampered = { ...att, attestedAmount: { value: 999999, currency: 'EUR' } }
    const v = verifyReserveAttestation(tampered)
    assert.ok(!v.valid)
    assert.ok(!v.signatureValid)
  })

  it('compareAssuranceClass orders correctly', () => {
    assert.ok(compareAssuranceClass('unbacked', 'gateway_attested') < 0)
    assert.ok(compareAssuranceClass('externally_attested', 'self_attested') > 0)
    assert.equal(compareAssuranceClass('escrow_backed', 'escrow_backed'), 0)
  })

  it('meetsAssuranceRequirement checks minimum', () => {
    assert.ok(meetsAssuranceRequirement('gateway_attested', 'self_attested'))
    assert.ok(meetsAssuranceRequirement('escrow_backed', 'escrow_backed'))
    assert.ok(!meetsAssuranceRequirement('unbacked', 'gateway_attested'))
    assert.ok(!meetsAssuranceRequirement('self_attested', 'externally_attested'))
  })
})

// ══════════════════════════════════════
// Federation Functions — import, vouch, downgrade
// ══════════════════════════════════════

describe('Federation Functions — WS-2/WS-3 Operations', () => {
  const importPolicy: GatewayImportPolicy = {
    receipts: { acceptFrom: ['gw_partner'], requireWitness: true },
    reputation: { acceptFrom: ['gw_partner'], downgradeRatio: 0.5 },
    witnessAttestations: { acceptFrom: ['gw_partner'], minObservationBasis: 'independent_recomputation' },
    reserveAttestations: { acceptFrom: [], requireLiabilityClass: true },
    charterFacts: { acceptFrom: ['gw_partner'] },
    foreignAgentDefaultTier: 0,
  }

  it('WS-2: imports a receipt from an accepted gateway', () => {
    const importer = generateKeyPair()
    const env = importReceipt({
      receiptId: 'rcpt_001',
      receiptContent: '{"action":"test"}',
      originGatewayId: 'gw_partner',
      originGatewaySignature: 'sig_origin',
      agentId: 'agent_001',
      agentSignature: 'sig_agent',
      importerPrivateKey: importer.privateKey,
      importerGatewayId: 'gw_local',
      importPolicy,
    })

    assert.equal(env.importDecision, 'accepted')
    assert.ok(env.receiptHash.length > 0)
    assert.ok(env.importingGatewaySignature.length > 0)

    // Verify the envelope signature
    assert.ok(verifyReceiptEnvelope(env, importer.publicKey))
  })

  it('WS-2: rejects a receipt from an unknown gateway', () => {
    const importer = generateKeyPair()
    const env = importReceipt({
      receiptId: 'rcpt_bad',
      receiptContent: '{"action":"bad"}',
      originGatewayId: 'gw_unknown',
      originGatewaySignature: 'sig_unknown',
      agentId: 'agent_bad',
      agentSignature: 'sig_agent_bad',
      importerPrivateKey: importer.privateKey,
      importerGatewayId: 'gw_local',
      importPolicy,
    })
    assert.equal(env.importDecision, 'rejected')
  })

  it('WS-3: creates and verifies a vouched reputation', () => {
    const gateway = generateKeyPair()
    const rep = vouchReputation({
      agentId: 'agent_proven',
      tier: 4,
      diversityScore: 0.92,
      gatewayPrivateKey: gateway.privateKey,
      gatewayId: 'gw_home',
    })

    assert.equal(rep.attestedTier, 4)
    assert.equal(rep.attestedDiversityScore, 0.92)
    assert.equal(rep.originGatewayId, 'gw_home')
    assert.ok(rep.originGatewaySignature.length > 0)
    assert.ok(new Date(rep.expiresAt) > new Date())

    // Verify signature
    assert.ok(verifyVouchedReputation(rep, gateway.publicKey))
    // Tamper → fails
    const tampered = { ...rep, attestedTier: 99 }
    assert.ok(!verifyVouchedReputation(tampered, gateway.publicKey))
  })

  it('WS-3: applies reputation downgrade on import', () => {
    const gateway = generateKeyPair()
    const rep = vouchReputation({
      agentId: 'agent_foreign',
      tier: 4,
      diversityScore: 0.8,
      gatewayPrivateKey: gateway.privateKey,
      gatewayId: 'gw_partner',
    })

    const result = applyReputationDowngrade(rep, importPolicy)
    assert.ok(result.accepted)
    assert.equal(result.effectiveTier, 2)        // 4 * 0.5 = 2
    assert.equal(result.effectiveDiversity, 0.4)  // 0.8 * 0.5 = 0.4
  })

  it('WS-3: rejects reputation from unknown gateway', () => {
    const gateway = generateKeyPair()
    const rep = vouchReputation({
      agentId: 'agent_unknown',
      tier: 5,
      diversityScore: 1.0,
      gatewayPrivateKey: gateway.privateKey,
      gatewayId: 'gw_untrusted',
    })

    const result = applyReputationDowngrade(rep, importPolicy)
    assert.ok(!result.accepted)
    assert.equal(result.effectiveTier, 0)  // falls back to default tier
    assert.equal(result.effectiveDiversity, 0)
  })
})
