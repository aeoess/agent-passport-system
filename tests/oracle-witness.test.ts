// Oracle Witness Diversity Tests (Module 28 — Gap 4)
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createWitnessPool, createAttestation, verifyWitnessAttestation,
  addAttestation, computeDiversityScore, evaluateWitnessConsensus,
  wouldIncreaseDiversity,
} from '../src/core/oracle-witness.js'
import type { WitnessAttestation } from '../src/types/oracle-witness.js'

// Helper: create a signed attestation from a fresh keypair
function makeAttestation(opts: {
  provider: string, modelFamily: string, observation: string,
  confidence?: number, witnessId?: string
}): WitnessAttestation {
  const kp = generateKeyPair()
  return createAttestation({
    witnessId: opts.witnessId ?? `w-${Math.random().toString(36).slice(2, 8)}`,
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    provider: opts.provider,
    modelFamily: opts.modelFamily,
    observation: opts.observation,
    confidence: opts.confidence ?? 0.9,
  })
}

describe('Witness Pool — Creation', () => {
  it('creates pool with defaults', () => {
    const pool = createWitnessPool({ context: 'Is the API up?' })
    assert.ok(pool.poolId.startsWith('wp_'))
    assert.equal(pool.quorum, 3)
    assert.equal(pool.minDiversityScore, 0.5)
    assert.equal(pool.status, 'collecting')
    assert.equal(pool.attestations.length, 0)
  })

  it('creates pool with custom config', () => {
    const pool = createWitnessPool({ context: 'Price check', quorum: 5, minDiversityScore: 0.7 })
    assert.equal(pool.quorum, 5)
    assert.equal(pool.minDiversityScore, 0.7)
  })
})

describe('Attestation — Create & Verify', () => {
  it('creates and verifies a signed attestation', () => {
    const att = makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'API is up' })
    assert.ok(att.signature)
    assert.equal(att.provider, 'anthropic')
    assert.equal(verifyWitnessAttestation(att), true)
  })

  it('rejects tampered attestation', () => {
    const att = makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'price is $100' })
    const tampered = { ...att, observation: 'price is $999' }
    assert.equal(verifyWitnessAttestation(tampered), false)
  })

  it('rejects confidence outside 0-1', () => {
    const kp = generateKeyPair()
    assert.throws(() => createAttestation({
      witnessId: 'w1', publicKey: kp.publicKey, privateKey: kp.privateKey,
      provider: 'test', modelFamily: 'test', observation: 'x', confidence: 1.5,
    }), /Confidence must be between/)
  })
})

describe('Witness Pool — Add Attestation', () => {
  it('adds verified attestation to pool', () => {
    let pool = createWitnessPool({ context: 'test', quorum: 2 })
    const att = makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'yes' })
    pool = addAttestation(pool, att)
    assert.equal(pool.attestations.length, 1)
    assert.equal(pool.status, 'collecting')
  })

  it('transitions to quorum_met when quorum reached', () => {
    let pool = createWitnessPool({ context: 'test', quorum: 2 })
    pool = addAttestation(pool, makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'yes' }))
    pool = addAttestation(pool, makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'yes' }))
    assert.equal(pool.status, 'quorum_met')
  })

  it('rejects duplicate witness', () => {
    let pool = createWitnessPool({ context: 'test', quorum: 3 })
    const att = makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'yes', witnessId: 'w-dup' })
    pool = addAttestation(pool, att)
    assert.throws(() => addAttestation(pool, att), /already attested/)
  })

  it('rejects attestation with invalid signature', () => {
    const att = makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'yes' })
    const forged = { ...att, signature: 'deadbeef'.repeat(16) }
    let pool = createWitnessPool({ context: 'test', quorum: 2 })
    assert.throws(() => addAttestation(pool, forged), /signature invalid/)
  })
})

describe('Diversity Scoring', () => {
  it('returns zero for empty attestations', () => {
    const d = computeDiversityScore([])
    assert.equal(d.overall, 0)
    assert.equal(d.providerCount, 0)
  })

  it('single provider = zero entropy', () => {
    const atts = [
      makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'x' }),
      makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'x' }),
    ]
    const d = computeDiversityScore(atts)
    assert.equal(d.providerEntropy, 0)
    assert.equal(d.singleProviderDominant, true)
    assert.equal(d.providerCount, 1)
  })

  it('diverse providers = high entropy', () => {
    const atts = [
      makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'x' }),
      makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'x' }),
      makeAttestation({ provider: 'google', modelFamily: 'gemini', observation: 'x' }),
    ]
    const d = computeDiversityScore(atts)
    assert.equal(d.providerEntropy, 1)  // perfect entropy with 3 equal groups
    assert.equal(d.singleProviderDominant, false)
    assert.equal(d.providerCount, 3)
    assert.equal(d.modelFamilyCount, 3)
    assert.ok(d.overall > 0.7, `Expected overall > 0.7, got ${d.overall}`)
  })

  it('detects single provider dominance', () => {
    const atts = [
      makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'x' }),
      makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'x' }),
      makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'x' }),
    ]
    const d = computeDiversityScore(atts)
    assert.equal(d.singleProviderDominant, true)
  })
})

describe('Consensus Evaluation', () => {
  it('fails below quorum', () => {
    let pool = createWitnessPool({ context: 'test', quorum: 3 })
    pool = addAttestation(pool, makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'yes' }))
    const result = evaluateWitnessConsensus(pool)
    assert.equal(result.reached, false)
    assert.equal(result.failureReason, 'below_quorum')
  })

  it('reaches consensus with diverse agreeing witnesses', () => {
    let pool = createWitnessPool({ context: 'Is API healthy?', quorum: 3, minDiversityScore: 0.3 })
    pool = addAttestation(pool, makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'healthy' }))
    pool = addAttestation(pool, makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'healthy' }))
    pool = addAttestation(pool, makeAttestation({ provider: 'google', modelFamily: 'gemini', observation: 'healthy' }))
    const result = evaluateWitnessConsensus(pool)
    assert.equal(result.reached, true)
    assert.equal(result.consensusObservation, 'healthy')
    assert.equal(result.agreementCount, 3)
    assert.equal(result.agreementRatio, 1)
  })

  it('fails consensus when no majority', () => {
    let pool = createWitnessPool({ context: 'test', quorum: 3, minDiversityScore: 0.0 })
    pool = addAttestation(pool, makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'yes' }))
    pool = addAttestation(pool, makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'no' }))
    pool = addAttestation(pool, makeAttestation({ provider: 'google', modelFamily: 'gemini', observation: 'maybe' }))
    const result = evaluateWitnessConsensus(pool)
    assert.equal(result.reached, false)
    assert.equal(result.failureReason, 'no_majority')
  })

  it('fails consensus when diversity too low (Sybil resistance)', () => {
    let pool = createWitnessPool({ context: 'test', quorum: 3, minDiversityScore: 0.7 })
    pool = addAttestation(pool, makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'yes' }))
    pool = addAttestation(pool, makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'yes' }))
    pool = addAttestation(pool, makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'yes' }))
    const result = evaluateWitnessConsensus(pool)
    assert.equal(result.reached, false)
    assert.equal(result.failureReason, 'low_diversity')
  })
})

describe('wouldIncreaseDiversity', () => {
  it('returns true when adding a new provider', () => {
    let pool = createWitnessPool({ context: 'test', quorum: 3 })
    pool = addAttestation(pool, makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'x' }))
    assert.equal(wouldIncreaseDiversity(pool, 'openai', 'gpt'), true)
  })

  it('returns false when adding same provider and family', () => {
    let pool = createWitnessPool({ context: 'test', quorum: 5 })
    pool = addAttestation(pool, makeAttestation({ provider: 'anthropic', modelFamily: 'claude', observation: 'x' }))
    pool = addAttestation(pool, makeAttestation({ provider: 'openai', modelFamily: 'gpt', observation: 'x' }))
    pool = addAttestation(pool, makeAttestation({ provider: 'google', modelFamily: 'gemini', observation: 'x' }))
    // Adding a 4th from anthropic/claude would decrease diversity (more weight on already-present provider)
    // But the overall score might still increase if witness count factor helps
    // With 3 diverse providers, adding a 4th same-provider reduces entropy
    const result = wouldIncreaseDiversity(pool, 'anthropic', 'claude')
    // With perfect 3-way split, adding a 4th to one group reduces entropy
    assert.equal(result, false)
  })
})
