// Behavioral Fingerprint envelope tests.
// Composes HBB fidelity (axis 1) + PDR (axis 2) + Saebo constraint (axis 3)
// into a signed artifact. Reference: Nanook PDR v2.19 §2.2, §8.10.
// Gap audit §3 row 10 and §5 rank 2.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  createBehavioralFingerprint,
  verifyBehavioralFingerprint,
  composeFingerprintAxes,
  createFidelityAttestation,
  generateKeyPair,
  canonicalize,
} from '../src/index.js'
import type {
  BehavioralFingerprint,
  PDRScoreRef,
  SaeboScoreRef,
  FidelityAttestation,
  SubstrateFidelity,
} from '../src/index.js'

// ── Fixtures ────────────────────────────────────────────────

function makeFidelity(score: number, substrate: string = 'claude-sonnet-4'): SubstrateFidelity {
  return {
    score,
    substrate,
    measuredAt: '2026-04-10T00:00:00.000Z',
    method: 'hbb-v1',
    dimensions: {
      boundaries: score,
      reasoning: score,
    },
  }
}

function makeAttestation(
  agentId: string,
  score: number,
  measurer: { id: string; privateKey: string },
  substrate: string = 'claude-sonnet-4',
): FidelityAttestation {
  return createFidelityAttestation(agentId, makeFidelity(score, substrate), measurer)
}

function makePDR(overall: number = 0.85): PDRScoreRef {
  return {
    source: 'pdr.score.v1',
    scoreOverall: overall,
    scoreCalibration: 0.9,
    scoreAdaptation: 0.7,
    scoreRobustness: 0.85,
    observationCount: 37,
    windowDays: 14,
    issuer: 'nexusguard-aip-0.5.48',
    issuedAt: '2026-04-10T00:00:00.000Z',
  }
}

function makeSaebo(compliance: number = 0.92): SaeboScoreRef {
  return {
    source: 'saebo.constraint.v1',
    complianceScore: compliance,
    violationCount: 1,
    sessionTurnCount: 20,
    issuer: 'saebo-scorer-1',
    issuedAt: '2026-04-10T00:00:00.000Z',
  }
}

function makeMeasurer() {
  const kp = generateKeyPair()
  return {
    id: 'measurer-test-001',
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
  }
}

// ── 1. Round-trip: create, serialize, verify ────────────────

describe('createBehavioralFingerprint + verifyBehavioralFingerprint', () => {
  it('round-trips a single-fidelity envelope', () => {
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:agent-a', 0.95, measurer)

    const fp = createBehavioralFingerprint(
      { did: 'did:aps:agent-a', substrate: 'claude-sonnet-4' },
      [att],
      {
        measurerId: measurer.id,
        measurerPublicKey: measurer.publicKey,
        signingKey: measurer.privateKey,
      },
    )

    assert.ok(fp.signature.length > 0)
    assert.equal(fp.subject.did, 'did:aps:agent-a')
    assert.equal(fp.fidelity.length, 1)
    assert.equal(fp.measurerId, measurer.id)

    const result = verifyBehavioralFingerprint(fp, measurer.publicKey)
    assert.equal(result.valid, true, `errors: ${result.errors.join(', ')}`)
    assert.equal(result.envelopeSignatureValid, true)
    assert.deepEqual(result.innerFidelitySignaturesValid, [true])
    assert.deepEqual(result.errors, [])
  })

  it('round-trips JSON serialization (envelope survives JSON.stringify + parse)', () => {
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:agent-b', 0.8, measurer)
    const fp = createBehavioralFingerprint(
      { did: 'did:aps:agent-b', substrate: 'claude-sonnet-4' },
      [att],
      {
        measurerId: measurer.id,
        measurerPublicKey: measurer.publicKey,
        signingKey: measurer.privateKey,
      },
    )

    const wire = JSON.stringify(fp)
    const restored = JSON.parse(wire) as BehavioralFingerprint
    const result = verifyBehavioralFingerprint(restored, measurer.publicKey)
    assert.equal(result.valid, true)
  })
})

// ── 2. Tamper detection ─────────────────────────────────────

describe('verifyBehavioralFingerprint — tamper detection', () => {
  function freshFp() {
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:agent-c', 0.9, measurer)
    const fp = createBehavioralFingerprint(
      { did: 'did:aps:agent-c', substrate: 'claude-sonnet-4' },
      [att],
      {
        pdr: makePDR(0.85),
        constraint: makeSaebo(0.92),
        measurerId: measurer.id,
        measurerPublicKey: measurer.publicKey,
        signingKey: measurer.privateKey,
      },
    )
    return { fp, measurer }
  }

  it('mutated subject.did fails verification', () => {
    const { fp, measurer } = freshFp()
    const tampered = { ...fp, subject: { ...fp.subject, did: 'did:aps:evil' } }
    const result = verifyBehavioralFingerprint(tampered, measurer.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.envelopeSignatureValid, false)
  })

  it('mutated subject.substrate fails verification', () => {
    const { fp, measurer } = freshFp()
    const tampered = { ...fp, subject: { ...fp.subject, substrate: 'gpt-5' } }
    const result = verifyBehavioralFingerprint(tampered, measurer.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.envelopeSignatureValid, false)
  })

  it('mutated pdr_ref.scoreOverall fails verification', () => {
    const { fp, measurer } = freshFp()
    const tampered: BehavioralFingerprint = {
      ...fp,
      pdr_ref: { ...fp.pdr_ref!, scoreOverall: 0.99 },
    }
    const result = verifyBehavioralFingerprint(tampered, measurer.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.envelopeSignatureValid, false)
  })

  it('mutated constraint_ref.complianceScore fails verification', () => {
    const { fp, measurer } = freshFp()
    const tampered: BehavioralFingerprint = {
      ...fp,
      constraint_ref: { ...fp.constraint_ref!, complianceScore: 0.01 },
    }
    const result = verifyBehavioralFingerprint(tampered, measurer.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.envelopeSignatureValid, false)
  })

  it('mutated measurerId fails verification', () => {
    const { fp, measurer } = freshFp()
    const tampered = { ...fp, measurerId: 'measurer-evil' }
    const result = verifyBehavioralFingerprint(tampered, measurer.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.envelopeSignatureValid, false)
  })

  it('mutated signedAt fails verification', () => {
    const { fp, measurer } = freshFp()
    const tampered = { ...fp, signedAt: '2099-01-01T00:00:00.000Z' }
    const result = verifyBehavioralFingerprint(tampered, measurer.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.envelopeSignatureValid, false)
  })

  it('truncated signature fails verification gracefully (no throw)', () => {
    const { fp, measurer } = freshFp()
    const tampered = { ...fp, signature: 'deadbeef' }
    const result = verifyBehavioralFingerprint(tampered, measurer.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.envelopeSignatureValid, false)
  })
})

// ── 3. Missing fidelity throws ──────────────────────────────

describe('createBehavioralFingerprint — input validation', () => {
  it('throws when fidelity array is empty', () => {
    const measurer = makeMeasurer()
    assert.throws(
      () =>
        createBehavioralFingerprint(
          { did: 'did:aps:x', substrate: 'claude-sonnet-4' },
          [],
          {
            measurerId: measurer.id,
            measurerPublicKey: measurer.publicKey,
            signingKey: measurer.privateKey,
          },
        ),
      /at least one fidelity attestation/,
    )
  })

  it('throws when fidelity is undefined', () => {
    const measurer = makeMeasurer()
    assert.throws(
      () =>
        createBehavioralFingerprint(
          { did: 'did:aps:x', substrate: 'claude-sonnet-4' },
          undefined as unknown as FidelityAttestation[],
          {
            measurerId: measurer.id,
            measurerPublicKey: measurer.publicKey,
            signingKey: measurer.privateKey,
          },
        ),
      /at least one fidelity attestation/,
    )
  })

  it('throws when measurerId is missing', () => {
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:x', 0.8, measurer)
    assert.throws(
      () =>
        createBehavioralFingerprint(
          { did: 'did:aps:x', substrate: 'claude-sonnet-4' },
          [att],
          {
            measurerId: '',
            measurerPublicKey: measurer.publicKey,
            signingKey: measurer.privateKey,
          },
        ),
      /measurerId/,
    )
  })

  it('throws when signingKey is missing', () => {
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:x', 0.8, measurer)
    assert.throws(
      () =>
        createBehavioralFingerprint(
          { did: 'did:aps:x', substrate: 'claude-sonnet-4' },
          [att],
          {
            measurerId: measurer.id,
            measurerPublicKey: measurer.publicKey,
            signingKey: '',
          },
        ),
      /signingKey/,
    )
  })
})

// ── 4. Optional axes: 4 combinations ────────────────────────

describe('verifyBehavioralFingerprint — optional axes', () => {
  function withAxes(opts: { pdr?: PDRScoreRef; constraint?: SaeboScoreRef }) {
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:axes', 0.88, measurer)
    const fp = createBehavioralFingerprint(
      { did: 'did:aps:axes', substrate: 'claude-sonnet-4' },
      [att],
      {
        ...opts,
        measurerId: measurer.id,
        measurerPublicKey: measurer.publicKey,
        signingKey: measurer.privateKey,
      },
    )
    return { fp, measurer }
  }

  it('valid with neither pdr nor constraint', () => {
    const { fp, measurer } = withAxes({})
    assert.equal(fp.pdr_ref, undefined)
    assert.equal(fp.constraint_ref, undefined)
    const result = verifyBehavioralFingerprint(fp, measurer.publicKey)
    assert.equal(result.valid, true)
  })

  it('valid with pdr only', () => {
    const { fp, measurer } = withAxes({ pdr: makePDR() })
    assert.ok(fp.pdr_ref)
    assert.equal(fp.constraint_ref, undefined)
    const result = verifyBehavioralFingerprint(fp, measurer.publicKey)
    assert.equal(result.valid, true)
  })

  it('valid with constraint only', () => {
    const { fp, measurer } = withAxes({ constraint: makeSaebo() })
    assert.equal(fp.pdr_ref, undefined)
    assert.ok(fp.constraint_ref)
    const result = verifyBehavioralFingerprint(fp, measurer.publicKey)
    assert.equal(result.valid, true)
  })

  it('valid with both pdr and constraint', () => {
    const { fp, measurer } = withAxes({ pdr: makePDR(), constraint: makeSaebo() })
    assert.ok(fp.pdr_ref)
    assert.ok(fp.constraint_ref)
    const result = verifyBehavioralFingerprint(fp, measurer.publicKey)
    assert.equal(result.valid, true)
  })
})

// ── 5. Inner fidelity tamper: envelope still valid, inner reports false ──

describe('verifyBehavioralFingerprint — inner attestation tamper', () => {
  it('tampering an inner attestation field invalidates the envelope (because the envelope signs the attestations)', () => {
    // Sanity check first: when the inner attestation field changes, the
    // envelope signature must also fail because the envelope signs the
    // attestations as JSON content. This is the spec behavior.
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:inner', 0.9, measurer)
    const fp = createBehavioralFingerprint(
      { did: 'did:aps:inner', substrate: 'claude-sonnet-4' },
      [att],
      {
        measurerId: measurer.id,
        measurerPublicKey: measurer.publicKey,
        signingKey: measurer.privateKey,
      },
    )

    // Mutate the inner fidelity score (this changes the attestation but
    // since we did not re-sign the inner attestation, its own signature is
    // also broken).
    const tamperedFidelity = {
      ...fp.fidelity[0],
      fidelity: { ...fp.fidelity[0].fidelity, score: 0.1 },
    }
    const tampered = { ...fp, fidelity: [tamperedFidelity] }
    const result = verifyBehavioralFingerprint(tampered, measurer.publicKey)

    assert.equal(result.envelopeSignatureValid, false, 'envelope signs attestation content; tamper breaks envelope sig')
    assert.equal(result.innerFidelitySignaturesValid[0], false, 'inner sig also broken because attestation content changed under its own signature')
    assert.equal(result.valid, false)
  })

  it('inner attestation signed by a different measurer reports false in innerFidelitySignaturesValid', () => {
    // This is the case the per-attestation breakdown is for: an attestation
    // created by measurer B is bundled into an envelope by measurer A. The
    // envelope signature is valid (A signed it correctly), but the inner
    // signature was made by B, so verifying with A's key returns false for
    // that attestation specifically.
    const measurerA = makeMeasurer()
    const measurerB = makeMeasurer()

    const attFromB = makeAttestation('did:aps:multi', 0.85, measurerB)

    const fp = createBehavioralFingerprint(
      { did: 'did:aps:multi', substrate: 'claude-sonnet-4' },
      [attFromB],
      {
        measurerId: measurerA.id,
        measurerPublicKey: measurerA.publicKey,
        signingKey: measurerA.privateKey,
      },
    )

    const result = verifyBehavioralFingerprint(fp, measurerA.publicKey)
    assert.equal(result.envelopeSignatureValid, true, 'envelope sig is valid: A signed it')
    assert.equal(result.innerFidelitySignaturesValid[0], false, 'inner sig fails: B signed it, not A')
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => /inner fidelity attestation/.test(e)))
  })
})

// ── 6. composeFingerprintAxes ───────────────────────────────

describe('composeFingerprintAxes', () => {
  it('computes the arithmetic mean across 3 fidelity attestations', () => {
    const measurer = makeMeasurer()
    const a = makeAttestation('did:aps:mean', 1.0, measurer)
    const b = makeAttestation('did:aps:mean', 0.6, measurer)
    const c = makeAttestation('did:aps:mean', 0.2, measurer)
    const fp = createBehavioralFingerprint(
      { did: 'did:aps:mean', substrate: 'claude-sonnet-4' },
      [a, b, c],
      {
        measurerId: measurer.id,
        measurerPublicKey: measurer.publicKey,
        signingKey: measurer.privateKey,
      },
    )
    const axes = composeFingerprintAxes(fp)
    // (1.0 + 0.6 + 0.2) / 3 = 0.6 exactly
    assert.ok(Math.abs(axes.fidelityMean - 0.6) < 1e-9, `got ${axes.fidelityMean}`)
    assert.equal(axes.pdrOverall, undefined)
    assert.equal(axes.constraintCompliance, undefined)
  })

  it('surfaces pdr.scoreOverall when present', () => {
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:p', 0.9, measurer)
    const fp = createBehavioralFingerprint(
      { did: 'did:aps:p', substrate: 'claude-sonnet-4' },
      [att],
      {
        pdr: makePDR(0.77),
        measurerId: measurer.id,
        measurerPublicKey: measurer.publicKey,
        signingKey: measurer.privateKey,
      },
    )
    const axes = composeFingerprintAxes(fp)
    assert.equal(axes.pdrOverall, 0.77)
    assert.equal(axes.constraintCompliance, undefined)
  })

  it('surfaces constraint.complianceScore when present', () => {
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:s', 0.9, measurer)
    const fp = createBehavioralFingerprint(
      { did: 'did:aps:s', substrate: 'claude-sonnet-4' },
      [att],
      {
        constraint: makeSaebo(0.66),
        measurerId: measurer.id,
        measurerPublicKey: measurer.publicKey,
        signingKey: measurer.privateKey,
      },
    )
    const axes = composeFingerprintAxes(fp)
    assert.equal(axes.constraintCompliance, 0.66)
    assert.equal(axes.pdrOverall, undefined)
  })

  it('surfaces all three axes when all present', () => {
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:all', 0.95, measurer)
    const fp = createBehavioralFingerprint(
      { did: 'did:aps:all', substrate: 'claude-sonnet-4' },
      [att],
      {
        pdr: makePDR(0.81),
        constraint: makeSaebo(0.93),
        measurerId: measurer.id,
        measurerPublicKey: measurer.publicKey,
        signingKey: measurer.privateKey,
      },
    )
    const axes = composeFingerprintAxes(fp)
    assert.equal(axes.fidelityMean, 0.95)
    assert.equal(axes.pdrOverall, 0.81)
    assert.equal(axes.constraintCompliance, 0.93)
  })
})

// ── 7. Canonical JSON stability across declaration order ─────

describe('canonical JSON stability', () => {
  it('produces byte-identical signatures regardless of opts property order', () => {
    const measurer = makeMeasurer()
    const att = makeAttestation('did:aps:canon', 0.88, measurer)
    const subject = { did: 'did:aps:canon', substrate: 'claude-sonnet-4' }
    const signedAt = '2026-04-10T12:00:00.000Z'

    // Order 1: pdr declared before constraint
    const fp1 = createBehavioralFingerprint(subject, [att], {
      pdr: makePDR(0.8),
      constraint: makeSaebo(0.9),
      measurerId: measurer.id,
      measurerPublicKey: measurer.publicKey,
      signingKey: measurer.privateKey,
      signedAt,
    })

    // Order 2: constraint declared before pdr
    const fp2 = createBehavioralFingerprint(subject, [att], {
      constraint: makeSaebo(0.9),
      pdr: makePDR(0.8),
      measurerId: measurer.id,
      measurerPublicKey: measurer.publicKey,
      signingKey: measurer.privateKey,
      signedAt,
    })

    assert.equal(fp1.signature, fp2.signature, 'signatures must be byte-identical regardless of declaration order')

    // Both verify
    assert.equal(verifyBehavioralFingerprint(fp1, measurer.publicKey).valid, true)
    assert.equal(verifyBehavioralFingerprint(fp2, measurer.publicKey).valid, true)
  })

  it('canonical payload sorts subject fields the same way both times', () => {
    // Sanity check that canonicalize is in fact sorting the subject keys.
    const a = canonicalize({ subject: { did: 'd', substrate: 's' } })
    const b = canonicalize({ subject: { substrate: 's', did: 'd' } })
    assert.equal(a, b)
  })
})

// ── 8. Cross-key verification (different measurer keys do not collide) ──

describe('verifyBehavioralFingerprint — cross-key', () => {
  it('fingerprint signed by key A does not verify against key B', () => {
    const measurerA = makeMeasurer()
    const measurerB = makeMeasurer()

    const att = makeAttestation('did:aps:cross', 0.85, measurerA)
    const fp = createBehavioralFingerprint(
      { did: 'did:aps:cross', substrate: 'claude-sonnet-4' },
      [att],
      {
        measurerId: measurerA.id,
        measurerPublicKey: measurerA.publicKey,
        signingKey: measurerA.privateKey,
      },
    )

    // Verifying against A succeeds
    const okA = verifyBehavioralFingerprint(fp, measurerA.publicKey)
    assert.equal(okA.valid, true)

    // Verifying against B fails completely
    const okB = verifyBehavioralFingerprint(fp, measurerB.publicKey)
    assert.equal(okB.valid, false)
    assert.equal(okB.envelopeSignatureValid, false)
    assert.equal(okB.innerFidelitySignaturesValid[0], false)
  })
})
